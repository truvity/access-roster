//! The SQL of the driver, one function per statement shape, so that what runs is readable in one
//! place (and testable without a database).
//!
//! Rules that hold for every statement here (0005 "Engines"):
//!
//! - No `ATTACH`, no trigger, no default that is not deterministic: rqlite replicates the
//!   statement text and a replica would compute its own `now`. Every timestamp is a parameter.
//! - Bytes travel as hex text (`unhex(?)`, `hex(x)`), keys as text.
//! - A key range is `key >= prefix AND key < successor`, never `LIKE` with user bytes.

use sluis_conformance::rules::{Expected, prefix_successor};

use crate::client::{Param, Stmt, hex};

/// The version of the schema this build speaks, kept in `<ns>_meta`.
pub const SCHEMA_VERSION: i64 = 1;

/// The most log rows one poll of a tail takes.
pub const TAIL_BATCH: i64 = 500;

/// The tables of one namespace (`durable` or `temp`).
#[derive(Clone, Debug)]
pub struct Ns {
    /// `<ns>_items`.
    pub items: String,
    /// `<ns>_index`.
    pub index: String,
    /// `<ns>_log`.
    pub log: String,
    /// `<ns>_meta`.
    pub meta: String,
    /// `<ns>_guard`: always empty; a failed condition inserts a NULL into it.
    pub guard: String,
}

impl Ns {
    /// The tables of a namespace. Only the two ports of the item contract exist.
    ///
    /// # Errors
    ///
    /// For any name but `durable` and `temp`.
    pub fn new(name: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(
            matches!(name, "durable" | "temp"),
            "--namespace: want durable or temp"
        );
        Ok(Self {
            items: format!("{name}_items"),
            index: format!("{name}_index"),
            log: format!("{name}_log"),
            meta: format!("{name}_meta"),
            guard: format!("{name}_guard"),
        })
    }

    /// The schema, idempotently (`serve` runs it, `check` does not).
    #[must_use]
    pub fn ddl(&self) -> Vec<Stmt> {
        let Self {
            items,
            index,
            log,
            meta,
            guard,
        } = self;
        let none = Vec::new;
        vec![
            Stmt::new(
                format!(
                    "CREATE TABLE IF NOT EXISTS {meta}(name TEXT PRIMARY KEY, value INTEGER NOT NULL)"
                ),
                none(),
            ),
            // The expiry is milliseconds since the epoch, as store@ gave it.
            Stmt::new(
                format!(
                    "CREATE TABLE IF NOT EXISTS {items}(key TEXT PRIMARY KEY, version INTEGER NOT NULL, \
                     value BLOB NOT NULL, expires_at INTEGER)"
                ),
                none(),
            ),
            Stmt::new(
                format!(
                    "CREATE INDEX IF NOT EXISTS {items}_expiry ON {items}(expires_at) WHERE expires_at IS NOT NULL"
                ),
                none(),
            ),
            Stmt::new(
                format!(
                    "CREATE TABLE IF NOT EXISTS {index}(name TEXT NOT NULL, value BLOB NOT NULL, \
                     key TEXT NOT NULL, PRIMARY KEY(name, value, key))"
                ),
                none(),
            ),
            Stmt::new(
                format!("CREATE INDEX IF NOT EXISTS {index}_key ON {index}(key)"),
                none(),
            ),
            // `logged_at` is the driver's clock and is used only to trim old rows.
            Stmt::new(
                format!(
                    "CREATE TABLE IF NOT EXISTS {log}(seq INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL, \
                     version INTEGER NOT NULL, deleted INTEGER NOT NULL, logged_at INTEGER NOT NULL)"
                ),
                none(),
            ),
            Stmt::new(
                format!("CREATE TABLE IF NOT EXISTS {guard}(ok INTEGER NOT NULL)"),
                none(),
            ),
            Stmt::new(
                format!(
                    "INSERT OR IGNORE INTO {meta}(name, value) VALUES ('schema_version', ?), ('log_floor', 0)"
                ),
                vec![Param::Int(SCHEMA_VERSION)],
            ),
        ]
    }

    /// Reads the schema version.
    #[must_use]
    pub fn schema_version(&self) -> Stmt {
        Stmt::new(
            format!(
                "SELECT value FROM {} WHERE name = 'schema_version'",
                self.meta
            ),
            vec![],
        )
    }

    // ---- reads ------------------------------------------------------------------------------

    /// One live item with its index entries (one row per entry; one row with a NULL name when it
    /// has none). The columns are those of [`Ns::query`].
    #[must_use]
    pub fn get(&self, key: &str, now: i64) -> Stmt {
        Stmt::new(
            format!(
                "SELECT i.key, i.version, hex(i.value), i.expires_at, x.name, hex(x.value) \
                 FROM {items} AS i LEFT JOIN {index} AS x ON x.key = i.key \
                 WHERE i.key = ? AND (i.expires_at IS NULL OR i.expires_at > ?) \
                 ORDER BY x.name, x.value",
                items = self.items,
                index = self.index
            ),
            vec![Param::Text(key.to_owned()), Param::Int(now)],
        )
    }

    /// One page of live items in key order: under `prefix`, after `after` (the last key of the
    /// previous page), optionally those with an index entry; `limit` items, each with its index
    /// entries. The limit applies to items, not rows, so it sits in a subquery.
    #[must_use]
    pub fn query(
        &self,
        prefix: &str,
        after: Option<&str>,
        index: Option<(&str, &[u8])>,
        limit: usize,
        now: i64,
    ) -> Stmt {
        let mut cond = vec!["(expires_at IS NULL OR expires_at > ?)".to_owned()];
        let mut params = vec![Param::Int(now)];
        if let Some(after) = after {
            cond.push("key > ?".into());
            params.push(Param::Text(after.to_owned()));
        } else if !prefix.is_empty() {
            cond.push("key >= ?".into());
            params.push(Param::Text(prefix.to_owned()));
        }
        if let Some(end) = prefix_successor(prefix.as_bytes()) {
            cond.push("key < ?".into());
            // A successor of printable ASCII is printable ASCII (rules::check_key).
            params.push(Param::Text(String::from_utf8_lossy(&end).into_owned()));
        }
        if let Some((name, value)) = index {
            cond.push(format!(
                "key IN (SELECT key FROM {} WHERE name = ? AND value = unhex(?))",
                self.index
            ));
            params.push(Param::Text(name.to_owned()));
            params.push(Param::Text(hex(value)));
        }
        params.push(Param::Int(i64::try_from(limit).unwrap_or(i64::MAX)));
        Stmt::new(
            format!(
                "SELECT i.key, i.version, hex(i.value), i.expires_at, x.name, hex(x.value) \
                 FROM (SELECT key, version, value, expires_at FROM {items} WHERE {cond} ORDER BY key LIMIT ?) AS i \
                 LEFT JOIN {index} AS x ON x.key = i.key \
                 ORDER BY i.key, x.name, x.value",
                items = self.items,
                index = self.index,
                cond = cond.join(" AND ")
            ),
            params,
        )
    }

    /// The highest sequence the log has given out: the newest row, or the floor when every row
    /// was trimmed. One row: the newest row's sequence (or 0) and the floor.
    #[must_use]
    pub fn log_head(&self) -> Stmt {
        Stmt::new(
            format!(
                "SELECT COALESCE((SELECT MAX(seq) FROM {}), 0), \
                 (SELECT value FROM {} WHERE name = 'log_floor')",
                self.log, self.meta
            ),
            vec![],
        )
    }

    /// The rows after `seq`, in order.
    #[must_use]
    pub fn log_after(&self, seq: i64) -> Stmt {
        Stmt::new(
            format!(
                "SELECT seq, key, version, deleted FROM {} WHERE seq > ? ORDER BY seq LIMIT ?",
                self.log
            ),
            vec![Param::Int(seq), Param::Int(TAIL_BATCH)],
        )
    }

    // ---- writes (one Transact is guards, deletes, then puts, in one transaction) -----------

    /// A condition as a statement that fails, with `SQLITE_CONSTRAINT_NOTNULL`, when the
    /// condition does not hold, and inserts nothing when it does. rqlite stops at the first failed
    /// statement of a transaction and rolls it back, so a failed guard aborts the whole request
    /// and the position of the failure is the index of the condition. An item past its expiry
    /// does not exist for a condition, as for a read.
    #[must_use]
    pub fn guard(&self, key: &str, expect: Expected, now: i64) -> Stmt {
        let live = format!(
            "SELECT 1 FROM {} WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)",
            self.items
        );
        match expect {
            Expected::Absent => Stmt::new(
                format!(
                    "INSERT INTO {}(ok) SELECT NULL WHERE EXISTS ({live})",
                    self.guard
                ),
                vec![Param::Text(key.to_owned()), Param::Int(now)],
            ),
            Expected::Version(v) => Stmt::new(
                // A version beyond i64 matches nothing: versions start at 1 and only grow by 1.
                format!(
                    "INSERT INTO {}(ok) SELECT NULL WHERE NOT EXISTS ({live} AND version = ?)",
                    self.guard
                ),
                vec![
                    Param::Text(key.to_owned()),
                    Param::Int(now),
                    Param::Int(i64::try_from(v).unwrap_or(-1)),
                ],
            ),
        }
    }

    /// The change-log row of a delete: the item as it is now, if it is live. It runs before the
    /// delete, so the row holds the version the item had.
    #[must_use]
    pub fn log_delete(&self, key: &str, now: i64) -> Stmt {
        Stmt::new(
            format!(
                "INSERT INTO {log}(key, version, deleted, logged_at) \
                 SELECT key, version, 1, ? FROM {items} \
                 WHERE key = ? AND (expires_at IS NULL OR expires_at > ?)",
                log = self.log,
                items = self.items
            ),
            vec![
                Param::Int(now),
                Param::Text(key.to_owned()),
                Param::Int(now),
            ],
        )
    }

    /// Removes the index entries of a key.
    #[must_use]
    pub fn delete_index(&self, key: &str) -> Stmt {
        Stmt::new(
            format!("DELETE FROM {} WHERE key = ?", self.index),
            vec![Param::Text(key.to_owned())],
        )
    }

    /// Removes an item, live or not.
    #[must_use]
    pub fn delete_item(&self, key: &str) -> Stmt {
        Stmt::new(
            format!("DELETE FROM {} WHERE key = ?", self.items),
            vec![Param::Text(key.to_owned())],
        )
    }

    /// Writes an item and returns its version: 1 at creation (or over an item past its expiry),
    /// plus 1 at each change. The statement is the whole conditional update: the condition is a
    /// guard in front of it in the same transaction, and `RETURNING` hands back the version it
    /// wrote, so no second read is needed and no race exists.
    #[must_use]
    pub fn upsert(&self, key: &str, value: &[u8], expires_ms: Option<i64>, now: i64) -> Stmt {
        let items = &self.items;
        Stmt::new(
            format!(
                "INSERT INTO {items}(key, version, value, expires_at) VALUES (?, 1, unhex(?), ?) \
                 ON CONFLICT(key) DO UPDATE SET \
                 version = CASE WHEN {items}.expires_at IS NOT NULL AND {items}.expires_at <= ? \
                                THEN 1 ELSE {items}.version + 1 END, \
                 value = excluded.value, expires_at = excluded.expires_at \
                 RETURNING version"
            ),
            vec![
                Param::Text(key.to_owned()),
                Param::Text(hex(value)),
                expires_ms.map_or(Param::Null, Param::Int),
                Param::Int(now),
            ],
        )
    }

    /// One index entry of an item.
    #[must_use]
    pub fn insert_index(&self, key: &str, name: &str, value: &[u8]) -> Stmt {
        Stmt::new(
            format!(
                "INSERT OR IGNORE INTO {}(name, value, key) VALUES (?, unhex(?), ?)",
                self.index
            ),
            vec![
                Param::Text(name.to_owned()),
                Param::Text(hex(value)),
                Param::Text(key.to_owned()),
            ],
        )
    }

    /// The change-log row of a put: the item as it was just written.
    #[must_use]
    pub fn log_put(&self, key: &str, now: i64) -> Stmt {
        Stmt::new(
            format!(
                "INSERT INTO {log}(key, version, deleted, logged_at) \
                 SELECT key, version, 0, ? FROM {items} WHERE key = ?",
                log = self.log,
                items = self.items
            ),
            vec![Param::Int(now), Param::Text(key.to_owned())],
        )
    }

    // ---- the sweeper ------------------------------------------------------------------------

    /// The two statements that free one batch of expired items and their index entries. The
    /// second one's `rows_affected` is the batch size. Expiry is not a change, so no log row.
    #[must_use]
    pub fn sweep_expired(&self, now: i64, batch: i64) -> [Stmt; 2] {
        let pick = format!(
            "SELECT key FROM {} WHERE expires_at IS NOT NULL AND expires_at <= ? \
             ORDER BY expires_at, key LIMIT ?",
            self.items
        );
        let params = vec![Param::Int(now), Param::Int(batch)];
        [
            Stmt::new(
                format!("DELETE FROM {} WHERE key IN ({pick})", self.index),
                params.clone(),
            ),
            Stmt::new(
                format!("DELETE FROM {} WHERE key IN ({pick})", self.items),
                params,
            ),
        ]
    }

    /// The two statements that trim the change log: raise the floor to the newest sequence logged
    /// before `cutoff`, then delete every row up to the floor. Trimming up to a sequence, not by
    /// time row by row, keeps the log contiguous when two nodes' clocks differ.
    #[must_use]
    pub fn trim_log(&self, cutoff: i64) -> [Stmt; 2] {
        [
            Stmt::new(
                format!(
                    "UPDATE {meta} SET value = MAX(value, COALESCE((SELECT MAX(seq) FROM {log} WHERE logged_at < ?), 0)) \
                     WHERE name = 'log_floor'",
                    meta = self.meta,
                    log = self.log
                ),
                vec![Param::Int(cutoff)],
            ),
            Stmt::new(
                format!(
                    "DELETE FROM {log} WHERE seq <= (SELECT value FROM {meta} WHERE name = 'log_floor')",
                    meta = self.meta,
                    log = self.log
                ),
                vec![],
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns() -> Ns {
        Ns::new("durable").unwrap()
    }

    #[test]
    fn only_the_two_ports_have_a_namespace() {
        assert!(Ns::new("temp").is_ok());
        for bad in ["", "durable_items", "x; DROP TABLE y", "Durable"] {
            assert!(Ns::new(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_prefix_is_a_range_never_like() {
        let s = ns().query("a/b/", None, None, 11, 5);
        assert!(!s.sql.contains("LIKE"));
        assert!(s.sql.contains("key >= ?") && s.sql.contains("key < ?"));
        assert_eq!(
            s.params,
            vec![
                Param::Int(5),
                Param::Text("a/b/".into()),
                Param::Text("a/b0".into()),
                Param::Int(11)
            ]
        );
        let after = ns().query("a/b/", Some("a/b/m"), None, 1, 5);
        assert!(after.sql.contains("key > ?") && !after.sql.contains("key >= ?"));
        // The number of placeholders is the number of parameters, for every shape.
        for s in [
            s,
            after,
            ns().query("", None, Some(("n", b"v")), 3, 1),
            ns().guard("k", Expected::Version(2), 1),
            ns().upsert("k", b"v", Some(9), 1),
            ns().sweep_expired(1, 500)[0].clone(),
        ] {
            assert_eq!(s.sql.matches('?').count(), s.params.len(), "{}", s.sql);
        }
    }

    #[test]
    fn user_bytes_are_never_in_the_sql_text() {
        let s = ns().upsert("k'; DROP TABLE x; --", b"v", None, 1);
        assert!(!s.sql.contains("DROP"));
        let g = ns().guard("k'; DROP TABLE x; --", Expected::Absent, 1);
        assert!(!g.sql.contains("DROP"));
    }
}
