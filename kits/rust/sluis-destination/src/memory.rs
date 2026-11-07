//! The in-memory driver of the destination port (tests and the conformance suite only; no executable serves it).
//!
//! It keeps documents in a map, records every call in order (`calls`), and can play what a test needs of a destination:
//! a public address with an edge cache in front of it (a copy stays until it is purged, so a stale copy is possible), a
//! call that fails a number of times, and a purge that is accepted and does nothing.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::{
    Destination, Document, Error, Fetched, Listed, Page, Purged, Written, check_address,
    check_document, check_prefix, page_size, sha256_hex,
};

/// One call the driver took, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `put`, with the address.
    Put(String),
    /// `delete`, with the address.
    Delete(String),
    /// `list`, with the prefix.
    List(String),
    /// `purge`, with the addresses.
    Purge(Vec<String>),
    /// `read_back`, with the address.
    ReadBack(String),
}

/// A call of the port, to name which one fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `put`.
    Put,
    /// `delete`.
    Delete,
    /// `list`.
    List,
    /// `purge`.
    Purge,
    /// `read_back`.
    ReadBack,
}

#[derive(Clone)]
struct Stored {
    content_type: String,
    cache_control: String,
    body: Vec<u8>,
}

struct Public {
    base: String,
    edge: bool,
}

#[derive(Default)]
struct State {
    docs: BTreeMap<String, Stored>,
    public: Option<Public>,
    edge_cache: BTreeMap<String, Stored>,
    calls: Vec<Call>,
    failures: Vec<(Op, usize, Error)>,
    purge_does_nothing: bool,
    next_version: u64,
}

/// The in-memory driver. Clones share the documents, the calls and the failures.
#[derive(Clone, Default)]
pub struct Memory {
    state: Arc<Mutex<State>>,
}

impl Memory {
    /// A destination with no public address: `purge` answers [`Purged::None`] and `read_back` is unsupported, as a
    /// directory with none declared does.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A destination whose documents are served at `<base>/<address>`. With `edge` a cache sits in front of them: a
    /// `read_back` fills it, and only a `purge` empties it.
    #[must_use]
    pub fn with_public(base: &str, edge: bool) -> Self {
        let m = Self::default();
        m.lock().public = Some(Public {
            base: base.trim_end_matches('/').to_owned(),
            edge,
        });
        m
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The public address of a document, if the destination has one.
    #[must_use]
    pub fn public_address(&self, address: &str) -> Option<String> {
        self.lock()
            .public
            .as_ref()
            .map(|p| format!("{}/{address}", p.base))
    }

    /// Every call so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    /// Forgets the calls so far.
    pub fn clear_calls(&self) {
        self.lock().calls.clear();
    }

    /// Makes the next `times` calls of `op` fail with `error`.
    pub fn fail(&self, op: Op, times: usize, error: Error) {
        self.lock().failures.push((op, times, error));
    }

    /// Makes every later call of `op` fail with `error`, for good.
    pub fn fail_for_good(&self, op: Op, error: Error) {
        self.lock().failures.push((op, usize::MAX, error));
    }

    /// Stops the failures set so far.
    pub fn heal(&self) {
        self.lock().failures.clear();
    }

    /// A `purge` that the edge accepts and does nothing with: the stale copy stays.
    pub fn purge_does_nothing(&self, yes: bool) {
        self.lock().purge_does_nothing = yes;
    }

    /// The body held at the address, if any.
    #[must_use]
    pub fn body(&self, address: &str) -> Option<Vec<u8>> {
        self.lock().docs.get(address).map(|d| d.body.clone())
    }

    /// Writes at the address behind the port's back, as someone with access to the destination would.
    pub fn tamper(&self, address: &str, body: &[u8]) {
        let mut s = self.lock();
        let (ct, cc) = s.docs.get(address).map_or_else(Default::default, |d| {
            (d.content_type.clone(), d.cache_control.clone())
        });
        s.docs.insert(
            address.to_owned(),
            Stored {
                content_type: ct,
                cache_control: cc,
                body: body.to_vec(),
            },
        );
    }

    fn enter(&self, op: Op, call: Call) -> Result<MutexGuard<'_, State>, Error> {
        let mut s = self.lock();
        s.calls.push(call);
        if let Some(i) = s.failures.iter().position(|(o, n, _)| *o == op && *n > 0) {
            let e = s.failures[i].2.clone();
            if s.failures[i].1 != usize::MAX {
                s.failures[i].1 -= 1;
            }
            return Err(e);
        }
        Ok(s)
    }
}

impl Destination for Memory {
    async fn put(&self, doc: Document) -> Result<Written, Error> {
        check_document(&doc)?;
        let mut s = self.enter(Op::Put, Call::Put(doc.address.clone()))?;
        s.next_version += 1;
        let version = s.next_version;
        let sha256 = sha256_hex(&doc.body);
        s.docs.insert(
            doc.address,
            Stored {
                content_type: doc.content_type,
                cache_control: doc.cache_control,
                body: doc.body,
            },
        );
        Ok(Written {
            version: version.to_string(),
            sha256,
        })
    }

    async fn delete(&self, address: &str) -> Result<bool, Error> {
        check_address(address)?;
        let mut s = self.enter(Op::Delete, Call::Delete(address.to_owned()))?;
        Ok(s.docs.remove(address).is_some())
    }

    async fn list(&self, prefix: &str, page: Option<&str>, size: usize) -> Result<Page, Error> {
        check_prefix(prefix)?;
        let after = match page {
            None | Some("") => None,
            Some(t) => Some(t.to_owned()),
        };
        let s = self.enter(Op::List, Call::List(prefix.to_owned()))?;
        let size = page_size(size);
        let mut it = s
            .docs
            .iter()
            .filter(|(a, _)| a.starts_with(prefix))
            .filter(|(a, _)| after.as_ref().is_none_or(|t| a.as_str() > t.as_str()));
        let documents: Vec<Listed> = it
            .by_ref()
            .take(size)
            .map(|(a, d)| Listed {
                address: a.clone(),
                sha256: sha256_hex(&d.body),
                content_type: d.content_type.clone(),
                cache_control: d.cache_control.clone(),
                size: d.body.len() as u64,
            })
            .collect();
        let next = if it.next().is_some() {
            documents.last().map(|d| d.address.clone())
        } else {
            None
        };
        Ok(Page { documents, next })
    }

    async fn purge(&self, addresses: &[String]) -> Result<Purged, Error> {
        let mut s = self.enter(Op::Purge, Call::Purge(addresses.to_vec()))?;
        let Some(p) = s.public.as_ref() else {
            return Ok(Purged::None);
        };
        let (base, edge) = (p.base.clone(), p.edge);
        for a in addresses {
            if !a.strip_prefix(&base).is_some_and(|r| r.starts_with('/')) {
                return Err(Error::Invalid("addresses"));
            }
        }
        if !edge {
            return Ok(Purged::None);
        }
        if !s.purge_does_nothing {
            for a in addresses {
                s.edge_cache.remove(a);
            }
        }
        Ok(Purged::Purged)
    }

    async fn read_back(&self, address: &str) -> Result<Fetched, Error> {
        let mut s = self.enter(Op::ReadBack, Call::ReadBack(address.to_owned()))?;
        let Some(p) = s.public.as_ref() else {
            return Err(Error::Unsupported);
        };
        let (base, edge) = (p.base.clone(), p.edge);
        let Some(path) = address
            .strip_prefix(&base)
            .and_then(|r| r.strip_prefix('/'))
            .map(str::to_owned)
        else {
            return Err(Error::Invalid("address"));
        };
        let fetched = |d: &Stored, state: &str, age: &str| Fetched {
            status: 200,
            cache_control: d.cache_control.clone(),
            content_type: d.content_type.clone(),
            age: age.to_owned(),
            cache_state: state.to_owned(),
            body: d.body.clone(),
        };
        if edge && let Some(d) = s.edge_cache.get(address) {
            return Ok(fetched(d, "HIT", "1"));
        }
        match s.docs.get(&path).cloned() {
            Some(d) => {
                if edge {
                    s.edge_cache.insert(address.to_owned(), d.clone());
                }
                Ok(fetched(&d, if edge { "MISS" } else { "" }, ""))
            }
            None => Ok(Fetched {
                status: 404,
                cache_control: String::new(),
                content_type: String::new(),
                age: String::new(),
                cache_state: if edge { "MISS".into() } else { String::new() },
                body: Vec::new(),
            }),
        }
    }
}
