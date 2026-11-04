//! The transport suite (REQ-TEST-009) over a [`Spool`]: what any caller can rely on, run by
//! `conformance` in a temporary directory. A case that fails is the error; there is no skip.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::{Result, ensure};

use crate::{Config, Error, Spool};

fn root() -> Result<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}

fn ids(s: &Spool) -> Result<Vec<u64>> {
    Ok(s.read_from(0, usize::MAX, usize::MAX)?
        .0
        .iter()
        .map(|e| e.seq)
        .collect())
}

fn segment(dir: &Path) -> Result<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "seg"))
        .collect();
    v.sort();
    v.pop().ok_or_else(|| anyhow::anyhow!("no segment"))
}

/// Runs every case in fresh directories.
///
/// # Errors
///
/// The first case that fails.
pub fn run_temp() -> Result<()> {
    // The directory must be ours and closed.
    let wide = tempfile::tempdir()?;
    std::fs::set_permissions(wide.path(), std::fs::Permissions::from_mode(0o750))?;
    ensure!(
        Spool::open(wide.path(), Config::default()).is_err(),
        "a directory of mode 0750 was accepted"
    );
    println!("ok: directory checks");

    // Durable, ordered, and a second spool on the directory is refused.
    let dir = root()?;
    let s = Spool::open(dir.path(), Config::default())?;
    ensure!(
        Spool::open(dir.path(), Config::default()).is_err(),
        "two spools shared a directory"
    );
    let first = s.append("entry@dev", b"one")?;
    ensure!(
        s.syncs().file.load(Ordering::SeqCst) == 1,
        "an append did not sync the file"
    );
    ensure!(
        s.syncs().dir.load(Ordering::SeqCst) >= 1,
        "the first segment did not sync the directory"
    );
    let second = s.append("session@dev", b"two")?;
    let third = s.append("entry@dev", b"three")?;
    ensure!(
        (first, second, third) == (1, 2, 3),
        "sequence numbers are not 1, 2, 3"
    );
    let (all, tail) = s.read_from(0, 10, usize::MAX)?;
    ensure!(
        tail == 3
            && all.iter().map(|e| e.message.clone()).collect::<Vec<_>>()
                == [b"one".to_vec(), b"two".to_vec(), b"three".to_vec()],
        "the order or the bodies differ"
    );
    ensure!(all[1].emitter == "session@dev", "the emitter was lost");
    ensure!(
        s.read_from(1, 1, usize::MAX)?.0.first().map(|e| e.seq) == Some(2),
        "after/max not honoured"
    );
    println!("ok: durable and ordered");

    // An ack removes; a restart replays what is unacknowledged under the same ids.
    s.ack(&[2, 2, 99])?;
    ensure!(ids(&s)? == [1, 3], "an acknowledged message came again");
    drop(s);
    let s = Spool::open(dir.path(), Config::default())?;
    ensure!(
        ids(&s)? == [1, 3],
        "a restart did not replay the unacknowledged"
    );
    ensure!(
        s.append("entry@dev", b"four")? == 4,
        "sequence numbers did not continue"
    );
    println!("ok: ack and replay");

    // Drained segments are removed, and sequence numbers never go back.
    let small = Config {
        limit: 1 << 20,
        segment: 64,
    };
    let d2 = root()?;
    let s2 = Spool::open(d2.path(), small)?;
    for _ in 0..4 {
        s2.append("entry@dev", &[7u8; 40])?;
    }
    let before = std::fs::read_dir(d2.path())?.count();
    s2.ack(&[1, 2, 3])?;
    ensure!(
        std::fs::read_dir(d2.path())?.count() < before,
        "a drained segment stayed"
    );
    s2.ack(&[4])?;
    drop(s2);
    let s2 = Spool::open(d2.path(), small)?;
    ensure!(
        s2.depth() == 0 && s2.append("entry@dev", b"x")? == 5,
        "sequence numbers went back"
    );
    println!("ok: compaction");

    // A torn tail is cut; the rest survives.
    let d3 = root()?;
    let s3 = Spool::open(d3.path(), Config::default())?;
    s3.append("entry@dev", b"kept")?;
    s3.append("entry@dev", b"torn")?;
    drop(s3);
    let seg = segment(d3.path())?;
    let len = std::fs::metadata(&seg)?.len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&seg)?
        .set_len(len - 3)?;
    let s3 = Spool::open(d3.path(), Config::default())?;
    ensure!(ids(&s3)? == [1], "the torn frame or a good one was lost");
    ensure!(
        s3.append("entry@dev", b"after")? == 2,
        "append after a cut failed"
    );
    println!("ok: torn tail");

    // Full: refused, never dropped; room comes back with acks.
    let d4 = root()?;
    let tiny = Config {
        limit: 400,
        segment: 200,
    };
    let s4 = Spool::open(d4.path(), tiny)?;
    let mut held = 0u64;
    loop {
        match s4.append("entry@dev", &[1u8; 50]) {
            Ok(_) => held += 1,
            Err(Error::Full) => break,
            Err(e) => return Err(e.into()),
        }
        ensure!(held < 100, "the bound never held");
    }
    ensure!(
        held >= 2 && s4.depth() as u64 == held && s4.bytes() <= tiny.limit,
        "a message was dropped or the bound passed"
    );
    let seqs = ids(&s4)?;
    s4.ack(&seqs)?;
    s4.append("entry@dev", &[1u8; 50])?;
    ensure!(
        s4.bytes() <= tiny.limit,
        "the bound passed after room came back"
    );
    println!("ok: bounded");
    Ok(())
}
