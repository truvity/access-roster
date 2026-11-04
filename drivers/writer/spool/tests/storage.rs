//! The spool's files: the suite, and the damage cases that need a look at the directory.

#![allow(clippy::unwrap_used, clippy::expect_used)] // a failed unwrap in a test is the failure

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sluis_driver_writer_spool::{Config, Spool, suite};

fn root() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

fn files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == ext))
        .collect();
    v.sort();
    v
}

fn ids(s: &Spool) -> Vec<u64> {
    s.read_from(0, usize::MAX, usize::MAX)
        .unwrap()
        .0
        .iter()
        .map(|e| e.seq)
        .collect()
}

const SMALL: Config = Config {
    limit: 1 << 20,
    segment: 64,
};

#[test]
fn the_transport_suite_passes() {
    suite::run_temp().unwrap();
}

#[test]
fn a_flipped_byte_in_the_last_frame_is_cut_like_a_torn_write() {
    let r = root();
    let s = Spool::open(r.path(), Config::default()).unwrap();
    s.append("entry@dev", b"good").unwrap();
    s.append("entry@dev", b"bad").unwrap();
    drop(s);
    let seg = files(r.path(), "seg").pop().unwrap();
    let mut b = std::fs::read(&seg).unwrap();
    let n = b.len();
    b[n - 1] ^= 0xff;
    std::fs::write(&seg, b).unwrap();
    let s = Spool::open(r.path(), Config::default()).unwrap();
    assert_eq!(ids(&s), [1]);
}

#[test]
fn a_cut_inside_the_header_of_the_last_frame_is_cut() {
    let r = root();
    let s = Spool::open(r.path(), Config::default()).unwrap();
    s.append("entry@dev", b"good").unwrap();
    let kept = std::fs::metadata(files(r.path(), "seg").pop().unwrap())
        .unwrap()
        .len();
    s.append("entry@dev", b"second").unwrap();
    drop(s);
    let seg = files(r.path(), "seg").pop().unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&seg)
        .unwrap()
        .set_len(kept + 7)
        .unwrap();
    let s = Spool::open(r.path(), Config::default()).unwrap();
    assert_eq!(ids(&s), [1]);
    // The file was cut back to the good frame, and the next append follows it.
    assert_eq!(std::fs::metadata(&seg).unwrap().len(), kept);
    assert_eq!(s.append("entry@dev", b"third").unwrap(), 2);
}

#[test]
fn damage_before_the_newest_segment_refuses_to_start() {
    let r = root();
    let s = Spool::open(r.path(), SMALL).unwrap();
    for _ in 0..4 {
        s.append("entry@dev", &[7u8; 40]).unwrap();
    }
    drop(s);
    let segs = files(r.path(), "seg");
    assert!(segs.len() > 1, "the test needs more than one segment");
    let first = &segs[0];
    let mut b = std::fs::read(first).unwrap();
    let n = b.len();
    b[n - 1] ^= 0xff;
    std::fs::write(first, b).unwrap();
    assert!(Spool::open(r.path(), SMALL).is_err());
}

#[test]
fn a_torn_ack_file_only_means_a_repeat_delivery() {
    let r = root();
    let s = Spool::open(r.path(), Config::default()).unwrap();
    for _ in 0..3 {
        s.append("entry@dev", b"x").unwrap();
    }
    s.ack(&[1]).unwrap();
    s.ack(&[2]).unwrap();
    drop(s);
    let ack = files(r.path(), "ack").pop().unwrap();
    let len = std::fs::metadata(&ack).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&ack)
        .unwrap()
        .set_len(len - 2)
        .unwrap();
    let s = Spool::open(r.path(), Config::default()).unwrap();
    assert_eq!(ids(&s), [2, 3]);
}

#[test]
fn a_file_that_is_not_a_regular_file_and_a_second_spool_are_refused() {
    let r = root();
    let target = r.path().join("elsewhere");
    std::fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, r.path().join(format!("{:020}.seg", 1))).unwrap();
    assert!(Spool::open(r.path(), Config::default()).is_err());

    let r = root();
    let _s = Spool::open(r.path(), Config::default()).unwrap();
    assert!(Spool::open(r.path(), Config::default()).is_err());
}

#[test]
fn the_files_are_private() {
    let r = root();
    let s = Spool::open(r.path(), Config::default()).unwrap();
    s.append("entry@dev", b"x").unwrap();
    s.ack(&[1]).unwrap();
    for p in files(r.path(), "seg")
        .into_iter()
        .chain(files(r.path(), "ack"))
    {
        assert_eq!(
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
