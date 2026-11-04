//! The blob port suite (REQ-TEST-009, REQ-AUDIT-103) over a [`Fs`]. `conformance` runs it against
//! a temporary directory. A case that fails is the error; there is no skip.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use anyhow::{Result, bail, ensure};

use crate::{Error, Fs};

macro_rules! refused {
    ($e:expr, $want:pat) => {{
        let got = $e.map(|_| ());
        ensure!(
            matches!(got, Err($want)),
            "{}: answered {got:?}",
            stringify!($e)
        )
    }};
}

/// Runs every case in a fresh directory of mode 0750.
///
/// # Errors
///
/// The first case that fails.
pub fn run_temp() -> Result<()> {
    let dir = tempfile::tempdir()?;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750))?;
    let fs = Fs::open(dir.path())?;
    let mode =
        |p: &str| std::fs::metadata(dir.path().join(p)).map(|m| m.permissions().mode() & 0o777);

    // A root that is open to others, or a symlink, is refused at the start.
    let wide = tempfile::tempdir()?;
    std::fs::set_permissions(wide.path(), std::fs::Permissions::from_mode(0o770))?;
    ensure!(
        Fs::open(wide.path()).is_err(),
        "a root of mode 0770 was accepted"
    );
    let link = dir.path().join("root-link");
    std::os::unix::fs::symlink(dir.path(), &link)?;
    ensure!(
        Fs::open(&link).is_err(),
        "a symlink as the root was accepted"
    );
    std::fs::remove_file(&link)?;
    println!("ok: root checks");

    // Create is write-once; modes are 0640 and 0750.
    let tag = fs.create("log/tile/0/000", b"one")?;
    ensure!(
        fs.get("log/tile/0/000")? == (b"one".to_vec(), tag),
        "get differs from create"
    );
    refused!(fs.create("log/tile/0/000", b"two"), Error::Taken);
    ensure!(
        fs.get("log/tile/0/000")?.0 == b"one",
        "a second create changed the object"
    );
    ensure!(
        mode("log/tile/0/000")? == 0o640 && mode("log/tile")? == 0o750,
        "modes are not 0640/0750"
    );
    refused!(fs.get("log/missing"), Error::Absent);
    println!("ok: create is write-once");

    // Many creators race for one path: exactly one wins, the rest are Taken.
    let fs2 = Arc::new(fs.clone());
    let racers: Vec<_> = (0..32u8)
        .map(|i| {
            let fs = fs2.clone();
            std::thread::spawn(move || fs.create("race/entries/000", &[i]).map(|_| i))
        })
        .collect();
    let mut won = Vec::new();
    for r in racers {
        match r.join() {
            Ok(Ok(i)) => won.push(i),
            Ok(Err(Error::Taken)) => {}
            other => bail!("a racing create answered {other:?}"),
        }
    }
    ensure!(
        won.len() == 1,
        "{} creators won the race, want 1",
        won.len()
    );
    ensure!(
        fs.get("race/entries/000")?.0 == won,
        "the object is not the winner's"
    );
    println!("ok: 32 racing creators, one winner");

    // Put overwrites only a pointer, and only under its tag.
    refused!(fs.put("log/tile/0/000", b"x", ""), Error::Rule);
    refused!(fs.put("log/other", b"x", "any"), Error::Rule);
    refused!(fs.put("log/checkpoint", b"c1", "stale"), Error::Version);
    let t1 = fs.put("log/checkpoint", b"c1", "")?;
    refused!(fs.put("log/checkpoint", b"c1", ""), Error::Version);
    let t2 = fs.put("log/checkpoint", b"c2", &t1)?;
    refused!(fs.put("log/checkpoint", b"c3", &t1), Error::Version);
    ensure!(
        fs.get("log/checkpoint")? == (b"c2".to_vec(), t2),
        "the pointer is not the last put"
    );
    println!("ok: conditional put on pointers only");

    // The tag is the SHA-384 of the content: same-size contents still differ, so a stale tag
    // cannot win after other puts (an inode- or clock-based tag can repeat).
    let ta = fs.put("tags/checkpoint", b"AAAA", "")?;
    ensure!(
        ta.len() == 96,
        "a SHA-384 tag is 96 hex digits, got {}",
        ta.len()
    );
    let tb = fs.put("tags/checkpoint", b"BBBB", &ta)?;
    let tc = fs.put("tags/checkpoint", b"CCCC", &tb)?;
    ensure!(
        ta != tb && tb != tc && ta != tc,
        "same-size contents share a tag"
    );
    refused!(fs.put("tags/checkpoint", b"DDDD", &ta), Error::Version);
    ensure!(
        fs.get("tags/checkpoint")? == (b"CCCC".to_vec(), tc),
        "a stale tag changed the pointer"
    );
    println!("ok: tags follow the content");

    // Two drivers on one directory (two open file descriptions, so two mutexes): of many puts
    // under one tag exactly one wins, because the flock orders them.
    let other = Fs::open(dir.path())?;
    let t0 = fs.put("fence/checkpoint", b"0", "")?;
    let putters: Vec<_> = (0..16u8)
        .map(|i| {
            let f = if i % 2 == 0 {
                fs.clone()
            } else {
                other.clone()
            };
            let t0 = t0.clone();
            std::thread::spawn(move || f.put("fence/checkpoint", &[b'a' + i], &t0))
        })
        .collect();
    let mut wins = 0;
    for p in putters {
        match p.join() {
            Ok(Ok(_)) => wins += 1,
            Ok(Err(Error::Version)) => {}
            other => bail!("a racing put answered {other:?}"),
        }
    }
    ensure!(wins == 1, "{wins} puts won under one tag, want 1");
    println!("ok: puts of two drivers are ordered by flock");

    // A restart removes only the driver's own temporary names.
    std::fs::create_dir_all(dir.path().join("sw/deep"))?;
    for keep in [
        "sw/.tmp-x-1",
        "sw/.tmp-1",
        "sw/.tmpfoo",
        "sw/.tmp-1-2-3",
        "sw/data",
    ] {
        std::fs::write(dir.path().join(keep), b"k")?;
    }
    for gone in ["sw/.tmp-12-3", "sw/deep/.tmp-4-5"] {
        std::fs::write(dir.path().join(gone), b"t")?;
    }
    ensure!(fs.sweep()? == 2, "sweep removed another count");
    for keep in [
        "sw/.tmp-x-1",
        "sw/.tmp-1",
        "sw/.tmpfoo",
        "sw/.tmp-1-2-3",
        "sw/data",
    ] {
        ensure!(dir.path().join(keep).exists(), "sweep removed {keep}");
    }
    ensure!(
        !dir.path().join("sw/.tmp-12-3").exists(),
        "sweep left a temporary file"
    );
    println!("ok: sweep");

    // No path leaves the root.
    let outside = tempfile::tempdir()?;
    std::fs::write(outside.path().join("f"), b"secret")?;
    std::os::unix::fs::symlink(outside.path(), dir.path().join("out"))?;
    std::os::unix::fs::symlink(outside.path().join("f"), dir.path().join("file-link"))?;
    for bad in [
        "../x", "/abs", "a//b", "a/./b", "a/../b", "", ".hidden", "a/.tmp-1", "out/f", "out/new",
    ] {
        refused!(fs.get(bad), Error::Path);
        refused!(fs.create(bad, b"x"), Error::Path);
        refused!(fs.put(&format!("{bad}/checkpoint"), b"x", ""), Error::Path);
    }
    // A symlink in the way is a name in use: it is never read or written through.
    refused!(fs.get("file-link"), Error::Path);
    refused!(fs.create("file-link", b"x"), Error::Taken);
    ensure!(
        std::fs::read(outside.path().join("f"))? == b"secret",
        "a create wrote through a symlink"
    );
    ensure!(
        !outside.path().join("new").exists(),
        "a create wrote through a symlink"
    );
    println!("ok: paths and symlinks refused");

    // List: byte order, prefix, pages, no temporary files.
    for p in ["l/a/1", "l/a/2", "l/b", "l/c/1", "m/1"] {
        fs.create(p, b"x")?;
    }
    std::fs::write(dir.path().join("l/.tmp-9-9"), b"x")?;
    let (all, next) = fs.list("l/", "", 0)?;
    ensure!(
        all == ["l/a/1", "l/a/2", "l/b", "l/c/1"] && next.is_empty(),
        "list l/: {all:?}"
    );
    let (some, _) = fs.list("l/a/", "", 0)?;
    ensure!(some == ["l/a/1", "l/a/2"], "list l/a/: {some:?}");
    let (part, _) = fs.list("l/c", "", 0)?;
    ensure!(part == ["l/c/1"], "list l/c: {part:?}");
    let (mut seen, mut token) = (Vec::new(), String::new());
    loop {
        let (page, next) = fs.list("l/", &token, 3)?;
        ensure!(page.len() <= 3, "a page of {}", page.len());
        seen.extend(page);
        if next.is_empty() {
            break;
        }
        token = next;
    }
    ensure!(seen == all, "pages {seen:?} differ from the whole {all:?}");
    ensure!(
        fs.list("nothing/", "", 0)?.0.is_empty(),
        "a missing prefix listed something"
    );
    refused!(fs.list("../", "", 0), Error::Path);
    refused!(fs.list("l/", "", -1), Error::Path);
    println!("ok: list");
    Ok(())
}
