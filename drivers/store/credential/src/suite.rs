//! The source suite of the `credential` driver (store-api.md "The command line and the suite"):
//! the cases of the source contract that a directory of credentials can show. `conformance` runs
//! it in a temporary directory. A case that fails is the error; there is no skip.

use std::os::unix::fs::{PermissionsExt as _, symlink};

use anyhow::{Result, ensure};

use crate::{Dir, Error, SECRET_MAX};

macro_rules! refused {
    ($e:expr, $want:pat) => {{
        let got = $e.map(|s| s.version);
        ensure!(
            matches!(got, Err($want)),
            "{}: answered {got:?}",
            stringify!($e)
        )
    }};
}

fn put(dir: &std::path::Path, name: &str, data: &[u8], mode: u32) -> Result<()> {
    let path = dir.join(name);
    std::fs::write(&path, data)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Runs every case in a fresh directory.
///
/// # Errors
///
/// The first case that fails. A message names a case, never a value.
pub fn run_temp() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("credentials");
    std::fs::create_dir(&root)?;
    let dir = Dir::open(&root)?;

    // The bytes come back as they are, and the label does not depend on them alone.
    put(&root, "upstream-workforce", b"s3cret\n", 0o400)?;
    let a = dir.read("upstream-workforce")?;
    ensure!(a.data == b"s3cret\n", "the bytes changed");
    ensure!(!a.version.is_empty(), "no label");
    ensure!(
        dir.read("upstream-workforce")?.version == a.version,
        "one file, two labels"
    );
    println!("ok: read gives the bytes and a label");

    // Absent is its own answer.
    refused!(dir.read("nothing"), Error::Absent);
    println!("ok: an absent credential is absent");

    // A name is a credential name: no way out of the directory, no hidden file.
    for bad in [
        "",
        "../x",
        "a/b",
        ".hidden",
        "a b",
        "a\0b",
        &"a".repeat(129),
    ] {
        refused!(dir.read(bad), Error::Name);
    }
    println!("ok: a name that is not a credential name is refused");

    // A secret that others can read is not served; nor is a link, in or out of the directory.
    put(&root, "open-to-group", b"x", 0o440)?;
    put(&root, "open-to-others", b"x", 0o404)?;
    refused!(dir.read("open-to-group"), Error::Rule);
    refused!(dir.read("open-to-others"), Error::Rule);
    symlink("upstream-workforce", root.join("link-inside"))?;
    refused!(dir.read("link-inside"), Error::Bound);
    put(tmp.path(), "outside", b"x", 0o400)?;
    symlink("../outside", root.join("link-outside"))?;
    refused!(dir.read("link-outside"), Error::Bound);
    println!("ok: a file open to others and a link are refused");

    // A directory is not a credential, and a file over the limit is not read.
    std::fs::create_dir(root.join("a-directory"))?;
    refused!(dir.read("a-directory"), Error::Bound);
    put(&root, "big", b"", 0o600)?;
    std::fs::OpenOptions::new()
        .write(true)
        .open(root.join("big"))?
        .set_len(SECRET_MAX + 1)?;
    std::fs::set_permissions(root.join("big"), std::fs::Permissions::from_mode(0o400))?;
    refused!(dir.read("big"), Error::Bound);
    println!("ok: a directory and an oversized file are refused");

    // The label moves when the file does.
    put(&root, "rotated", b"one", 0o400)?;
    let before = dir.read("rotated")?.version;
    std::fs::remove_file(root.join("rotated"))?;
    put(&root, "rotated", b"two-and-more", 0o400)?;
    ensure!(
        dir.read("rotated")?.version != before,
        "the label did not move with the file"
    );
    println!("ok: the label moves with the file");

    ensure!(
        Dir::open(&tmp.path().join("nothing")).is_err(),
        "a missing directory was opened"
    );
    symlink(&root, tmp.path().join("root-link"))?;
    ensure!(
        Dir::open(&tmp.path().join("root-link")).is_err(),
        "a symlink was opened as the directory"
    );
    println!("ok: the directory is checked");
    Ok(())
}
