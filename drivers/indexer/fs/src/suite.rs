//! The read side of the blob port suite (REQ-TEST-009): what the writer's driver made is read back
//! through [`Fs::open_read_only`], and nothing in this driver can change it. `conformance` runs it
//! against a temporary directory. A case that fails is the error; there is no skip.

use std::os::unix::fs::PermissionsExt;

use anyhow::{Result, ensure};
use sluis_driver_writer_fs::{Error, Fs};

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
    let me = rustix::process::geteuid().as_raw();
    let writer = Fs::open(dir.path())?;
    let reader = Fs::open_read_only(dir.path(), me)?;

    // A root of another owner, a wide mode and a symlink are refused at the start.
    ensure!(
        Fs::open_read_only(dir.path(), me.wrapping_add(1)).is_err(),
        "a root of another owner was accepted"
    );
    let wide = tempfile::tempdir()?;
    std::fs::set_permissions(wide.path(), std::fs::Permissions::from_mode(0o770))?;
    ensure!(
        Fs::open_read_only(wide.path(), me).is_err(),
        "a root of mode 0770 was accepted"
    );
    let link = dir.path().join("root-link");
    std::os::unix::fs::symlink(dir.path(), &link)?;
    ensure!(
        Fs::open_read_only(&link, me).is_err(),
        "a symlink as the root was accepted"
    );
    std::fs::remove_file(&link)?;
    println!("ok: root checks");

    // What the writer made is read back, byte for byte, with the same tag.
    let tag = writer.create("log/tile/entries/000", b"one")?;
    writer.create("log/tile/entries/001", b"two")?;
    let cp = writer.put("log/checkpoint", b"c1", "")?;
    ensure!(
        reader.get("log/tile/entries/000")? == (b"one".to_vec(), tag),
        "get differs from what the writer made"
    );
    ensure!(
        reader.get("log/checkpoint")? == (b"c1".to_vec(), cp),
        "the pointer differs from what the writer made"
    );
    refused!(reader.get("log/missing"), Error::Absent);
    println!("ok: get");

    // List is the writer's list.
    let (all, next) = reader.list("log/", "", 0)?;
    ensure!(
        all == [
            "log/checkpoint",
            "log/tile/entries/000",
            "log/tile/entries/001"
        ] && next.is_empty(),
        "list log/: {all:?}"
    );
    ensure!(
        all == writer.list("log/", "", 0)?.0,
        "the two drivers list differently"
    );
    refused!(reader.list("../", "", 0), Error::Path);
    refused!(reader.get("../x"), Error::Path);
    println!("ok: list");

    // A later object of the writer is seen without a restart.
    writer.create("log/tile/entries/002", b"three")?;
    ensure!(
        reader.get("log/tile/entries/002")?.0 == b"three",
        "an object made after the open is not read"
    );
    println!("ok: a later object is read");
    Ok(())
}
