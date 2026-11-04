//! The source suite of the `file` driver (store-api.md "The command line and the suite"): the
//! cases of the source contract that a directory of documents can show. `conformance` runs it in
//! a temporary directory. A case that fails is the error; there is no skip.

use std::os::unix::fs::symlink;

use anyhow::{Result, ensure};

use crate::{DOCUMENT_MAX, Dir, Error};

macro_rules! refused {
    ($e:expr, $want:pat) => {{
        let got = $e.map(|d| d.version);
        ensure!(
            matches!(got, Err($want)),
            "{}: answered {got:?}",
            stringify!($e)
        )
    }};
}

/// Runs every case in a fresh directory.
///
/// # Errors
///
/// The first case that fails.
pub fn run_temp() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let root = tmp.path().join("config");
    std::fs::create_dir(&root)?;
    let dir = Dir::open(&root)?;

    // The bytes come back as they are, with the SHA-384 of the file as the label.
    std::fs::write(root.join("boundary.jws"), b"{\"payload\":\"x\"}")?;
    let a = dir.read("boundary")?;
    ensure!(a.data == b"{\"payload\":\"x\"}", "the bytes changed");
    ensure!(
        a.version.len() == 96 && a.version.bytes().all(|b| b.is_ascii_hexdigit()),
        "the label is not 96 hex digits"
    );
    ensure!(
        dir.read("boundary")?.version == a.version,
        "one content, two labels"
    );
    std::fs::write(root.join("boundary.jws"), b"{\"payload\":\"y\"}")?;
    ensure!(
        dir.read("boundary")?.version != a.version,
        "two contents, one label"
    );
    println!("ok: read gives the bytes and their label");

    // Absent is its own answer, and a version of an absent document is none.
    refused!(dir.read("upstream"), Error::Absent);
    ensure!(
        dir.version("upstream")?.is_none(),
        "an absent document has a label"
    );
    println!("ok: an absent document is absent");

    // A name is a kind's kebab-case name and nothing else: no way out of the directory.
    let long = "a".repeat(64);
    for bad in [
        "",
        "../boundary",
        "a/b",
        "a.b",
        "Boundary",
        "1a",
        "a_b",
        "-a",
        long.as_str(),
    ] {
        refused!(dir.read(bad), Error::Name);
    }
    println!("ok: a name that is not kebab-case is refused");

    // A link inside the directory is followed (a mounted ConfigMap is a tree of them); a link out
    // of it is not.
    std::fs::create_dir(root.join("..data"))?;
    std::fs::write(root.join("..data").join("key-plan.jws"), b"inside")?;
    symlink("..data/key-plan.jws", root.join("key-plan.jws"))?;
    ensure!(
        dir.read("key-plan")?.data == b"inside",
        "a link below the directory"
    );
    std::fs::write(tmp.path().join("outside"), b"outside")?;
    symlink("../outside", root.join("audit-log.jws"))?;
    refused!(dir.read("audit-log"), Error::Bound);
    symlink(tmp.path().join("outside"), root.join("token-lifetime.jws"))?;
    refused!(dir.read("token-lifetime"), Error::Bound);
    println!("ok: links stay below the directory");

    // A directory is not a document, and a document over the limit is not read.
    std::fs::create_dir(root.join("audit-catalogue.jws"))?;
    refused!(dir.read("audit-catalogue"), Error::Bound);
    let big = std::fs::File::create(root.join("exchange-trust.jws"))?;
    big.set_len(DOCUMENT_MAX + 1)?;
    refused!(dir.read("exchange-trust"), Error::Bound);
    println!("ok: a directory and an oversized file are refused");

    // A directory that is missing is not opened.
    ensure!(
        Dir::open(&tmp.path().join("nothing")).is_err(),
        "a missing directory was opened"
    );
    ensure!(
        Dir::open(&root.join("boundary.jws")).is_err(),
        "a file was opened as the directory"
    );
    println!("ok: the directory is checked");
    Ok(())
}
