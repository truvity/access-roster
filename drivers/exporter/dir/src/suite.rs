//! The conformance suite of the destination port, run against a temporary directory (REQ-EXPORT-027), and the cases
//! that are the directory's own.

use std::os::unix::fs::PermissionsExt;

use anyhow::{Result, ensure};
use sluis_destination::suite::{Caps, run};
use sluis_destination::{Destination, Document};

use crate::{Directory, Until};

/// A fresh pair of directories of the modes `open` wants.
///
/// # Errors
///
/// When the temporary directories cannot be made.
pub fn temp() -> Result<(tempfile::TempDir, tempfile::TempDir)> {
    let (root, state) = (tempfile::tempdir()?, tempfile::tempdir()?);
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755))?;
    std::fs::set_permissions(state.path(), std::fs::Permissions::from_mode(0o700))?;
    Ok((root, state))
}

/// The port's suite and the directory's own cases over temporary directories.
///
/// # Errors
///
/// The first case that fails.
pub async fn run_temp() -> Result<()> {
    let (root, state) = temp()?;
    let d = Directory::open(root.path(), state.path())?;
    run(&d, &Caps::default()).await?;
    own(&d, root.path()).await
}

fn doc(address: &str, body: &[u8]) -> Document {
    Document {
        address: address.into(),
        content_type: "application/json".into(),
        cache_control: "public, max-age=300".into(),
        body: body.to_vec(),
    }
}

async fn own(d: &Directory, root: &std::path::Path) -> Result<()> {
    // Files are public and directories open to traverse, whatever the umask of the process.
    d.put(doc("own/sub/x.json", b"{}")).await?;
    let mode = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.permissions().mode() & 0o777);
    ensure!(
        mode(&root.join("own/sub/x.json"))? == 0o644,
        "a document is not 0644"
    );
    ensure!(
        mode(&root.join("own/sub"))? == 0o755,
        "a directory is not 0755"
    );
    // A file someone else put in the directory is neither listed nor removed.
    std::fs::write(root.join("own/foreign.json"), b"x")?;
    ensure!(
        d.list("own/", None, 0).await?.documents.len() == 1,
        "a file the driver did not write is listed"
    );
    ensure!(
        !d.delete("own/foreign.json").await?,
        "a foreign file was removed"
    );
    ensure!(
        root.join("own/foreign.json").exists(),
        "a foreign file is gone"
    );
    // A document and a directory cannot share an address.
    ensure!(
        d.put(doc("own/sub", b"{}")).await.is_err(),
        "a document over a directory"
    );
    ensure!(
        d.put(doc("own/sub/x.json/y", b"{}")).await.is_err(),
        "a document below a document"
    );
    // Nothing is left behind by a write.
    d.delete("own/sub/x.json").await?;
    ensure!(
        !root.join("own/sub").exists(),
        "an empty directory is left after the last delete"
    );
    let left: Vec<_> = std::fs::read_dir(root.join("own"))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    ensure!(left == ["foreign.json"], "left behind: {left:?}");
    // A write stopped before the rename leaves the old document; a restart sweeps the stray file.
    d.put(doc("own/live.json", b"old")).await?;
    d.put_until(&doc("own/live.json", b"new"), Until::Temp)?;
    ensure!(
        std::fs::read(root.join("own/live.json"))? == b"old",
        "a half write shows"
    );
    ensure!(d.sweep()? == 1, "the sweep did not find the stray file");
    println!("ok: the directory's own cases");
    Ok(())
}
