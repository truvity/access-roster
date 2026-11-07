//! Compiles `proto/**/*.proto` into buffa messages and connectrpc services under `OUT_DIR`.
//! The generated code is never committed. The runtime is buffa, the one `connectrpc` 0.9 emits.

use std::path::{Path, PathBuf};

fn collect(dir: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            collect(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "proto") {
            out.push(p);
        }
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let repo = manifest.join("../../..");
    let root = repo.join("proto");
    // Cargo scans a directory recursively by mtime, so a changed .proto anywhere under it reruns this script.
    println!("cargo:rerun-if-changed={}", root.display());
    // A changed dependency of the module (buf.yaml, buf.lock) changes the descriptors too.
    println!("cargo:rerun-if-changed={}", repo.join("buf.yaml").display());
    println!("cargo:rerun-if-changed={}", repo.join("buf.lock").display());
    let mut files = Vec::new();
    collect(&root, &mut files)?;
    if files.is_empty() {
        return Err(format!("no .proto file under {}", root.display()).into());
    }
    // The names buf knows the files by: relative to the module root, as `import` writes them.
    let names = files
        .iter()
        .map(|f| f.strip_prefix(&root).map(Path::to_path_buf))
        .collect::<Result<Vec<_>, _>>()?;

    // The descriptors come from `buf build`, as `buf lint` and `buf generate` get theirs, because the messages import the
    // protovalidate options (buf/validate/validate.proto) of the module's dependency pinned in buf.lock, and only buf
    // resolves it. buf is in devbox, with protoc.
    let set = PathBuf::from(std::env::var("OUT_DIR")?).join("sluis.binpb");
    let buf = std::env::var("BUF").unwrap_or_else(|_| "buf".to_owned());
    let out = std::process::Command::new(&buf)
        .arg("build")
        .arg(&repo)
        .arg("--as-file-descriptor-set")
        .arg("-o")
        .arg(&set)
        .output()
        .map_err(|e| format!("cannot run `{buf}` (it is part of devbox): {e}"))?;
    if !out.status.success() {
        return Err(format!("buf build failed: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    connectrpc_build::Config::new()
        .descriptor_set(&set)
        .files(&names)
        .include_file("_connectrpc.rs")
        .compile()?;
    Ok(())
}
