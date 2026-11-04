//! Compiles the echo contract of `kits/conformance/kit/proto` (WP-04, the Go kit, owns it). The
//! Rust and the Go side of the cross-language test therefore read one file.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR")?)
        .join("../../conformance/kit/proto");
    connectrpc_build::Config::new()
        .files(&[root.join("sluis/conformance/v2alpha1/echo.proto")])
        .includes(&[&root])
        .include_file("_connectrpc.rs")
        .compile()?;
    Ok(())
}
