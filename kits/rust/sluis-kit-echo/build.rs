//! Compiles the echo contract. It is a copy of `kits/conformance/kit/proto/.../echo.proto` of
//! WP-04 (the Go kit), kept here until that file is on `main`; then this crate builds from it.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    connectrpc_build::Config::new()
        .files(&["proto/sluis/conformance/v2alpha1/echo.proto"])
        .includes(&["proto"])
        .include_file("_connectrpc.rs")
        .compile()?;
    Ok(())
}
