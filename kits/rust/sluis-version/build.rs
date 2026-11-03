//! Makes `SLUIS_VERSION` available to the crate. The release build sets it in the environment
//! (ADR 0013, One version); a development build gets `0.0.0-dev`.

fn main() {
    println!("cargo:rerun-if-env-changed=SLUIS_VERSION");
    if std::env::var_os("SLUIS_VERSION").is_none() {
        println!("cargo:rustc-env=SLUIS_VERSION=0.0.0-dev");
    }
}
