//! The release version, stamped at build time through the `SLUIS_VERSION` environment variable.
//! Every Rust executable's `version` command prints it.

/// The version of this build: the release version, or `0.0.0-dev` for a development build.
pub const VERSION: &str = env!("SLUIS_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_set() {
        assert!(!VERSION.is_empty());
    }
}
