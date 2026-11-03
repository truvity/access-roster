# kits

The libraries every actor and driver is built on, one directory tree per language: `kits/go/<name>` in the Go module `github.com/truvity/sluis/v2`, and `kits/rust/<crate>` as members of the Cargo workspace (matched by glob, so a new crate edits no manifest at the root). `kits/conformance` holds the language-neutral test vectors that both languages must pass. A kit holds code that two or more executables share and nothing else. `kits/go/version` and `kits/rust/sluis-version` carry the one release version (ADR 0013).
