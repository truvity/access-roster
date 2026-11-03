# actors

One directory here is one executable: an actor of the registry in `docs/architecture/actors.yaml`. A Go actor has a `main.go` (package `main`) and its logic under `internal/`; a Rust actor has a `Cargo.toml` and a `src/main.rs`. Which actor is in which language is the per-actor table of ADR 0012. Nothing outside the actor imports its internals: actors talk to each other only over the contracts in `proto/`.
