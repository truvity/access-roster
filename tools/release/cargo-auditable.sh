#!/usr/bin/env bash
# `cargo auditable <subcommand> ...` for GoReleaser's Rust builder, which runs `<tool> <command> <flags>` and so cannot
# say `cargo auditable zigbuild`: it runs this file as the tool, with `zigbuild` as the command. cargo-auditable records
# the crates of the build in the executable, where syft reads them for the SBOM (ADR 0013, "Signing and checksums").
set -euo pipefail
exec cargo auditable "$@"
