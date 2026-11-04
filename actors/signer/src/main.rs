//! `signer`: serve | check | version.

fn main() {
    sluis_kit::cli::main("signer", signer::run::Signer, signer::run::extra)
}
