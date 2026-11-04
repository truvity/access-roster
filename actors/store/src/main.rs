//! `store`: serve | check | version.

fn main() {
    sluis_kit::cli::main("store", store::run::Store, store::run::extra)
}
