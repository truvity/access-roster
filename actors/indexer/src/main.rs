//! `indexer`: serve | check | version (cli.md).

fn main() {
    sluis_kit::cli::main("indexer", indexer::run::Indexer, indexer::run::extra)
}
