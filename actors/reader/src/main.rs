//! `reader`: serve | check | version (cli.md).

fn main() {
    sluis_kit::cli::main("reader", reader::run::Reader, reader::run::extra)
}
