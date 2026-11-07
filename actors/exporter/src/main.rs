//! `exporter`: serve | check | version (cli.md).

fn main() {
    sluis_kit::cli::main("exporter", exporter::run::Exporter, exporter::run::extra)
}
