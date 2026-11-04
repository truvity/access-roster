//! `policy`: serve | check | version.

fn main() {
    sluis_kit::cli::main("policy", policy::run::Policy, policy::run::extra)
}
