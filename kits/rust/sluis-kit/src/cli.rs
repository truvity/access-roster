//! The one command shape of every Rust executable: `serve`, `check`, `version`, `conformance`,
//! with the exit codes of cli.md "Exit codes".

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Arg, ArgAction, ArgMatches, Command};
use tracing_subscriber::EnvFilter;

/// Exit code: success.
pub const EXIT_OK: u8 = 0;
/// Exit code: something that should have worked did not.
pub const EXIT_FAILURE: u8 = 1;
/// Exit code: a usage error, or a command that cannot run.
pub const EXIT_USAGE: u8 = 2;
/// Exit code: refused by a check.
pub const EXIT_REFUSED: u8 = 3;

/// The global flags of every command (cli cannot reach the environment for these: a flag or a
/// default, nothing else).
#[derive(Clone, Debug)]
pub struct Flags {
    /// `--boundary`: the boundary the command acts on.
    pub boundary: String,
    /// `--socket`: the socket the command serves or dials.
    pub socket: PathBuf,
    /// `--log-level`: a `tracing` filter such as `info`.
    pub log_level: String,
    /// `--json`: one JSON object on standard output.
    pub json: bool,
    /// The positional arguments after the command.
    pub args: Vec<String>,
    /// The parsed arguments, for the flags the `extra` function of [`main`] added to the command.
    pub matches: ArgMatches,
}

/// A check that ran and refused: [`main`] exits 3 instead of 1.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// What an executable does under each command. `serve` should end when [`shutdown_signal`]
/// resolves.
// The trait is used with a concrete type by `main`, never as a trait object, and `main` needs no
// `Send` future: the lint is about callers that spawn the future, which nobody does here.
#[allow(async_fn_in_trait)]
pub trait Commands {
    /// Runs the actor, driver or node until the shutdown signal.
    async fn serve(&self, f: Flags) -> anyhow::Result<()>;

    /// Checks without serving. `None`: this executable has no check, which is "not run" (exit 2),
    /// never a pass. An `Err` holding [`Refused`] exits 3.
    async fn check(&self, f: Flags) -> Option<anyhow::Result<()>> {
        let _ = f;
        None
    }

    /// Runs the driver conformance suite; drivers only. `None` is "not run" (exit 2).
    async fn conformance(&self, f: Flags) -> Option<anyhow::Result<()>> {
        let _ = f;
        None
    }
}

/// Resolves on SIGTERM or SIGINT.
pub async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        // No signal handling: wait for ever rather than stop at once.
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {},
        _ = int.recv() => {},
    }
}

fn command(name: &str) -> Command {
    let global = |a: Arg| a.global(true);
    let sub = |n: &'static str, about: &'static str| {
        Command::new(n).about(about).arg(
            Arg::new("args")
                .num_args(0..)
                .trailing_var_arg(true)
                .value_name("ARGS"),
        )
    };
    Command::new(name.to_owned())
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .subcommand_required(true)
        .arg_required_else_help(false)
        .arg(global(
            Arg::new("boundary")
                .long("boundary")
                .value_name("NAME")
                .default_value("")
                .help("The boundary the command acts on"),
        ))
        .arg(global(
            Arg::new("socket")
                .long("socket")
                .value_name("PATH")
                .default_value("")
                .help("The socket the command serves or dials"),
        ))
        .arg(global(
            Arg::new("log-level")
                .long("log-level")
                .value_name("LEVEL")
                .default_value("info")
                .help("A tracing filter, e.g. info or sluis_kit=debug"),
        ))
        .arg(global(
            Arg::new("json")
                .long("json")
                .action(ArgAction::SetTrue)
                .help("Print one JSON object on standard output"),
        ))
        .subcommand(sub("serve", "Run until SIGTERM"))
        .subcommand(sub("check", "Check without serving"))
        .subcommand(sub("version", "Print the version"))
        .subcommand(sub("conformance", "Run the driver conformance suite"))
}

/// Parses the command line, sets up logging and runs the command. Never returns.
///
/// Exit codes: 0 ok, 1 any other error, 2 usage (and a command this executable does not have),
/// 3 refused by a check ([`Refused`]).
pub fn main(name: &str, c: impl Commands, extra: impl FnOnce(Command) -> Command) -> ! {
    let code = run(
        name,
        c,
        extra,
        std::env::args_os(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    std::process::exit(i32::from(code))
}

/// [`main`] without the exit and with its output streams, for the kit's own tests. Results go to
/// `out`, everything a person reads to `err` (cli.md "Conventions").
fn run(
    name: &str,
    c: impl Commands,
    extra: impl FnOnce(Command) -> Command,
    argv: impl IntoIterator<Item = std::ffi::OsString>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> u8 {
    let matches = match extra(command(name)).try_get_matches_from(argv) {
        Ok(m) => m,
        Err(e) => {
            let (code, rendered) = (
                if e.use_stderr() { EXIT_USAGE } else { EXIT_OK },
                e.render().to_string(),
            );
            let _ = if code == EXIT_OK {
                out.write_all(rendered.as_bytes())
            } else {
                err.write_all(rendered.as_bytes())
            };
            return code;
        }
    };
    let Some((sub, sm)) = matches.subcommand() else {
        let _ = writeln!(
            err,
            "{name}: a command is needed: serve, check, version or conformance"
        );
        return EXIT_USAGE;
    };
    let flags = Flags {
        boundary: sm
            .get_one::<String>("boundary")
            .cloned()
            .unwrap_or_default(),
        socket: PathBuf::from(sm.get_one::<String>("socket").cloned().unwrap_or_default()),
        log_level: sm
            .get_one::<String>("log-level")
            .cloned()
            .unwrap_or_default(),
        json: sm.get_flag("json"),
        args: sm
            .get_many::<String>("args")
            .map(|v| v.cloned().collect())
            .unwrap_or_default(),
        matches: matches.clone(),
    };
    if sub == "version" {
        print_version(out, name, flags.json);
        return EXIT_OK;
    }
    let filter = match EnvFilter::try_new(&flags.log_level) {
        Ok(f) => f,
        Err(_) => {
            let _ = writeln!(err, "{name}: --log-level: not a tracing filter");
            return EXIT_USAGE;
        }
    };
    // Logs are JSON on standard error; a second initialisation (a test) is not an error.
    let _ = tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(err, "{name}: runtime: {e}");
            return EXIT_FAILURE;
        }
    };
    let outcome = runtime.block_on(async {
        match sub {
            "serve" => Some(c.serve(flags).await),
            "check" => c.check(flags).await,
            "conformance" => c.conformance(flags).await,
            _ => None,
        }
    });
    match (sub, outcome) {
        (_, Some(Ok(()))) => EXIT_OK,
        (_, Some(Err(e))) if e.downcast_ref::<Refused>().is_some() => {
            let _ = writeln!(err, "{name} {sub}: refused: {e}");
            EXIT_REFUSED
        }
        (_, Some(Err(e))) => {
            let _ = writeln!(err, "{name} {sub}: {e:#}");
            EXIT_FAILURE
        }
        // A check that cannot run is "not run", never a pass.
        (sub, None) => {
            let _ = writeln!(err, "{sub}: not-run");
            EXIT_USAGE
        }
    }
}

fn print_version(out: &mut impl Write, name: &str, json: bool) {
    let v = sluis_version::VERSION;
    let _ = if json {
        writeln!(
            out,
            r#"{{"name":"{name}","version":"{v}","contracts":["v2alpha1"]}}"#
        )
    } else {
        writeln!(out, "{name} {v}\ncontracts v2alpha1")
    };
}

/// Exit code as `ExitCode`, for an executable that does not use [`main`].
#[must_use]
pub fn exit_code(code: u8) -> ExitCode {
    ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Plain;
    impl Commands for Plain {
        async fn serve(&self, _f: Flags) -> anyhow::Result<()> {
            Ok(())
        }
    }

    struct Refusing;
    impl Commands for Refusing {
        async fn serve(&self, _f: Flags) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("boom"))
        }
        async fn check(&self, _f: Flags) -> Option<anyhow::Result<()>> {
            Some(Err(Refused("a rule".into()).into()))
        }
    }

    fn argv(a: &[&str]) -> Vec<std::ffi::OsString> {
        std::iter::once("t")
            .chain(a.iter().copied())
            .map(Into::into)
            .collect()
    }

    /// Runs the command line; returns the exit code, standard output and standard error.
    fn go(c: impl Commands, a: &[&str]) -> (u8, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let code = run("t", c, |c| c, argv(a), &mut out, &mut err);
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    #[test]
    fn version_exits_0_and_prints_the_version_and_the_contracts() {
        let (code, out, _) = go(Plain, &["version"]);
        assert_eq!(code, EXIT_OK);
        assert!(
            out.starts_with(&format!("t {}", sluis_version::VERSION)),
            "{out}"
        );
        assert!(out.contains("v2alpha1"));
        let (code, out, _) = go(Plain, &["version", "--json"]);
        assert_eq!(code, EXIT_OK);
        assert!(
            out.starts_with('{') && out.trim_end().ends_with('}'),
            "{out}"
        );
    }

    #[test]
    fn unknown_command_exits_2() {
        assert_eq!(go(Plain, &["frobnicate"]).0, EXIT_USAGE);
        assert_eq!(go(Plain, &[]).0, EXIT_USAGE);
        assert_eq!(go(Plain, &["serve", "--nope"]).0, EXIT_USAGE);
        assert_eq!(go(Plain, &["serve", "--log-level", "[[["]).0, EXIT_USAGE);
    }

    #[test]
    fn missing_check_is_not_run_and_exits_2() {
        let (code, out, err) = go(Plain, &["check"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("not-run"), "{err}");
        assert!(
            out.is_empty(),
            "a result goes to standard output only when there is one"
        );
        let (code, _, err) = go(Plain, &["conformance"]);
        assert_eq!(code, EXIT_USAGE);
        assert!(err.contains("not-run"), "{err}");
    }

    #[test]
    fn serve_ok_error_and_refusal_codes() {
        assert_eq!(go(Plain, &["serve"]).0, EXIT_OK);
        assert_eq!(go(Refusing, &["serve"]).0, EXIT_FAILURE);
        assert_eq!(go(Refusing, &["check"]).0, EXIT_REFUSED);
    }

    #[test]
    fn global_flags_reach_the_command() {
        struct Echo;
        impl Commands for Echo {
            async fn serve(&self, f: Flags) -> anyhow::Result<()> {
                anyhow::ensure!(f.boundary == "dev", "boundary");
                anyhow::ensure!(f.socket.as_os_str() == "/x.sock", "socket");
                anyhow::ensure!(f.json, "json");
                anyhow::ensure!(f.args == ["a", "b"], "args");
                anyhow::ensure!(
                    f.matches
                        .get_one::<String>("extra")
                        .is_some_and(|s| s == "z"),
                    "extra"
                );
                Ok(())
            }
        }
        let extra = |c: Command| c.arg(Arg::new("extra").long("extra").global(true));
        let code = run(
            "t",
            Echo,
            extra,
            argv(&[
                "serve",
                "--boundary",
                "dev",
                "--socket=/x.sock",
                "--json",
                "--extra",
                "z",
                "a",
                "b",
            ]),
            &mut Vec::new(),
            &mut Vec::new(),
        );
        assert_eq!(code, EXIT_OK);
    }
}
