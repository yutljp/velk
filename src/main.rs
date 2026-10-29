#![cfg_attr(not(test), deny(clippy::missing_assert_message))]

mod cli;
mod cli_output;
mod terminal;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::json;

use terminal::{Language, Terminal};

#[cfg(test)]
use cli::{Cli, Command};
use velk::error::{Error, Result};
use velk::service::Binary;
use velk::sigs::Database;

/// Lets a closed pipe end the process quietly, as for other command-line
/// tools, instead of failing the next write.
#[cfg(unix)]
fn exit_on_closed_pipe() {
    unsafe extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    // SAFETY: SIGPIPE is 13 and SIG_DFL is 0 on Linux and macOS; no Rust
    // handler or pointer is passed. The standard library has no signal API.
    unsafe {
        signal(13, 0);
    }
}

fn parse_address(text: &str) -> std::result::Result<u64, String> {
    velk::addr::parse(text).ok_or_else(|| format!("invalid address: {text}"))
}

fn open_binary(
    path: &Path,
    project: Option<&Path>,
    options: &velk::loader::OpenOptions,
    signatures: &velk::service::SignatureOptions,
) -> Result<Binary> {
    let binary = match Binary::open_input_with_signatures(path, project, options, signatures) {
        Ok(binary) => binary,
        Err(error) => return Err(error),
    };
    if let Some(report) = &binary.image().packing {
        eprintln!(
            "unpacked {}{} using {}",
            report.packer,
            report
                .version
                .as_ref()
                .map_or(String::new(), |version| format!(" {version}")),
            report.method
        );
    }
    Ok(binary)
}

fn main() -> ExitCode {
    #[cfg(unix)]
    exit_on_closed_pipe();
    let cli = match cli::parse() {
        Ok(cli) => cli,
        Err(code) => return code,
    };
    let project = cli.project.clone();
    let input_options = velk::loader::OpenOptions {
        cache: cli.cache.clone().map(|value| {
            if value == "off" {
                velk::service::CacheLocation::Enabled(false)
            } else {
                velk::service::CacheLocation::Path(value.into())
            }
        }),
        arch: cli.arch,
        raw: cli.raw_arch.map(|arch| velk::loader::RawOptions {
            arch,
            base: cli.load_address.expect("clap requires a load address"),
            entries: cli.entry.clone(),
            byte_order: cli.raw_byte_order,
        }),
    };
    let signature_options = velk::service::SignatureOptions {
        defaults: !cli.no_default_signatures,
        files: cli.signatures.clone(),
    };
    if let Some(destination) = &cli.save_unpacked {
        let saved = match cli.input.as_deref() {
            Some(path) => {
                match open_binary(path, project.as_deref(), &input_options, &signature_options) {
                    Ok(binary) => binary.image().save_unpacked(destination),
                    Err(error) => Err(error),
                }
            }
            None => Err(Error::Packed(
                "saving requires an input executable".to_owned(),
            )),
        };
        if let Err(error) = saved {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    }
    let operation = if cli.annotate {
        Some(velk::project::cli::Command::Set {
            json: cli.function.clone().unwrap_or_default(),
        })
    } else if cli.annotation {
        Some(velk::project::cli::Command::Get {
            target: cli.function.clone().unwrap_or_default(),
        })
    } else if cli.annotations {
        Some(velk::project::cli::Command::List)
    } else if cli.unannotate {
        Some(velk::project::cli::Command::Remove {
            target: cli.function.clone().unwrap_or_default(),
        })
    } else if cli.export_project {
        Some(velk::project::cli::Command::Export)
    } else if cli.import_project {
        Some(velk::project::cli::Command::Import {
            file: PathBuf::from(cli.function.clone().unwrap_or_default()),
        })
    } else if cli.origins {
        Some(velk::project::cli::Command::Origins {
            function: cli.function.clone().unwrap_or_default(),
        })
    } else {
        None
    };
    if let Some(command) = operation {
        return match velk::project::cli::execute(velk::project::cli::Cli {
            binary: cli.input.expect("clap requires input"),
            arch: cli.arch,
            raw: input_options.raw,
            cache: input_options.cache,
            project,
            command,
        }) {
            Ok(value) => {
                println!("{value:#}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                let value = match &error {
                    Error::Project(detail) => json!(detail),
                    _ => json!({"code": "analysis_error", "message": error.to_string()}),
                };
                eprintln!("{value}");
                ExitCode::FAILURE
            }
        };
    }
    let decode_strings = !cli.no_string_decoding;
    match cli::run(
        cli.into_command(),
        project.as_deref(),
        &input_options,
        decode_strings,
        &signature_options,
    ) {
        Ok(code) => code,
        Err(Error::Project(detail)) => {
            eprintln!("{}", json!(detail));
            ExitCode::FAILURE
        }
        Err(error) => {
            eprintln!("{} {error}", Terminal::stderr().error("error:"));
            ExitCode::FAILURE
        }
    }
}

fn decompile_functions(
    binary: &mut Binary,
    addresses: &[u64],
    title: &str,
    signatures: Option<&Database>,
) -> ExitCode {
    use std::time::Duration;

    let mut code = String::new();
    let mut status = ExitCode::SUCCESS;
    let results = if addresses.len() <= 1 {
        addresses
            .iter()
            .map(|&addr| {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                binary.decompile(addr, signatures, Some(deadline))
            })
            .collect()
    } else {
        match binary.decompile_many(addresses, signatures, None) {
            Ok(results) => results,
            Err(error) => {
                for addr in addresses {
                    eprintln!("error: function at 0x{addr:x}: {error}");
                }
                return ExitCode::FAILURE;
            }
        }
    };
    for (&addr, result) in std::iter::zip(addresses, results) {
        match result {
            Ok(text) => code.push_str(&text),
            Err(error) => {
                eprintln!("error: function at 0x{addr:x}: {error}");
                status = ExitCode::FAILURE;
            }
        }
    }
    let code = velk::render::combine(&code);
    let addr = addresses.first().copied().unwrap_or(0);
    cli_output::print_code(binary, addr, title, &code, Language::C);
    status
}

fn write_json(path: &Path, value: &serde_json::Value) -> Result<()> {
    std::fs::write(path, format!("{value:#}\n")).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::{Cli, Command};
    use clap::Parser;
    use clap::error::ErrorKind;
    use std::path::PathBuf;
    use velk::card;

    #[cfg(all(unix, miri))]
    #[test]
    fn closed_pipe_signal() {
        super::exit_on_closed_pipe();
    }

    const OPERATIONS: [(&str, &str); 10] = [
        ("-f", "--functions"),
        ("-s", "--sections"),
        ("-c", "--card"),
        ("-D", "--decompile"),
        ("-d", "--disasm"),
        ("-i", "--ir"),
        ("-b", "--build-signatures"),
        ("-I", "--identify"),
        ("-r", "--run"),
        ("-m", "--mcp"),
    ];

    fn parse(args: &[&str]) -> Command {
        Cli::try_parse_from(std::iter::once("velk").chain(args.iter().copied()))
            .unwrap()
            .into_command()
    }

    fn error(args: &[&str]) -> clap::Error {
        match Cli::try_parse_from(std::iter::once("velk").chain(args.iter().copied())) {
            Ok(_) => panic!("expected invalid arguments: {args:?}"),
            Err(error) => error,
        }
    }

    #[test]
    fn project_flags_share_the_operation_parser() {
        for flag in [
            "--annotate",
            "--annotation",
            "--unannotate",
            "--import-project",
            "--origins",
        ] {
            assert!(
                Cli::try_parse_from([
                    "velk",
                    flag,
                    "binary",
                    "value",
                    "--project",
                    "annotations.json"
                ])
                .is_ok()
            );
            assert!(Cli::try_parse_from(["velk", flag, "binary"]).is_err());
        }
        for flag in [
            "--annotate",
            "--annotation",
            "--annotations",
            "--unannotate",
            "--export-project",
            "--import-project",
            "--origins",
        ] {
            assert!(Cli::try_parse_from(["velk", flag, "binary", "--functions"]).is_err());
            assert!(Cli::try_parse_from(["velk", flag, "binary", "--json"]).is_err());
            assert!(Cli::try_parse_from(["velk", flag, "binary", "--limit", "2"]).is_err());
        }
        assert!(Cli::try_parse_from(["velk", "--annotations", "binary"]).is_ok());
        assert!(Cli::try_parse_from(["velk", "--export-project", "binary"]).is_ok());
        assert!(Cli::try_parse_from(["velk", "project", "binary", "list"]).is_err());
    }

    #[test]
    fn navigation_operations_validate_arguments() {
        use velk::xrefs::query::Query;
        assert_eq!(
            parse(&["--path", "binary", "a", "b"]),
            Command::Navigation {
                path: PathBuf::from("binary"),
                query: Query::Path {
                    from: "a".into(),
                    to: "b".into(),
                    depth: 32
                },
            }
        );
        assert_eq!(
            parse(&["binary", "--xrefs", "a", "--from"]),
            Command::Navigation {
                path: PathBuf::from("binary"),
                query: Query::Xrefs {
                    target: "a".into(),
                    from: true
                },
            }
        );
        for flag in [
            "--xrefs",
            "--callers",
            "--callees",
            "--path",
            "--constants",
            "--summary",
        ] {
            error(&[flag, "binary"]);
            error(&[flag, "binary", "a", "--functions"]);
            error(&[flag, "binary", "a", "--json"]);
            error(&[flag, "binary", "a", "--limit", "2"]);
            error(&[flag.trim_start_matches('-'), "binary", "a"]);
        }
        for args in [
            vec!["--path", "binary", "a", "b", "c"],
            vec!["--summary", "binary", "a", "b"],
            vec!["--strings", "binary", "a"],
            vec!["--strings", "binary", "--from"],
            vec!["--summary", "binary", "a", "--depth", "2"],
            vec!["--xrefs", "binary", "a", "--contains", "hi"],
        ] {
            error(&args);
        }
        for args in [
            vec!["--callers", "binary", "a", "--depth", "0"],
            vec!["--callees", "binary", "a"],
            vec!["--strings", "binary", "--contains", "hi"],
            vec!["--constants", "binary", "0x12"],
            vec!["--summary", "binary", "a"],
        ] {
            parse(&args);
        }
    }

    #[test]
    fn short_and_long_operations_select_the_same_command() {
        let cases = [
            (
                vec!["binary", "--limit", "12", "--json"],
                Command::Functions {
                    path: PathBuf::from("binary"),
                    limit: 12,
                    json: true,
                },
            ),
            (
                vec!["binary"],
                Command::Sections {
                    path: PathBuf::from("binary"),
                },
            ),
            (
                vec![
                    "binary",
                    "sum3",
                    "--budget",
                    "360",
                    "--signatures",
                    "db.json",
                ],
                Command::Card {
                    path: PathBuf::from("binary"),
                    function: "sum3".into(),
                    budget: 360,
                },
            ),
            (
                vec!["binary", "0x1e0", "--signatures", "db.json"],
                Command::Decompile {
                    path: PathBuf::from("binary"),
                    functions: vec!["0x1e0".into()],
                },
            ),
            (
                vec!["binary", "sum3", "--limit", "12"],
                Command::Disasm {
                    path: PathBuf::from("binary"),
                    function: "sum3".into(),
                    limit: Some(12),
                    json: false,
                },
            ),
            (
                vec!["binary", "sum3"],
                Command::Ir {
                    path: PathBuf::from("binary"),
                    function: "sum3".into(),
                },
            ),
            (
                vec!["binary", "--output", "db.json"],
                Command::BuildSignatures {
                    path: PathBuf::from("binary"),
                    output: PathBuf::from("db.json"),
                },
            ),
            (
                vec!["binary", "--signatures", "db.json", "--limit", "12"],
                Command::Identify {
                    path: PathBuf::from("binary"),
                    limit: 12,
                },
            ),
            (
                vec!["script.js"],
                Command::Run {
                    script: PathBuf::from("script.js"),
                },
            ),
            (vec![], Command::Mcp),
        ];
        for ((short, long), (operands, expected)) in OPERATIONS.into_iter().zip(cases) {
            for flag in [short, long] {
                let args: Vec<_> = std::iter::once(flag)
                    .chain(operands.iter().copied())
                    .collect();
                assert_eq!(parse(&args), expected, "{flag}");
            }
        }
    }

    #[test]
    fn operation_defaults_are_preserved() {
        assert_eq!(
            parse(&["-f", "binary"]),
            Command::Functions {
                path: PathBuf::from("binary"),
                limit: 40,
                json: false,
            }
        );
        assert_eq!(
            parse(&["-c", "binary", "sum3"]),
            Command::Card {
                path: PathBuf::from("binary"),
                function: "sum3".into(),
                budget: card::DEFAULT_BUDGET,
            }
        );
        assert_eq!(
            parse(&["-d", "binary", "sum3"]),
            Command::Disasm {
                path: PathBuf::from("binary"),
                function: "sum3".into(),
                limit: None,
                json: false,
            }
        );
        assert_eq!(
            parse(&["-I", "binary", "--signatures", "db.json"]),
            Command::Identify {
                path: PathBuf::from("binary"),
                limit: 100,
            }
        );
    }

    #[test]
    fn every_pair_of_operations_conflicts() {
        for (index, (short, _)) in OPERATIONS.iter().enumerate() {
            for (_, long) in OPERATIONS.iter().skip(index + 1) {
                assert_eq!(error(&[short, long]).kind(), ErrorKind::ArgumentConflict);
            }
        }
    }

    #[test]
    fn operations_require_their_own_operands() {
        for (_, flag) in OPERATIONS.into_iter().take(9) {
            assert_eq!(error(&[flag]).kind(), ErrorKind::MissingRequiredArgument);
        }
        for flag in ["--card", "--disasm", "--ir"] {
            assert_eq!(
                error(&[flag, "binary"]).kind(),
                ErrorKind::MissingRequiredArgument
            );
        }
        assert_eq!(
            error(&["--build-signatures", "binary"]).kind(),
            ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn local_options_and_extra_operands_are_rejected() {
        for args in [
            vec!["-s", "binary", "--limit", "1"],
            vec!["-d", "binary", "sum3", "--budget", "20"],
            vec!["-D", "binary", "sum3", "--json"],
            vec!["-f", "binary", "--output", "db.json"],
            vec!["-f", "binary", "sum3"],
            vec!["-s", "binary", "sum3"],
            vec!["-b", "binary", "sum3", "--output", "db.json"],
            vec!["-I", "binary", "sum3", "--signatures", "db.json"],
            vec!["-r", "script.js", "sum3"],
            vec!["-m", "binary"],
            vec!["-m", "--limit", "1"],
        ] {
            error(&args);
        }
    }

    #[test]
    fn single_operation_options_conflict_with_every_other_operation() {
        for (allowed, option) in [
            (&["--card"][..], vec!["--budget", "20"]),
            (&["--functions", "--disasm"][..], vec!["--json"]),
            (&["--build-signatures"][..], vec!["--output", "db.json"]),
        ] {
            for (_, operation) in OPERATIONS {
                if allowed.contains(&operation) {
                    continue;
                }
                let mut args = vec![operation];
                if operation != "--mcp" {
                    args.push("binary");
                }
                if matches!(operation, "--card" | "--decompile" | "--disasm" | "--ir") {
                    args.push("sum3");
                }
                if operation == "--build-signatures" {
                    args.extend(["--output", "db.json"]);
                }
                if operation == "--identify" {
                    args.extend(["--signatures", "db.json"]);
                }
                args.extend(option.iter().copied());
                assert_eq!(error(&args).kind(), ErrorKind::ArgumentConflict, "{args:?}");
            }
        }
    }

    #[test]
    fn emulation_preserves_operation_and_option_conflicts() {
        assert_eq!(
            parse(&["--emulate", "binary", "decode", "--emulation-options", "{}"]),
            Command::Emulate {
                path: PathBuf::from("binary"),
                start: "decode".to_owned(),
                options: Some("{}".to_owned()),
                json: false,
            }
        );
        for operation in [
            "--compare",
            "--classes",
            "--search",
            "--read-memory",
            "--detect-constants",
        ] {
            assert_eq!(
                error(&["--emulate", operation, "binary", "decode"]).kind(),
                ErrorKind::ArgumentConflict
            );
        }
        for options in [
            vec!["--limit", "1"],
            vec!["--budget", "1"],
            vec!["--output", "db.json"],
        ] {
            let mut args = vec!["--emulate", "binary", "decode"];
            args.extend(options);
            assert_eq!(error(&args).kind(), ErrorKind::ArgumentConflict);
        }
        assert_eq!(
            error(&["--emulate", "binary"]).kind(),
            ErrorKind::MissingRequiredArgument
        );
        assert!(
            Cli::try_parse_from(["velk", "--functions", "binary", "--emulation-options", "{}"])
                .is_err()
        );
    }

    #[test]
    fn signature_options_apply_to_binary_operations() {
        for operation in [
            "--functions",
            "--identify",
            "--decompile",
            "--emulate",
            "--summary",
        ] {
            let mut args = vec!["velk", operation, "binary"];
            if matches!(operation, "--decompile" | "--emulate" | "--summary") {
                args.push("main");
            }
            args.extend([
                "--no-default-signatures",
                "--signatures",
                "first.json",
                "--signatures",
                "second.json.gz",
            ]);
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(cli.no_default_signatures);
            assert_eq!(
                cli.signatures,
                [PathBuf::from("first.json"), PathBuf::from("second.json.gz")]
            );
        }
        assert!(matches!(
            parse(&["--identify", "binary"]),
            Command::Identify { .. }
        ));
    }

    #[test]
    fn comparison_requires_two_binaries_and_compatible_options() {
        assert!(
            Cli::try_parse_from([
                "velk",
                "--compare",
                "first",
                "second",
                "--carry-annotations"
            ])
            .is_ok()
        );
        for args in [
            vec!["velk", "--compare", "first"],
            vec!["velk", "--compare", "first", "second", "--json"],
            vec!["velk", "--compare", "first", "second", "--limit", "1"],
            vec!["velk", "--compare", "first", "second", "--budget", "1"],
            vec!["velk", "--functions", "first", "--carry-annotations"],
            vec!["velk", "--compare", "--functions", "first", "second"],
        ] {
            assert!(Cli::try_parse_from(args.clone()).is_err(), "{args:?}");
        }
    }

    #[test]
    fn an_operation_flag_is_required() {
        assert_eq!(error(&[]).kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(
            error(&["binary", "sum3"]).kind(),
            ErrorKind::MissingRequiredArgument
        );
        error(&["binary", "--json"]);
        error(&["binary", "--budget", "20"]);
        for (_, flag) in OPERATIONS {
            assert!(Cli::try_parse_from(["velk", flag.trim_start_matches('-')]).is_err());
        }
        assert!(Cli::try_parse_from(["velk", "help"]).is_err());
    }

    #[test]
    fn operation_flags_and_positional_delimiters_follow_standard_parsing() {
        assert_eq!(
            parse(&["binary", "--functions", "--limit", "2"]),
            Command::Functions {
                path: PathBuf::from("binary"),
                limit: 2,
                json: false,
            }
        );
        assert_eq!(
            parse(&["-f", "--", "functions"]),
            Command::Functions {
                path: PathBuf::from("functions"),
                limit: 40,
                json: false,
            }
        );
        assert_eq!(
            parse(&["-d", "--", "-binary", "-sum3"]),
            Command::Disasm {
                path: PathBuf::from("-binary"),
                function: "-sum3".into(),
                limit: None,
                json: false,
            }
        );
    }

    #[test]
    fn help_is_available_for_every_operation() {
        for args in std::iter::once(vec!["--help"])
            .chain(OPERATIONS.into_iter().map(|(_, flag)| vec![flag, "--help"]))
        {
            let help = error(&args);
            assert_eq!(help.kind(), ErrorKind::DisplayHelp);
            let text = help.to_string();
            assert!(text.contains("Operations (choose one)"));
            assert!(text.contains("INPUT"));
            assert!(text.contains("FUNCTION"));
            assert!(text.contains("Examples:"));
            assert!(text.contains(&format!("default: {}", card::DEFAULT_BUDGET)));
        }
        for flag in ["-V", "--version"] {
            assert_eq!(error(&[flag]).kind(), ErrorKind::DisplayVersion);
            assert_eq!(error(&["-m", flag]).kind(), ErrorKind::DisplayVersion);
        }
    }
}
