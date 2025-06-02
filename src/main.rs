use anchor_sec_lint::{lint_paths, render_text, rules::Level, sarif};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

#[derive(Clone, Copy, ValueEnum)]
enum FailOn {
    Error,
    Warning,
    Note,
    Never,
}

/// Heuristic security lints for Anchor (Solana) programs.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Rust source files/directories and/or Anchor IDL .json files
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    #[arg(short, long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Write output to a file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Exit with status 1 when a finding at or above this level exists
    #[arg(long, value_enum, default_value_t = FailOn::Error)]
    fail_on: FailOn,
    /// Strip this prefix from file paths in SARIF (make URIs repo-relative)
    #[arg(long)]
    base: Option<String>,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let findings = match lint_paths(&cli.paths) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::from(2);
        }
    };
    let rendered = match cli.format {
        Format::Text => render_text(&findings),
        Format::Json => serde_json::to_string_pretty(&findings).unwrap(),
        Format::Sarif => serde_json::to_string_pretty(&sarif::to_sarif(&findings, cli.base.as_deref())).unwrap(),
    };
    match &cli.output {
        Some(p) => {
            if let Err(e) = std::fs::write(p, rendered) {
                eprintln!("error: writing {}: {e}", p.display());
                return ExitCode::from(2);
            }
        }
        None => print!("{rendered}"),
    }
    let threshold = match cli.fail_on {
        FailOn::Error => Some(Level::Error),
        FailOn::Warning => Some(Level::Warning),
        FailOn::Note => Some(Level::Note),
        FailOn::Never => None,
    };
    match threshold {
        Some(t) if findings.iter().any(|f| f.level >= t) => ExitCode::from(1),
        _ => ExitCode::SUCCESS,
    }
}
