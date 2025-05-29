//! anchor-sec-lint: heuristic security checks for Anchor programs.
//!
//! Input: Rust sources (files or directories) and/or Anchor IDL JSON files.
//! Output: text, JSON, or SARIF 2.1.0.
pub mod idl;
pub mod model;
pub mod rules;
pub mod sarif;

use anyhow::{Context, Result};
use rules::Finding;
use std::path::{Path, PathBuf};

/// Expand paths into `.rs` and `.json` files (skipping target/ and node_modules/).
pub fn collect_inputs(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = vec![];
    for p in paths {
        if p.is_file() {
            out.push(p.clone());
            continue;
        }
        for e in walkdir::WalkDir::new(p)
            .into_iter()
            .filter_entry(|e| {
                let n = e.file_name().to_string_lossy();
                !(e.file_type().is_dir() && (n == "target" || n == "node_modules" || n.starts_with('.') && n.len() > 1))
            })
            .filter_map(|e| e.ok())
        {
            if e.file_type().is_file() && e.path().extension().is_some_and(|x| x == "rs") {
                out.push(e.into_path());
            }
        }
    }
    out.sort();
    out
}

/// `// asl:allow ASL006` on the finding's line or the line above silences it.
fn suppressed(src: &str, f: &Finding) -> bool {
    let lines: Vec<&str> = src.lines().collect();
    let check = |i: usize| {
        lines
            .get(i)
            .map(|l| l.contains("asl:allow") && (l.contains(f.rule_id) || l.contains("asl:allow all")))
            .unwrap_or(false)
    };
    f.line >= 1 && (check(f.line - 1) || (f.line >= 2 && check(f.line - 2)))
}

pub fn lint_paths(paths: &[PathBuf]) -> Result<Vec<Finding>> {
    let files = collect_inputs(paths);
    let mut sources = vec![];
    let mut findings = vec![];
    for path in &files {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if path.extension().is_some_and(|x| x == "json") {
            findings.extend(idl::lint_idl(path, &text)?);
            continue;
        }
        match model::parse_file(path, &text) {
            Ok(f) => sources.push((f, text)),
            Err(e) => eprintln!("warning: skipping {}: {e}", path.display()),
        }
    }
    let parsed: Vec<_> = sources.iter().map(|(f, _)| f.clone()).collect();
    for (f, text) in &sources {
        findings.extend(rules::lint_file(f, &parsed).into_iter().filter(|x| !suppressed(text, x)));
    }
    findings.sort_by(|a, b| (&a.file, a.line, a.column, a.rule_id).cmp(&(&b.file, b.line, b.column, b.rule_id)));
    findings.dedup_by(|a, b| a.file == b.file && a.line == b.line && a.rule_id == b.rule_id && a.message == b.message);
    Ok(findings)
}

pub fn lint_source(name: &str, src: &str) -> Result<Vec<Finding>> {
    let f = model::parse_file(Path::new(name), src)?;
    let all = vec![f.clone()];
    Ok(rules::lint_file(&f, &all).into_iter().filter(|x| !suppressed(src, x)).collect())
}

pub fn render_text(findings: &[Finding]) -> String {
    let mut s = String::new();
    for f in findings {
        let r = rules::rule(f.rule_id);
        s.push_str(&format!(
            "{}:{}:{}: {} [{} {}] {}\n",
            f.file, f.line, f.column, f.level.as_str(), f.rule_id, r.name, f.message
        ));
    }
    let n = |l| findings.iter().filter(|f| f.level == l).count();
    s.push_str(&format!(
        "\n{} finding(s): {} error, {} warning, {} note\n",
        findings.len(),
        n(rules::Level::Error),
        n(rules::Level::Warning),
        n(rules::Level::Note)
    ));
    s
}
