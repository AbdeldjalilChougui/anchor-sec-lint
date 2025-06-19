//! Checks that only need the IDL (Anchor 0.30+ format): useful when you have
//! a deployed program's IDL but not its source.
use crate::rules::{rule, Finding, Level};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

const ROLE_NAMES: &[&str] = &["authority", "admin", "owner", "creator", "maker", "manager", "operator"];

fn is_role(name: &str) -> bool {
    ROLE_NAMES.contains(&name) || name.ends_with("_authority") || name.ends_with("Authority")
}

/// Flattens nested account groups (`accounts: [{name, accounts: [...]}]`).
fn flatten<'a>(accs: &'a [Value], out: &mut Vec<&'a Value>) {
    for a in accs {
        if let Some(inner) = a.get("accounts").and_then(|x| x.as_array()) {
            flatten(inner, out);
        } else {
            out.push(a);
        }
    }
}

pub fn lint_idl(path: &Path, text: &str) -> Result<Vec<Finding>> {
    let idl: Value = serde_json::from_str(text).with_context(|| format!("parsing IDL {}", path.display()))?;
    let Some(ixs) = idl.get("instructions").and_then(|x| x.as_array()) else {
        return Ok(vec![]); // not an IDL
    };
    let file = path.display().to_string();
    let line_of = |needle: &str| -> usize {
        text.lines().position(|l| l.contains(needle)).map(|i| i + 1).unwrap_or(1)
    };
    let mut out = vec![];
    for ix in ixs {
        let ix_name = ix.get("name").and_then(|x| x.as_str()).unwrap_or("?");
        let mut accs = vec![];
        flatten(ix.get("accounts").and_then(|x| x.as_array()).map(|v| v.as_slice()).unwrap_or(&[]), &mut accs);
        let flag = |a: &Value, k: &str| a.get(k).and_then(|x| x.as_bool()).unwrap_or(false);
        let any_signer = accs.iter().any(|a| flag(a, "signer"));
        let any_writable_pda_or_data = accs.iter().any(|a| flag(a, "writable") && a.get("address").is_none());
        let ix_line = line_of(&format!("\"name\": \"{ix_name}\""));
        for a in &accs {
            let name = a.get("name").and_then(|x| x.as_str()).unwrap_or("");
            if is_role(name) && !flag(a, "signer") && a.get("address").is_none() && a.get("pda").is_none() {
                out.push(Finding {
                    rule_id: "ASL001",
                    level: rule("ASL001").level,
                    message: format!("instruction `{ix_name}`: account `{name}` looks like an authority but is not a signer"),
                    file: file.clone(),
                    line: ix_line,
                    column: 1,
                });
            }
        }
        if !any_signer && any_writable_pda_or_data {
            out.push(Finding {
                rule_id: "ASL001",
                level: Level::Warning,
                message: format!("instruction `{ix_name}` writes accounts but requires no signer"),
                file: file.clone(),
                line: ix_line,
                column: 1,
            });
        }
    }
    Ok(out)
}
