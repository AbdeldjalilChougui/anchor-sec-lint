//! SARIF 2.1.0 output (GitHub code scanning, VS Code SARIF viewer, ...).
use crate::rules::{Finding, RULES};
use serde_json::{json, Value};

pub fn to_sarif(findings: &[Finding], base: Option<&str>) -> Value {
    let rules: Vec<Value> = RULES
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": { "text": r.short },
                "help": { "text": r.help },
                "defaultConfiguration": { "level": r.level.as_str() },
            })
        })
        .collect();
    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let uri = match base {
                Some(b) => f.file.strip_prefix(b).unwrap_or(&f.file).trim_start_matches('/').to_string(),
                None => f.file.clone(),
            };
            json!({
                "ruleId": f.rule_id,
                "ruleIndex": RULES.iter().position(|r| r.id == f.rule_id).unwrap_or(0),
                "level": f.level.as_str(),
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": uri },
                        "region": { "startLine": f.line.max(1), "startColumn": f.column.max(1) }
                    }
                }]
            })
        })
        .collect();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "anchor-sec-lint",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://github.com/abdeldjalil-chougui/anchor-sec-lint",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}
