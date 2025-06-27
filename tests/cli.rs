use anchor_sec_lint::{lint_paths, lint_source, sarif::to_sarif};
use assert_cmd::Command;
use std::path::PathBuf;

fn fixture(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(p)
}

fn ids(p: &str) -> Vec<&'static str> {
    lint_paths(&[fixture(p)]).unwrap().into_iter().map(|f| f.rule_id).collect()
}

#[test]
fn vulnerable_fixture_triggers_every_rule() {
    let found = ids("vulnerable");
    for id in ["ASL001", "ASL002", "ASL003", "ASL004", "ASL005", "ASL006"] {
        assert!(found.contains(&id), "{id} not reported; got {found:?}");
    }
}

#[test]
fn fixed_fixture_is_clean() {
    let f = lint_paths(&[fixture("fixed")]).unwrap();
    assert!(f.is_empty(), "unexpected findings: {f:#?}");
}

#[test]
fn findings_point_at_the_right_lines() {
    let f = lint_paths(&[fixture("vulnerable/lib.rs")]).unwrap();
    let src = std::fs::read_to_string(fixture("vulnerable/lib.rs")).unwrap();
    let lines: Vec<&str> = src.lines().collect();
    let line_of = |id: &str| f.iter().find(|x| x.rule_id == id).unwrap().line;
    assert!(lines[line_of("ASL006") - 1].contains("+= amount"));
    assert!(lines[line_of("ASL005") - 1].contains("pub vault"));
    assert!(lines[line_of("ASL002") - 1].contains("pub destination"));
}

#[test]
fn idl_mode_flags_unsigned_authority() {
    let f = lint_paths(&[fixture("idl/vault.json")]).unwrap();
    assert!(f.iter().any(|x| x.rule_id == "ASL001" && x.message.contains("`admin`")), "{f:#?}");
    assert!(f.iter().any(|x| x.message.contains("`set_fee` writes accounts but requires no signer")));
    assert!(!f.iter().any(|x| x.message.contains("deposit")));
}

#[test]
fn inline_suppression() {
    let src = r#"
        #[derive(Accounts)]
        pub struct X<'info> {
            pub s: Signer<'info>,
            // asl:allow ASL002 -- read-only clock-like account, verified elsewhere
            pub raw: AccountInfo<'info>,
        }
    "#;
    assert!(lint_source("x.rs", src).unwrap().is_empty());
    let src2 = src.replace("asl:allow ASL002", "just a comment");
    assert_eq!(lint_source("x.rs", &src2).unwrap().len(), 1);
}

#[test]
fn checked_math_and_tests_are_not_flagged() {
    let src = r#"
        fn f(a: &mut Acc, b: u64) -> Option<u64> { a.x.checked_add(b) }
        const SPACE: usize = 8 + 32;
        #[cfg(test)]
        mod tests { fn t(a: Acc) { let _ = a.x + 1; } }
    "#;
    assert!(lint_source("y.rs", src).unwrap().is_empty());
}

#[test]
fn sarif_shape() {
    let f = lint_paths(&[fixture("vulnerable")]).unwrap();
    let s = to_sarif(&f, Some(env!("CARGO_MANIFEST_DIR")));
    assert_eq!(s["version"], "2.1.0");
    let run = &s["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "anchor-sec-lint");
    assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 6);
    let r0 = &run["results"][0];
    assert!(r0["ruleId"].as_str().unwrap().starts_with("ASL"));
    let uri = r0["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str().unwrap();
    assert!(uri.starts_with("tests/fixtures/"), "{uri}");
    assert!(r0["locations"][0]["physicalLocation"]["region"]["startLine"].as_u64().unwrap() > 0);
}

#[test]
fn cli_exit_codes_and_formats() {
    Command::cargo_bin("anchor-sec-lint").unwrap().arg(fixture("vulnerable")).assert().code(1);
    Command::cargo_bin("anchor-sec-lint").unwrap().arg(fixture("fixed")).assert().code(0);
    let out = Command::cargo_bin("anchor-sec-lint")
        .unwrap()
        .args(["--format", "sarif", "--fail-on", "never"])
        .arg(fixture("vulnerable"))
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["runs"][0]["results"].as_array().unwrap().len() >= 6);
}
