use super::*;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

#[test]
fn pattern_regex_rule_matches() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../");
    let rule_path = root.join("examples/rules/pattern-regex.yaml");
    let rules = loader::load_rules(&rule_path).expect("load pattern-regex rule");

    let mut file = FileIR::new("/tmp/token.txt".into(), "txt".into());
    file.source = Some("xoxb-12345678-abcdefghijklmnopqr".into());

    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "examples.pattern-regex");
}

#[test]
fn metavariable_pattern_rule_matches() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../");
    let rule_path = root.join("examples/rules/metavariable-pattern.yaml");
    let rules = loader::load_rules(&rule_path).expect("load metavariable-pattern rule");

    let dir = tempdir().unwrap();
    let path = dir.path().join("input_print.py");
    fs::write(&path, "print(input('name'))\n").unwrap();
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();

    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "examples.metavariable-pattern");
}
