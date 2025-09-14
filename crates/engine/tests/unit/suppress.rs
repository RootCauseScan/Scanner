use super::*;
use loader::Severity;
use regex::Regex;
use std::fs;
use tempfile::Builder;

#[test]
fn analysis_uses_in_memory_source() {
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "todo".into(),
        severity: Severity::Low,
        category: "text".into(),
        message: "todo".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("TODO").unwrap(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
    });
    let file = Builder::new().suffix(".rs").tempfile().unwrap();
    fs::write(file.path(), "// TODO\n").unwrap();
    let fir = parsers::parse_file(file.path(), None, None)
        .unwrap()
        .unwrap();
    fs::remove_file(file.path()).unwrap();
    let findings = analyze_file(&fir, &rules);
    assert_eq!(findings.len(), 1);
}

#[test]
fn suppression_lines_are_respected() {
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "todo".into(),
        severity: Severity::Low,
        category: "text".into(),
        message: "todo".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("TODO").unwrap(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
    });
    let file = Builder::new().suffix(".rs").tempfile().unwrap();
    fs::write(file.path(), "// TODO\n// TODO #skip\n").unwrap();
    let fir = parsers::parse_file(file.path(), Some("#skip"), None)
        .unwrap()
        .unwrap();
    fs::remove_file(file.path()).unwrap();
    let cfg = EngineConfig {
        suppress_comment: Some("#skip".into()),
        ..Default::default()
    };
    let findings = analyze_files_with_config(&[fir], &rules, &cfg, None, None);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 1);
}
