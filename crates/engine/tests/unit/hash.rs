use super::*;
use loader::Severity;
use regex::Regex;
use serde_json::json;
use std::fs;
use tempfile::tempdir;

#[test]
fn reuses_cache_and_detects_changes() {
    let tmp = tempdir().unwrap();
    let cache = tmp.path().join("hashes.json");

    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "r1".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: "m".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("foo").unwrap(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
    });

    let file1 = mk_file_ir(vec![("k8s", "a", json!("foo"))]);

    let mut metrics1 = EngineMetrics::default();
    analyze_files_cached(
        &[file1.clone()],
        &rules,
        &cache,
        &EngineConfig::default(),
        Some(&mut metrics1),
    );
    assert_eq!(metrics1.file_times_ms.len(), 1);
    assert_eq!(metrics1.rule_times_ms.len(), 1);

    let mut metrics2 = EngineMetrics::default();
    analyze_files_cached(
        &[file1.clone()],
        &rules,
        &cache,
        &EngineConfig::default(),
        Some(&mut metrics2),
    );
    assert_eq!(metrics2.file_times_ms.len(), 0);
    assert_eq!(metrics2.rule_times_ms.len(), 0);

    let mut modified = file1.clone();
    modified.nodes[0].value = json!("bar");
    let mut metrics3 = EngineMetrics::default();
    analyze_files_cached(
        &[modified],
        &rules,
        &cache,
        &EngineConfig::default(),
        Some(&mut metrics3),
    );
    assert_eq!(metrics3.file_times_ms.len(), 1);
}

#[test]
fn handles_corrupt_cache_file() {
    let tmp = tempdir().unwrap();
    let cache = tmp.path().join("hashes.json");
    fs::write(&cache, "not json").unwrap();

    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "r1".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: "m".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("foo").unwrap(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
    });

    let file1 = mk_file_ir(vec![("k8s", "a", json!("foo"))]);

    let mut metrics = EngineMetrics::default();
    analyze_files_cached(
        &[file1],
        &rules,
        &cache,
        &EngineConfig::default(),
        Some(&mut metrics),
    );
    assert_eq!(metrics.file_times_ms.len(), 1);
}
