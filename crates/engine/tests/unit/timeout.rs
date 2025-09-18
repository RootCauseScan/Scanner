use super::canonical::TEST_MUTEX;
use super::*;
use regex::Regex;
use std::time::{Duration, Instant};

#[test]
fn slow_rule_respects_timeout() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();

    let mut file = FileIR::new("/tmp/slow".into(), "txt".into());
    file.source = Some("content".into());

    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "slow.rule".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: "slow".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("content").unwrap().into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["txt".into()],
    });

    let cfg = EngineConfig {
        file_timeout: None,
        rule_timeout: Some(Duration::from_millis(10)),
        baseline: None,
        suppress_comment: None,
    };

    let start = Instant::now();
    let findings = analyze_file_with_config(&file, &rules, &cfg, None);
    let elapsed = start.elapsed();

    assert!(findings.is_empty());
    assert!(elapsed < Duration::from_millis(80));
}

#[test]
fn slow_rule_does_not_block_fast_rule() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();

    let mut file = FileIR::new("/tmp/mixed".into(), "txt".into());
    file.source = Some("fast\ncontent".into());

    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "slow.rule".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: "slow".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("content").unwrap().into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["txt".into()],
    });
    rules.rules.push(CompiledRule {
        id: "fast.rule".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: "fast".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("fast").unwrap().into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["txt".into()],
    });

    let cfg = EngineConfig {
        file_timeout: None,
        rule_timeout: Some(Duration::from_millis(10)),
        baseline: None,
        suppress_comment: None,
    };

    let start = Instant::now();
    let findings = analyze_file_with_config(&file, &rules, &cfg, None);
    let elapsed = start.elapsed();

    assert!(findings.iter().any(|f| f.rule_id == "fast.rule"));
    assert!(findings.iter().all(|f| f.rule_id != "slow.rule"));
    assert!(elapsed < Duration::from_millis(80));
}

#[test]
fn analyzes_without_rule_timeout() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();

    let mut file = FileIR::new("/tmp/no-timeout".into(), "txt".into());
    file.source = Some("content".into());

    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "fast.rule".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: "fast".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("content").unwrap().into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["txt".into()],
    });

    let cfg = EngineConfig {
        file_timeout: None,
        rule_timeout: None,
        baseline: None,
        suppress_comment: None,
    };

    let findings = analyze_file_with_config(&file, &rules, &cfg, None);
    assert!(findings.iter().any(|f| f.rule_id == "fast.rule"));
}
