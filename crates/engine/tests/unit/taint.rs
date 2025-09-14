use super::canonical::TEST_MUTEX;
use super::*;
use regex::Regex;
use std::path::PathBuf;

fn parse(path: &str) -> FileIR {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    if !path.exists() {
        eprintln!("Skipping test, fixture not found at {}", path.display());
        return FileIR::new("missing".into(), "python".into());
    }
    parsers::parse_file(&path, None, None).unwrap().unwrap()
}

fn mk_rule() -> RuleSet {
    let source = loader::TaintPattern {
        allow: vec![Regex::new(r"(?m)(\w+)\s*=\s*source\(\)").unwrap()],
        focus: Some("$VAR".into()),
        ..Default::default()
    };

    let sanitizer = loader::TaintPattern {
        allow: vec![Regex::new(r"(?m)sanitize\((\w+)\)").unwrap()],
        focus: Some("$VAR".into()),
        ..Default::default()
    };

    let reclass = loader::TaintPattern {
        allow: vec![Regex::new(r"(?m)clean\((\w+)\)").unwrap()],
        ..Default::default()
    };

    let sink = loader::TaintPattern {
        allow: vec![Regex::new(r"(?m)sink\((\w+)\)").unwrap()],
        ..Default::default()
    };
    let rule = CompiledRule {
        id: "taint.test".into(),
        severity: Severity::Medium,
        category: "semgrep".into(),
        message: "taint".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TaintRule {
            sources: vec![source],
            sanitizers: vec![sanitizer],
            reclass: vec![reclass],
            sinks: vec![sink],
        },
        source_file: None,
        sources: vec![],
        sinks: vec![],
    };
    RuleSet { rules: vec![rule] }
}

#[test]
fn detects_taint_flow() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();
    let file = parse("../../examples/fixtures/python/taint/bad.py");
    let rules = mk_rule();
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 2);
}

#[test]
fn ignores_sanitized_flow() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();
    let file = parse("../../examples/fixtures/python/taint/good.py");
    let rules = mk_rule();
    let findings = analyze_file(&file, &rules);
    assert!(findings.is_empty());
}

#[test]
fn reclassifies_flow() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();
    let file = parse("../../examples/fixtures/python/taint/reclass.py");
    let rules = mk_rule();
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 0);
}
