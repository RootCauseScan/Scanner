use super::canonical::TEST_MUTEX;
use super::*;
use loader::load_rules;
use parsers::parse_file;
use std::path::PathBuf;

fn load_java_rules() -> RuleSet {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/java");
    load_rules(&dir).expect("load rules")
}

fn run_java_rule(rule_id: &str, good: &str, bad: &str) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../");
    let rules = load_java_rules();
    assert!(rules.rules.iter().any(|r| r.id == rule_id));
    let good_path = root.join("examples/fixtures/java").join(rule_id).join(good);
    let bad_path = root.join("examples/fixtures/java").join(rule_id).join(bad);
    let good_ir = parse_file(&good_path, None, None).unwrap().unwrap();
    let bad_ir = parse_file(&bad_path, None, None).unwrap().unwrap();
    let good_findings = analyze_file(&good_ir, &rules);
    let bad_findings = analyze_file(&bad_ir, &rules);
    assert!(
        !good_findings.iter().any(|f| f.rule_id == rule_id),
        "unexpected finding in good fixture"
    );
    assert!(
        bad_findings.iter().any(|f| f.rule_id == rule_id),
        "missing finding in bad fixture"
    );
}

#[test]
fn java_no_system_exit_rule() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();
    run_java_rule("java.no-system-exit", "good.java", "bad.java");
}

#[test]
fn java_no_runtime_exec_rule() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();
    run_java_rule("java.no-runtime-exec", "good.java", "bad.java");
}
