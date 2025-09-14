use super::mk_file_ir;
use super::*;
use loader::Severity;
use serde_json::json;

// Basic deduplication: the same file appears twice and should generate a single finding.
#[test]
fn deduplicates_duplicate_findings() {
    let file = mk_file_ir(vec![(
        "k8s",
        "spec.template.spec.securityContext.runAsNonRoot",
        json!(false),
    )]);
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "k8s.non-root".into(),
        severity: Severity::High,
        category: "k8s".into(),
        message: "non root".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::JsonPathEq(
            "spec.template.spec.securityContext.runAsNonRoot".into(),
            json!(false),
        ),
        source_file: None,
        sources: vec![],
        sinks: vec![],
    });
    let findings = analyze_files(&[file.clone(), file], &rules, None);
    assert_eq!(findings.len(), 1);
}

// Verifica que hallazgos con IDs distintos no se mezclen.
#[test]
fn retains_unique_findings() {
    use ir::{IRNode, Meta};
    let mut f1 = FileIR::new("/tmp/f1".into(), "k8s".into());
    f1.push(IRNode {
        id: 0,
        kind: "k8s".into(),
        path: "spec.template.spec.securityContext.runAsNonRoot".into(),
        value: json!(false),
        meta: Meta {
            file: "/tmp/f1".into(),
            line: 1,
            column: 1,
        },
    });
    let mut f2 = FileIR::new("/tmp/f2".into(), "k8s".into());
    f2.push(IRNode {
        id: 0,
        kind: "k8s".into(),
        path: "spec.template.spec.securityContext.runAsNonRoot".into(),
        value: json!(false),
        meta: Meta {
            file: "/tmp/f2".into(),
            line: 1,
            column: 1,
        },
    });
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "k8s.non-root".into(),
        severity: Severity::High,
        category: "k8s".into(),
        message: "non root".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::JsonPathEq(
            "spec.template.spec.securityContext.runAsNonRoot".into(),
            json!(false),
        ),
        source_file: None,
        sources: vec![],
        sinks: vec![],
    });
    let findings = analyze_files(&[f1, f2], &rules, None);
    assert_eq!(findings.len(), 2);
}
