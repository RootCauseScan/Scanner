use engine::{analyze_files_with_config, AnalysisCache, EngineConfig, EngineMetrics};
use ir::{FileIR, IRNode, Meta};
use loader::{CompiledRule, MatcherKind, RuleSet, Severity};
use serde_json::json;
use tempfile::NamedTempFile;

fn sample_file() -> FileIR {
    let mut fir = FileIR::new("/tmp/f".into(), "k8s".into());
    fir.push(IRNode {
        id: 0,
        kind: "k8s".into(),
        path: "a".into(),
        value: json!("v"),
        meta: Meta {
            file: "/tmp/f".into(),
            line: 1,
            column: 1,
        },
    });
    fir
}

fn sample_rules() -> RuleSet {
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "r".into(),
        severity: Severity::Low,
        category: "k8s".into(),
        message: "m".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::JsonPathEq("a".into(), json!("v")),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["k8s".into()],
    });
    rules
}

#[test]
fn reuses_cached_results() {
    let file = sample_file();
    let rules = sample_rules();
    let cfg = EngineConfig::default();
    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let mut cache = AnalysisCache::load(&path);
    let mut m1 = EngineMetrics::default();
    let first = analyze_files_with_config(
        std::slice::from_ref(&file),
        &rules,
        &cfg,
        Some(&mut cache),
        Some(&mut m1),
    );
    assert_eq!(first.len(), 1);
    assert_eq!(m1.file_times_ms.len(), 1);
    cache.save(&path);

    let mut cache = AnalysisCache::load(&path);
    let mut m2 = EngineMetrics::default();
    let second = analyze_files_with_config(&[file], &rules, &cfg, Some(&mut cache), Some(&mut m2));
    assert_eq!(second.len(), first.len());
    assert!(m2.file_times_ms.is_empty());
}
