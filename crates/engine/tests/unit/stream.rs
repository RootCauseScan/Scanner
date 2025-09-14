use super::mk_file_ir;
use super::*;
use loader::Severity;
use serde_json::json;

// Verifica que el modo streaming produce los mismos hallazgos que el modo por lotes.
#[test]
fn stream_matches_batch() {
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
    let batch = analyze_files(&[file.clone()], &rules, None);
    let stream = analyze_files_streaming(vec![file], &rules, &EngineConfig::default(), None, None);
    assert_eq!(batch.len(), stream.len());
    assert_eq!(batch[0].rule_id, stream[0].rule_id);
}

// El modo streaming maneja correctamente entradas que no coinciden con reglas.
#[test]
fn stream_no_findings_on_non_matching_input() {
    let file = mk_file_ir(vec![(
        "k8s",
        "spec.template.spec.securityContext.runAsNonRoot",
        json!(true),
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
    let findings =
        analyze_files_streaming(vec![file], &rules, &EngineConfig::default(), None, None);
    assert!(findings.is_empty());
}

// Procesar cientos de archivos no aumenta significativamente la memoria.
#[test]
fn stream_memory_stable() {
    use std::fs::File;
    use std::io::Read;

    #[allow(unsafe_code)]
    fn current_rss() -> usize {
        let mut s = String::new();
        File::open("/proc/self/statm")
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        let rss_pages: usize = s.split_whitespace().nth(1).unwrap().parse().unwrap();
        let page_size = unsafe {
            // SAFETY: `_SC_PAGESIZE` yields the system page size and requires no
            // additional invariants, so calling `sysconf` here is sound.
            libc::sysconf(libc::_SC_PAGESIZE) as usize
        };
        rss_pages * page_size
    }

    let rules = RuleSet::default();
    let start_mem = current_rss();
    let files = (0..500).map(|_| mk_file_ir(vec![]));
    let findings = analyze_files_streaming(files, &rules, &EngineConfig::default(), None, None);
    assert!(findings.is_empty());
    let end_mem = current_rss();
    let diff = end_mem.saturating_sub(start_mem);
    assert!(diff < 10 * 1024 * 1024, "memory grew by {diff} bytes");
}
