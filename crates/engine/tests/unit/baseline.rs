use super::canonical::TEST_MUTEX;
use super::mk_file_ir;
use super::*;
use loader::Severity;
use serde_json::json;
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn write_and_load_preserve_metadata() -> anyhow::Result<()> {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = std::env::temp_dir().join(format!("baseline_{ts}"));
    std::fs::create_dir(&dir)?;
    let baseline_path = dir.join("baseline.json");
    let rel_file = dir.join("f.yaml");
    std::fs::write(&rel_file, "spec: {}\n")?;
    let finding = Finding {
        id: "id1".into(),
        rule_id: "rule".into(),
        rule_file: Some("test.yaml".into()),
        severity: Severity::Low,
        file: PathBuf::from("f.yaml"),
        line: 1,
        column: 1,
        excerpt: String::new(),
        message: String::new(),
        remediation: None,
        fix: None,
    };
    let orig_dir = std::env::current_dir()?;
    std::env::set_current_dir(&dir)?;
    write_baseline(&baseline_path, &[finding.clone()])?;
    let set = load_baseline(&baseline_path)?;
    let data = std::fs::read_to_string(&baseline_path)?;
    let entries: Vec<BaselineEntry> = serde_json::from_str(&data)?;

    // Verify that the baseline contains the expected finding
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id, "id1");
    assert_eq!(entries[0].line, 1);

    // On Windows, paths may differ, so only basic content is checked
    if cfg!(windows) {
        // On Windows, verify that the baseline was written and loaded correctly
        // without checking an exact path match
        assert_eq!(set.len(), 1);
        let entry = set.iter().next().unwrap();
        assert_eq!(entry.id, "id1");
        assert_eq!(entry.line, 1);
    } else {
        let canonical = std::fs::canonicalize("f.yaml")?
            .to_string_lossy()
            .into_owned();
        let entry_file = &entries[0].file;
        let canonical_file = std::path::Path::new(&canonical);
        assert_eq!(entry_file.file_name(), canonical_file.file_name());
        assert!(entry_file.exists());
        assert!(canonical_file.exists());
        assert!(set.contains(&BaselineEntry::from(&finding)));
    }

    std::env::set_current_dir(orig_dir)?;
    std::fs::remove_dir_all(&dir).ok();
    Ok(())
}

#[test]
fn baseline_filters_by_file_and_line() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_canonical_cache();

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
    let findings = analyze_files(&[file.clone()], &rules, None);
    assert_eq!(findings.len(), 1);
    let entry = BaselineEntry::from(&findings[0]);
    let mut set = HashSet::new();
    set.insert(entry.clone());
    let cfg = EngineConfig {
        file_timeout: None,
        rule_timeout: None,
        baseline: Some(set),
        suppress_comment: None,
    };
    let res = analyze_files_with_config(&[file.clone()], &rules, &cfg, None, None);
    assert!(res.is_empty());
    let mut entry2 = entry.clone();
    entry2.line += 1;
    let mut set2 = HashSet::new();
    set2.insert(entry2);
    let cfg2 = EngineConfig {
        file_timeout: None,
        rule_timeout: None,
        baseline: Some(set2),
        suppress_comment: None,
    };
    let res2 = analyze_files_with_config(&[file], &rules, &cfg2, None, None);
    assert_eq!(res2.len(), 1);
}
