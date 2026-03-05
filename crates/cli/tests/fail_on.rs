use rootcause::args::ScanArgs;
use rootcause::output::Format;
use rootcause::scan::run_scan;
use std::fs;
use tempfile::tempdir;

#[test]
fn fail_on_threshold_controls_exit_code() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let test_file = tmp.path().join("test.py");
    fs::write(&test_file, "import os\nos.system(\"echo\")\n")?;

    let rules_dir = tmp.path().join("rules");
    fs::create_dir(&rules_dir)?;
    fs::write(
        rules_dir.join("rule.yaml"),
        r#"rules:
  - id: test.rule
    pattern: os.system(...)
    message: \"Uso de os.system detectado\"
    languages: [python]
    severity: low
"#,
    )?;

    let base_args = ScanArgs {
        path: test_file.clone(),
        rules: rules_dir.clone(),
        download_rules: false,
        rules_provided: true,
        format: Format::Json,
        fail_on: None,
        threads: 1,
        exclude: vec![],
        no_default_exclude: true,
        max_file_size: 5 * 1024 * 1024,
        timeout_operation_ms: None,
        metrics: None,
        baseline: None,
        write_baseline: None,
        plugins: vec![],
        plugin_opts: vec![],
        plugin_config: None,
        suppress_comment: "sast-ignore".to_string(),
        stream: false,
        chunk_size: 100,
        dump_taints: false,
        debug: false,
        quiet: true,
        apply_fixes: false,
        cache_dir: None,
    };

    let mut low_threshold = base_args;
    low_threshold.fail_on = Some(loader::Severity::Low);
    let low_outcome = run_scan(low_threshold)?;
    assert!(low_outcome.should_fail_ci);

    let high_threshold = ScanArgs {
        path: test_file,
        rules: rules_dir,
        download_rules: false,
        rules_provided: true,
        format: Format::Json,
        fail_on: Some(loader::Severity::High),
        threads: 1,
        exclude: vec![],
        no_default_exclude: true,
        max_file_size: 5 * 1024 * 1024,
        timeout_operation_ms: None,
        metrics: None,
        baseline: None,
        write_baseline: None,
        plugins: vec![],
        plugin_opts: vec![],
        plugin_config: None,
        suppress_comment: "sast-ignore".to_string(),
        stream: false,
        chunk_size: 100,
        dump_taints: false,
        debug: false,
        quiet: true,
        apply_fixes: false,
        cache_dir: None,
    };
    let high_outcome = run_scan(high_threshold)?;
    assert!(!high_outcome.should_fail_ci);

    Ok(())
}
