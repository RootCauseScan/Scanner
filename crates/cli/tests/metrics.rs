use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn writes_metrics_file() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let test_file = tmp.path().join("test.py");

    // Create test file with problem
    fs::write(
        &test_file,
        r#"
import os
os.system("echo hello")
"#,
    )?;

    let rules_dir = tmp.path().join("rules");
    fs::create_dir(&rules_dir)?;

    // Create simple rule
    fs::write(
        rules_dir.join("rule.yaml"),
        r#"
rules:
  - id: test.rule
    pattern: os.system(...)
    message: "Uso de os.system detectado"
    languages: [python]
"#,
    )?;

    let metrics = tmp.path().join("metrics.json");

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--metrics")
        .arg(&metrics)
        .assert()
        .success();

    let data = std::fs::read_to_string(&metrics)?;
    let v: Value = serde_json::from_str(&data)?;
    assert!(v.get("findings").is_some());
    Ok(())
}
