use assert_cmd::prelude::*;
use serde_json::Value;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn cli_outputs_valid_sarif_json() -> Result<(), Box<dyn std::error::Error>> {
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

    let output = Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--format")
        .arg("sarif")
        .output()?;

    if !output.status.success() {
        eprintln!(
            "Command failed with stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    }

    assert!(output.status.success());

    let v: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(v["version"], "2.1.0");
    assert!(v["runs"].is_array());

    // Ensure there are results (may be empty if no issues are found)
    let runs = v["runs"].as_array().unwrap();
    if !runs.is_empty() {
        let results = &runs[0]["results"];
        assert!(results.is_array());
    }

    Ok(())
}
