use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
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

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--fail-on")
        .arg("low")
        .assert()
        .failure();

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--fail-on")
        .arg("high")
        .assert()
        .success();

    Ok(())
}
