use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn invalid_rule_severity_errors() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let test_file = tmp.path().join("test.py");
    fs::write(&test_file, "import os\nos.system(\"echo\")\n")?;

    let rules_dir = tmp.path().join("rules");
    fs::create_dir(&rules_dir)?;
    fs::write(
        rules_dir.join("rule.yaml"),
        r#"
rules:
  - id: test.rule
    pattern: os.system(...)
    message: \"test\"
    languages: [python]
    severity: BOGUS
"#,
    )?;

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .assert()
        .failure()
        .stderr(predicates::str::contains("unknown severity"));
    Ok(())
}

#[test]
fn invalid_fail_on_argument_errors() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let dummy = tmp.path().join("dummy");
    fs::write(&dummy, "")?;
    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&dummy)
        .arg("--fail-on")
        .arg("bogus")
        .assert()
        .failure()
        .stderr(predicates::str::contains("unknown severity"));
    Ok(())
}
