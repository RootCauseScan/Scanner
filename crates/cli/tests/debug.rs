use assert_cmd::prelude::*;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn prints_debug_messages_when_flag_set() -> Result<(), Box<dyn std::error::Error>> {
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
"#,
    )?;

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--debug")
        .assert()
        .success()
        .stderr(
            contains("Debug mode enabled")
                .and(contains("Scanning path"))
                .and(contains("Rules loaded"))
                .and(contains("Files queued")),
        );
    Ok(())
}

#[test]
fn debug_flag_shows_logs_on_failure() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let rules_dir = tmp.path().join("rules");
    fs::create_dir(&rules_dir)?;
    // Intentionally invalid YAML to trigger parse error
    fs::write(rules_dir.join("rule.yaml"), "not: [valid")?;

    let test_file = tmp.path().join("test.py");
    fs::write(&test_file, "print('hi')")?;

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--debug")
        .assert()
        .failure()
        .stderr(
            contains("Debug mode enabled")
                .and(contains("Failed to parse rule file"))
                .and(contains("rule.yaml")),
        );
    Ok(())
}
