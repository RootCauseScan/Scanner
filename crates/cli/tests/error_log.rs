use assert_cmd::prelude::*;
use predicates::str::contains;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn writes_error_log_under_config_directory() -> Result<(), Box<dyn std::error::Error>> {
    let home = tempdir()?;
    let workdir = tempdir()?;

    let rules_dir = workdir.path().join("rules");
    fs::create_dir_all(&rules_dir)?;
    fs::write(rules_dir.join("rule.yaml"), "not: [valid")?;

    let target_file = workdir.path().join("test.py");
    fs::write(&target_file, "print('hi')")?;

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .current_dir(workdir.path())
        .args([
            "scan",
            target_file.to_str().unwrap(),
            "--rules",
            rules_dir.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("Failed to parse rule file"));

    let config_log = home
        .path()
        .join(".config")
        .join("rootcause")
        .join("rootcause.error.log");
    assert!(
        config_log.exists(),
        "expected log at {}",
        config_log.display()
    );

    let log_contents = fs::read_to_string(config_log)?;
    assert!(log_contents.contains("kind=error"));
    assert!(log_contents.contains("Failed to parse rule file"));

    assert!(
        !workdir.path().join("rootcause.error.log").exists(),
        "legacy log should not be written in current directory"
    );

    Ok(())
}
