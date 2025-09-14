use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn create_invalid_yaml(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let test_file = dir.path().join("bad.yaml");
    fs::write(&test_file, "foo:\n  <<: *MISSING\n").expect("write invalid file");
    test_file
}

fn setup_rules(dir: &tempfile::TempDir) -> std::path::PathBuf {
    let rules_dir = dir.path().join("rules");
    fs::create_dir(&rules_dir).expect("create rules dir");
    rules_dir
}

#[test]
fn reports_failed_files_on_parse_error() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let test_file = create_invalid_yaml(&tmp);
    let rules_dir = setup_rules(&tmp);

    let assert = Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone())?;
    let failed_line = output
        .lines()
        .find(|l| l.contains("Failed files"))
        .expect("failed files line");
    let count = failed_line.split_whitespace().last().unwrap();
    assert_eq!(count, "1");
    Ok(())
}

#[test]
fn reports_failed_files_on_parse_error_streaming() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let test_file = create_invalid_yaml(&tmp);
    let rules_dir = setup_rules(&tmp);

    let assert = Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--stream")
        .assert()
        .success();
    let output = String::from_utf8(assert.get_output().stdout.clone())?;
    let failed_line = output
        .lines()
        .find(|l| l.contains("Failed files"))
        .expect("failed files line");
    let count = failed_line.split_whitespace().last().unwrap();
    assert_eq!(count, "1");
    Ok(())
}
