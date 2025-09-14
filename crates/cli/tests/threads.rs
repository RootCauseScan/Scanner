use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn zero_threads_argument_errors() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let test_file = tmp.path().join("test.py");
    fs::write(&test_file, "print('hi')")?;
    let rules_dir = tmp.path().join("rules");
    fs::create_dir(&rules_dir)?;

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--threads")
        .arg("0")
        .assert()
        .failure()
        .stderr(predicates::str::contains("threads must be greater than 0"));
    Ok(())
}
