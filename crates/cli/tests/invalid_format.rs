use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn invalid_format_argument_errors() -> Result<(), Box<dyn std::error::Error>> {
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
        .arg("--format")
        .arg("bogus")
        .assert()
        .failure();
    Ok(())
}
use rootcause::output::Format;
use std::str::FromStr;

#[test]
fn format_from_str_is_case_insensitive() {
    assert_eq!(Format::from_str("JSON").unwrap(), Format::Json);
}
