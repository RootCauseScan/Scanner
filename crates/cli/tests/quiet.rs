use assert_cmd::prelude::*;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn info_logs_printed_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let test_file = tmp.path().join("test.py");
    fs::write(&test_file, "print('hi')")?;
    let rules_dir = tmp.path().join("rules");
    fs::create_dir(&rules_dir)?;
    fs::write(
        rules_dir.join("rule.yaml"),
        r#"rules:
  - id: test.rule
    pattern: print(...)
    message: \"Use of print\"
    languages: [python]
"#,
    )?;

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .assert()
        .success()
        .stderr(
            contains("Scan started")
                .and(contains("Rules loaded"))
                .and(contains("Files queued"))
                .and(contains("Scan completed")),
        );
    Ok(())
}

#[test]
fn quiet_flag_hides_info_but_shows_errors() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    let rules_dir = tmp.path().join("rules");
    fs::create_dir(&rules_dir)?;
    fs::write(rules_dir.join("rule.yaml"), "not: [valid")?;
    let test_file = tmp.path().join("test.py");
    fs::write(&test_file, "print('hi')")?;

    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&test_file)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--quiet")
        .assert()
        .failure()
        .stderr(
            contains("did not find expected")
                .and(contains("Scan started").not())
                .and(contains("Rules loaded").not()),
        );
    Ok(())
}
