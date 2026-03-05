use assert_cmd::prelude::*;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn default_rules_directory_missing_non_interactive_fails_fast(
) -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let cfg_dir = home.path().join(".config/rootcause");
    fs::create_dir_all(&cfg_dir)?;

    let target = repo_root().join("examples/fixtures/python/py.insecure-tempfile/bad.py");
    let mut cmd = Command::cargo_bin("rootcause")?;
    cmd.env("HOME", home.path()).current_dir(repo_root()).args([
        "scan",
        target.to_str().unwrap(),
        "--format",
        "text",
    ]);

    cmd.assert()
        .failure()
        .stderr(contains("non-interactive mode").and(contains("--download-rules")));
    Ok(())
}

#[test]
fn missing_rules_directory_with_explicit_download_flag_attempts_download(
) -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let cfg_dir = home.path().join(".config/rootcause");
    fs::create_dir_all(&cfg_dir)?;

    let target = repo_root().join("examples/fixtures/python/py.insecure-tempfile/bad.py");
    let mut cmd = Command::cargo_bin("rootcause")?;
    cmd.env("HOME", home.path())
        .env("PATH", "")
        .current_dir(repo_root())
        .args([
            "scan",
            target.to_str().unwrap(),
            "--format",
            "text",
            "--download-rules",
        ]);

    cmd.assert()
        .failure()
        .stderr(contains("failed to clone rules repository"));
    Ok(())
}

#[test]
fn rules_present_does_not_prompt_for_download() -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let cfg_dir = home.path().join(".config/rootcause");
    fs::create_dir_all(&cfg_dir)?;

    let target = repo_root().join("examples/fixtures/python/py.insecure-tempfile/bad.py");
    let rules_dir = repo_root().join("examples/rules/python");

    let mut cmd = Command::cargo_bin("rootcause")?;
    cmd.env("HOME", home.path()).current_dir(repo_root()).args([
        "scan",
        target.to_str().unwrap(),
        "--rules",
        rules_dir.to_str().unwrap(),
        "--format",
        "text",
    ]);

    cmd.assert()
        .success()
        .stdout(predicates::str::contains("Do you want to download").not());
    Ok(())
}
