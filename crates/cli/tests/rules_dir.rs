use assert_cmd::prelude::*;
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
fn default_rules_directory_missing_fails() -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let cfg_dir = home.path().join(".config/rootcause");
    fs::create_dir_all(&cfg_dir)?;
    // Don't create the default rules directory to ensure it's missing
    let target = repo_root().join("examples/fixtures/python/py.insecure-tempfile/bad.py");
    let mut cmd = Command::cargo_bin("rootcause")?;
    cmd.env("HOME", home.path()).current_dir(repo_root()).args([
        "scan",
        target.to_str().unwrap(),
        "--format",
        "text",
    ]);
    cmd.assert().failure();
    Ok(())
}

#[test]
fn missing_rules_directory_fails() {
    let mut cmd = Command::cargo_bin("rootcause").unwrap();
    cmd.current_dir(repo_root());
    cmd.args([
        "scan",
        "examples/fixtures/python/py.insecure-tempfile/bad.py",
        "--rules",
        "non-existent-dir",
        "--format",
        "text",
    ]);
    cmd.assert().failure();
}
