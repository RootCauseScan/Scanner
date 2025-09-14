use assert_cmd::prelude::*;
use predicates::str::contains;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn install_rules_tarball() -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let home = TempDir::new()?;
    let docker = root.join("examples/rules/docker");
    let tar = home.path().join("docker.tar.gz");
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&tar)
        .arg("-C")
        .arg(&docker)
        .arg(".")
        .status()?;
    assert!(status.success());
    let url = format!("file://{}", tar.display());
    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["rules", "install", &url])
        .assert()
        .success();
    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["rules", "list"])
        .assert()
        .success()
        .stdout(contains("docker"));
    Ok(())
}
