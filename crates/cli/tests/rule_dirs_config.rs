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
fn loads_rules_from_config_dirs() -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let home = TempDir::new()?;
    let extra_rules = home.path().join("extra_rules");
    fs::create_dir_all(&extra_rules)?;
    fs::copy(
        root.join("examples/rules/python/py.insecure-tempfile.yaml"),
        extra_rules.join("py.insecure-tempfile.yaml"),
    )?;
    let base_rules = home.path().join("base_rules");
    fs::create_dir_all(&base_rules)?;
    let cfg_dir = home.path().join(".config/rootcause");
    fs::create_dir_all(&cfg_dir)?;
    // Create the default rules directory to avoid the download prompt
    let default_rules_dir = cfg_dir.join("rules");
    fs::create_dir_all(&default_rules_dir)?;
    fs::write(
        cfg_dir.join("config.toml"),
        format!("[rules]\nrule_dirs = [\"{}\"]\n", extra_rules.display()),
    )?;
    let target = root.join("examples/fixtures/python/py.insecure-tempfile/bad.py");
    let output = Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["scan", target.to_str().unwrap(), "--format", "text"])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("py.insecure-tempfile"));
    Ok(())
}
