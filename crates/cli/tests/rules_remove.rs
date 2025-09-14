use assert_cmd::prelude::*;
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn remove_ruleset_deletes_dir_and_config() -> Result<(), Box<dyn std::error::Error>> {
    let home = TempDir::new()?;
    let name = "demo";
    let cfg_dir = home.path().join(".config/rootcause");
    let ruleset_dir = cfg_dir.join("rules").join(name);
    fs::create_dir_all(&ruleset_dir)?;
    fs::write(ruleset_dir.join("dummy.yaml"), "rules = []")?;
    fs::create_dir_all(&cfg_dir)?;
    fs::write(
        cfg_dir.join("config.toml"),
        format!("[rules]\nrule_dirs=[\"{}\"]\n", ruleset_dir.display()),
    )?;

    Command::cargo_bin("rootcause")?
        .env("HOME", home.path())
        .args(["rules", "remove", name])
        .assert()
        .success();

    assert!(!ruleset_dir.exists());
    let cfg = fs::read_to_string(cfg_dir.join("config.toml"))?;
    assert!(!cfg.contains(name));
    Ok(())
}
