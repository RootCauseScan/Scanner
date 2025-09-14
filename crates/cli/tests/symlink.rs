#![cfg(unix)]

use assert_cmd::prelude::*;
use std::fs;
use std::os::unix::fs as unix_fs;
use std::process::Command;

#[test]
fn install_skips_symlinks() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let plugin_dir = dir.path().join("plugin");
    fs::create_dir(&plugin_dir)?;
    fs::write(plugin_dir.join("plugin.toml"), "name = \"sym-plugin\"")?;
    let target = dir.path().join("target.txt");
    fs::write(&target, "data")?;
    unix_fs::symlink(&target, plugin_dir.join("link"))?;

    Command::cargo_bin("rootcause")?
        .env("HOME", dir.path())
        .arg("plugins")
        .arg("install")
        .arg(&plugin_dir)
        .assert()
        .success();

    let installed = dir
        .path()
        .join(".config")
        .join("rootcause")
        .join("plugins")
        .join("sym-plugin");
    assert!(installed.join("plugin.toml").exists());
    assert!(!installed.join("link").exists());

    fs::remove_dir_all(installed)?;
    Ok(())
}
