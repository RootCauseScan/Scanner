use assert_cmd::prelude::*;
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

fn examples_root() -> PathBuf {
    repo_root().join("examples")
}

fn run_rule(
    rule_id: &str,
    lang: &str,
    good_rel: &str,
    bad_rel: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = examples_root();
    let rules_dir = root.join("rules").join(lang);
    let base = root.join("fixtures").join(lang).join(rule_id);
    let good = base.join(good_rel);
    let bad = base.join(bad_rel);

    let output = Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&good)
        .arg("--rules")
        .arg(&rules_dir)
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(rule_id));

    let output = Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&bad)
        .arg("--rules")
        .arg(&rules_dir)
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(rule_id));

    Ok(())
}

#[test]
fn docker_no_latest_tag() -> Result<(), Box<dyn std::error::Error>> {
    run_rule(
        "docker.no-latest-tag",
        "docker",
        "good/Dockerfile",
        "bad/Dockerfile",
    )
}

#[test]
fn docker_no_add() -> Result<(), Box<dyn std::error::Error>> {
    run_rule(
        "docker.no-add",
        "docker",
        "good/Dockerfile",
        "bad/Dockerfile",
    )
}

#[test]
fn docker_no_sudo() -> Result<(), Box<dyn std::error::Error>> {
    run_rule(
        "docker.no-sudo",
        "docker",
        "good/Dockerfile",
        "bad/Dockerfile",
    )
}

#[test]
fn yaml_no_plaintext_password() -> Result<(), Box<dyn std::error::Error>> {
    run_rule(
        "yaml.no-plaintext-password",
        "yaml",
        "good.yaml",
        "bad.yaml",
    )
}

#[test]
fn yaml_no_privileged() -> Result<(), Box<dyn std::error::Error>> {
    run_rule("yaml.no-privileged", "yaml", "good.yaml", "bad.yaml")
}

#[test]
fn terraform_no_public_acl() -> Result<(), Box<dyn std::error::Error>> {
    run_rule("tf.no-public-acl", "terraform", "good.tf", "bad.tf")
}

#[test]
fn terraform_no_wide_open_sg() -> Result<(), Box<dyn std::error::Error>> {
    run_rule("tf.no-wide-open-sg", "terraform", "good.tf", "bad.tf")
}

#[test]
fn python_no_eval() -> Result<(), Box<dyn std::error::Error>> {
    run_rule("py.no-eval", "python", "good.py", "bad.py")
}

#[test]
fn typescript_no_eval() -> Result<(), Box<dyn std::error::Error>> {
    run_rule("ts.no-eval", "typescript", "good.ts", "bad.ts")
}

#[test]
fn javascript_no_eval() -> Result<(), Box<dyn std::error::Error>> {
    run_rule("js.no-eval", "javascript", "good.js", "bad.js")
}

#[test]
fn javascript_no_innerhtml() -> Result<(), Box<dyn std::error::Error>> {
    run_rule("js.no-innerhtml", "javascript", "good.js", "bad.js")
}

#[test]
fn python_pickle_loads() -> Result<(), Box<dyn std::error::Error>> {
    run_rule("py.pickle-loads", "python", "good.py", "bad.py")
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
