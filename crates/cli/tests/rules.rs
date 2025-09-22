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
    // Only check in the Results section, not in debug messages
    let results_section = stdout.split("╭─────────╮").nth(1).unwrap_or("");
    assert!(!results_section.contains(rule_id));

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
