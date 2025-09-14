use assert_cmd::prelude::*;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
}

fn run_rule_stream(
    rule_id: &str,
    lang: &str,
    good_rel: &str,
    bad_rel: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let rules_dir = root.join("rules").join(lang);
    let base = root.join("fixtures").join(lang).join(rule_id);
    let good = base.join(good_rel);
    let bad = base.join(bad_rel);

    let output = Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&good)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--stream")
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(rule_id));

    let output = Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&bad)
        .arg("--rules")
        .arg(&rules_dir)
        .arg("--stream")
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(rule_id));
    Ok(())
}

#[test]
fn docker_no_latest_tag_stream() -> Result<(), Box<dyn std::error::Error>> {
    run_rule_stream(
        "docker.no-latest-tag",
        "docker",
        "good/Dockerfile",
        "bad/Dockerfile",
    )
}
