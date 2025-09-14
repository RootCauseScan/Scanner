use assert_cmd::prelude::*;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
}

fn run_cli(path: &PathBuf, rules: &PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(path)
        .arg("--rules")
        .arg(rules)
        .output()?;

    if !output.status.success() {
        eprintln!("Command failed with status: {:?}", output.status);
        eprintln!("Stderr: {}", String::from_utf8_lossy(&output.stderr));
        eprintln!("Stdout: {}", String::from_utf8_lossy(&output.stdout));
        return Err(format!("Command failed with status: {:?}", output.status).into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[test]
fn docker_configs() -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let rules = root.join("rules").join("docker");
    let good = root
        .join("fixtures")
        .join("docker")
        .join("good")
        .join("Dockerfile");
    let bad = root
        .join("fixtures")
        .join("docker")
        .join("bad")
        .join("Dockerfile");

    let stdout = run_cli(&good, &rules)?;
    assert!(!stdout.contains("docker.no-add"));

    let stdout = run_cli(&bad, &rules)?;
    assert!(stdout.contains("docker.no-add"));
    Ok(())
}

#[test]
fn k8s_configs() -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let rules_root = root.join("rules");
    let rules_dir = if rules_root.join("k8s").exists() {
        rules_root.join("k8s")
    } else {
        rules_root.join("config")
    };
    let good = root
        .join("fixtures")
        .join("k8s")
        .join("good")
        .join("config.yaml");
    let bad = root
        .join("fixtures")
        .join("k8s")
        .join("bad")
        .join("config.yaml");

    let stdout = run_cli(&good, &rules_dir)?;
    assert!(!stdout.contains("config.no_default_password"));

    let stdout = run_cli(&bad, &rules_dir)?;
    assert!(stdout.contains("config.no_default_password"));
    Ok(())
}
