use assert_cmd::prelude::*;
use predicates::str::contains;
use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

#[test]
fn respects_chunk_size_option() -> Result<(), Box<dyn std::error::Error>> {
    let root = repo_root();
    let scan_dir = root.join("examples/fixtures/python/py.no-eval");
    let rules = root.join("examples/rules/python");
    Command::cargo_bin("rootcause")?
        .arg("scan")
        .arg(&scan_dir)
        .arg("--rules")
        .arg(&rules)
        .arg("--chunk-size")
        .arg("1")
        .assert()
        .success()
        .stdout(contains("py.no-eval"));
    Ok(())
}
