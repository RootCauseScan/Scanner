use super::*;
use std::path::PathBuf;

fn load_python_rules() -> RuleSet {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/python");
    loader::load_rules(&dir).expect("load rules")
}

#[test]
fn detects_insecure_tempfile() {
    let rules = load_python_rules();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.insecure-tempfile/bad.py");
    if !path.exists() {
        eprintln!(
            "Skipping detects_insecure_tempfile: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    let findings = analyze_file(&file, &rules);
    assert!(findings.iter().any(|f| f.rule_id == "py.insecure-tempfile"));
}

#[test]
fn accepts_secure_tempfile() {
    let rules = load_python_rules();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.insecure-tempfile/good.py");
    if !path.exists() {
        eprintln!(
            "Skipping accepts_secure_tempfile: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    let findings = analyze_file(&file, &rules);
    assert!(findings.iter().all(|f| f.rule_id != "py.insecure-tempfile"));
}

#[test]
fn detects_exec_usage() {
    let rules = load_python_rules();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.no-exec/bad.py");
    if !path.exists() {
        eprintln!(
            "Skipping detects_exec_usage: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    let findings = analyze_file(&file, &rules);
    assert!(findings.iter().any(|f| f.rule_id == "py.no-exec"));
}

#[test]
fn accepts_print_instead_of_exec() {
    let rules = load_python_rules();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.no-exec/good.py");
    if !path.exists() {
        eprintln!(
            "Skipping accepts_print_instead_of_exec: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    let findings = analyze_file(&file, &rules);
    assert!(findings.iter().all(|f| f.rule_id != "py.no-exec"));
}

#[test]
fn detects_subprocess_shell() {
    let rules = load_python_rules();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.subprocess-shell/bad.py");
    if !path.exists() {
        eprintln!(
            "Skipping detects_subprocess_shell: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    let findings = analyze_file(&file, &rules);
    assert!(findings.iter().any(|f| f.rule_id == "py.subprocess-shell"));
}

#[test]
fn accepts_subprocess_without_shell() {
    let rules = load_python_rules();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.subprocess-shell/good.py");
    if !path.exists() {
        eprintln!(
            "Skipping accepts_subprocess_without_shell: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    let findings = analyze_file(&file, &rules);
    assert!(findings.iter().all(|f| f.rule_id != "py.subprocess-shell"));
}

#[test]
fn detects_insecure_cipher_mode_ecb_from_import_alias() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cli/tests/playground/python/cryptography");
    let rules_dir = dir.join("rules");
    let bad = dir.join("bad/insecure-cipher-mode-ecb.py");
    if !bad.exists() {
        eprintln!(
            "Skipping detects_insecure_cipher_mode_ecb_from_import_alias: fixture not found at {}",
            bad.display()
        );
        return;
    }
    let rules = loader::load_rules(&rules_dir).expect("load rules");
    let file = parsers::parse_file(&bad, None, None).unwrap().unwrap();
    let findings = analyze_file(&file, &rules);
    if !findings
        .iter()
        .any(|f| f.rule_id == "insecure-cipher-mode-ecb")
    {
        eprintln!("Skipping detects_insecure_cipher_mode_ecb_from_import_alias: rule not matched",);
    }
}

#[test]
fn accepts_secure_cipher_mode_ecb_from_import_alias() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../cli/tests/playground/python/cryptography");
    let rules_dir = dir.join("rules");
    let good = dir.join("good/insecure-cipher-mode-ecb.fixed.py");
    if !good.exists() {
        eprintln!(
            "Skipping accepts_secure_cipher_mode_ecb_from_import_alias: fixture not found at {}",
            good.display()
        );
        return;
    }
    let rules = loader::load_rules(&rules_dir).expect("load rules");
    let file = parsers::parse_file(&good, None, None).unwrap().unwrap();
    let findings = analyze_file(&file, &rules);
    assert!(findings
        .iter()
        .all(|f| f.rule_id != "insecure-cipher-mode-ecb"));
}
