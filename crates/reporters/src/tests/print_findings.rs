use crate::{write_findings, Format};
use engine::Finding;
use loader::Severity;
use std::path::PathBuf;

fn sample_findings() -> Vec<Finding> {
    let id = blake3::hash(b"rule:src/main.rs:10:5").to_hex().to_string();
    vec![Finding {
        id,
        rule_id: "rule".into(),
        rule_file: Some("test.yaml".into()),
        severity: Severity::High,
        file: PathBuf::from("src/main.rs"),
        line: 10,
        column: 5,
        excerpt: "let x = 1".into(),
        message: "dummy".into(),
        remediation: None,
        fix: None,
    }]
}

#[test]
fn json_matches_golden() {
    let findings = sample_findings();
    let mut buf = Vec::new();
    write_findings(&mut buf, &findings, Format::Json, None).unwrap();
    let rendered = String::from_utf8(buf).unwrap();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/json/print_findings.json");
    let expected = std::fs::read_to_string(path).unwrap();
    // Normalize line endings for cross-platform compatibility
    let rendered_normalized = rendered.replace("\r\n", "\n");
    let expected_normalized = expected.replace("\r\n", "\n");
    assert_eq!(rendered_normalized, expected_normalized);
}

#[test]
fn json_differs_with_wrong_data() {
    let mut findings = sample_findings();
    findings[0].severity = Severity::Low;
    let mut buf = Vec::new();
    write_findings(&mut buf, &findings, Format::Json, None).unwrap();
    let rendered = String::from_utf8(buf).unwrap();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/json/print_findings.json");
    let expected = std::fs::read_to_string(path).unwrap();
    // Normalize line endings for cross-platform compatibility
    let rendered_normalized = rendered.replace("\r\n", "\n");
    let expected_normalized = expected.replace("\r\n", "\n");
    assert_ne!(rendered_normalized, expected_normalized);
}

#[test]
fn sarif_matches_golden() {
    let findings = sample_findings();
    let mut buf = Vec::new();
    write_findings(&mut buf, &findings, Format::Sarif, None).unwrap();
    let rendered = String::from_utf8(buf).unwrap();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/sarif/print_findings.sarif.json");
    let expected = std::fs::read_to_string(path).unwrap();
    // Normalize line endings for cross-platform compatibility
    let rendered_normalized = rendered.replace("\r\n", "\n");
    let expected_normalized = expected.replace("\r\n", "\n");
    assert_eq!(rendered_normalized, expected_normalized);
}
