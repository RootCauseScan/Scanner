use loader::{load_rules, Severity};
use std::fs;
use tempfile::tempdir;

#[test]
fn parses_extended_severities() {
    assert_eq!("info".parse::<Severity>().unwrap(), Severity::Info);
    assert_eq!("error".parse::<Severity>().unwrap(), Severity::Error);
    assert_eq!("critical".parse::<Severity>().unwrap(), Severity::Critical);
}

#[test]
fn rejects_unknown_severity() -> anyhow::Result<()> {
    let dir = tempdir()?;
    fs::write(
        dir.path().join("rules.yaml"),
        r#"rules:
- id: test.rule
  pattern: foo
  message: test
  severity: UNKNOWN
"#,
    )?;
    let err = load_rules(dir.path()).unwrap_err();
    assert!(err.to_string().contains("unknown severity"));
    Ok(())
}

#[test]
fn default_severity_is_medium() -> anyhow::Result<()> {
    let dir = tempdir()?;
    fs::write(
        dir.path().join("rules.yaml"),
        r#"rules:
- id: test.rule
  pattern: foo
  message: test
"#,
    )?;
    let rs = load_rules(dir.path())?;
    assert_eq!(rs.rules[0].severity, Severity::Medium);
    Ok(())
}

#[test]
fn severity_roundtrip() {
    let sev: Severity = serde_json::from_str("\"CRITICAL\"").unwrap();
    assert_eq!(sev, Severity::Critical);
    let ser = serde_json::to_string(&sev).unwrap();
    assert_eq!(ser, "\"CRITICAL\"");
}
