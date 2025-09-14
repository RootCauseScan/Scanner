use loader::load_rules;
use std::fs;
use tempfile::tempdir;

#[test]
fn loads_interfile_option() -> anyhow::Result<()> {
    let dir = tempdir()?;
    fs::write(
        dir.path().join("rules.yaml"),
        r#"rules:
- id: test.rule
  pattern: foo
  message: test
  options:
    interfile: true
"#,
    )?;
    let rs = load_rules(dir.path())?;
    assert!(rs.rules[0].interfile);
    Ok(())
}

#[test]
fn invalid_interfile_type() -> anyhow::Result<()> {
    let dir = tempdir()?;
    fs::write(
        dir.path().join("rules.yaml"),
        r#"rules:
- id: test.rule
  pattern: foo
  message: test
  options:
    interfile: "yes"
"#,
    )?;
    let err = load_rules(dir.path()).unwrap_err();
    assert!(err.downcast_ref::<serde_yaml::Error>().is_some());
    Ok(())
}
