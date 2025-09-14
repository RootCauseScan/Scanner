use loader::load_rules;
use std::fs;
use tempfile::tempdir;

#[test]
fn rejects_duplicate_ids() -> anyhow::Result<()> {
    let dir = tempdir()?;
    fs::write(
        dir.path().join("rules.yaml"),
        r#"rules:
- id: dup.rule
  pattern: foo
  message: a
- id: dup.rule
  pattern: bar
  message: b
"#,
    )?;
    let err = load_rules(dir.path()).unwrap_err();
    assert!(err.to_string().to_lowercase().contains("duplicate"));
    Ok(())
}
