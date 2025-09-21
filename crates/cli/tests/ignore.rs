use loader::visit;
use rootcause::{is_excluded, load_ignore_patterns, DEFAULT_MAX_FILE_SIZE};
use std::fs;
use tempfile::tempdir;

#[test]
fn gitignore_files_are_skipped() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    fs::write(tmp.path().join(".gitignore"), "ignored.txt\n")?;
    fs::write(tmp.path().join("ignored.txt"), "")?;
    fs::write(tmp.path().join("included.txt"), "")?;

    let patterns = load_ignore_patterns(tmp.path());
    let mut seen = Vec::new();
    visit(
        tmp.path(),
        &|p| is_excluded(p, &patterns, DEFAULT_MAX_FILE_SIZE),
        &mut |p| {
            if let Some(name) = p.file_name() {
                seen.push(name.to_string_lossy().to_string());
            }
            Ok(())
        },
    )?;

    assert!(seen.contains(&"included.txt".to_string()));
    assert!(!seen.contains(&"ignored.txt".to_string()));
    Ok(())
}

#[test]
fn gitignore_negations_are_respected() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    fs::create_dir_all(tmp.path().join("target"))?;
    fs::write(tmp.path().join(".gitignore"), "target/**\n!target/.keep\n")?;
    fs::write(tmp.path().join("target/.keep"), "")?;
    fs::write(tmp.path().join("target/other.txt"), "")?;

    let patterns = load_ignore_patterns(tmp.path());

    let keep_path = tmp.path().join("target/.keep");
    assert!(
        !is_excluded(&keep_path, &patterns, DEFAULT_MAX_FILE_SIZE),
        "negated path should not be excluded"
    );

    let other_path = tmp.path().join("target/other.txt");
    assert!(
        is_excluded(&other_path, &patterns, DEFAULT_MAX_FILE_SIZE),
        "non-negated path should remain excluded"
    );

    Ok(())
}

#[test]
fn invalid_entries_are_ignored() -> Result<(), Box<dyn std::error::Error>> {
    let tmp = tempdir()?;
    fs::write(tmp.path().join(".gitignore"), "[\nignored.txt\n")?;
    fs::write(tmp.path().join("ignored.txt"), "")?;
    fs::write(tmp.path().join("included.txt"), "")?;

    let patterns = load_ignore_patterns(tmp.path());
    assert_eq!(patterns.len(), 1);

    let mut seen = Vec::new();
    visit(
        tmp.path(),
        &|p| is_excluded(p, &patterns, DEFAULT_MAX_FILE_SIZE),
        &mut |p| {
            if let Some(name) = p.file_name() {
                seen.push(name.to_string_lossy().to_string());
            }
            Ok(())
        },
    )?;

    assert!(seen.contains(&"included.txt".to_string()));
    assert!(!seen.contains(&"ignored.txt".to_string()));
    Ok(())
}
