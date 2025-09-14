use rootcause::{default_excludes, is_excluded, DEFAULT_MAX_FILE_SIZE};
use std::io::Write;
use std::path::Path;
use tempfile::NamedTempFile;

#[test]
fn excludes_common_dirs() {
    let patterns = default_excludes();
    assert!(is_excluded(
        Path::new("/repo/node_modules/pkg"),
        &patterns,
        DEFAULT_MAX_FILE_SIZE
    ));
    assert!(is_excluded(
        Path::new("/repo/.git/config"),
        &patterns,
        DEFAULT_MAX_FILE_SIZE
    ));
    assert!(!is_excluded(
        Path::new("/repo/src/main.rs"),
        &patterns,
        DEFAULT_MAX_FILE_SIZE
    ));
}

#[test]
fn excludes_large_files() {
    let mut tmp = NamedTempFile::new().unwrap();
    let size = DEFAULT_MAX_FILE_SIZE + 1;
    tmp.as_file_mut()
        .write_all(vec![0u8; size as usize].as_slice())
        .unwrap();
    assert!(is_excluded(tmp.path(), &[], DEFAULT_MAX_FILE_SIZE));
    assert!(!is_excluded(tmp.path(), &[], 0));
}

#[test]
fn can_disable_defaults() {
    assert!(!is_excluded(
        Path::new("/repo/node_modules/pkg"),
        &[],
        DEFAULT_MAX_FILE_SIZE
    ));
}
