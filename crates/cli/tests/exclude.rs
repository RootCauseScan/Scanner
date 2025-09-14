use rootcause::{is_excluded, parse_exclude, DEFAULT_MAX_FILE_SIZE};
use std::path::Path;

#[test]
fn handles_windows_paths() {
    let patterns = vec![parse_exclude("**/node_modules/**").unwrap()];
    assert!(is_excluded(
        Path::new(r"C:\repo\node_modules\pkg"),
        &patterns,
        DEFAULT_MAX_FILE_SIZE
    ));
    assert!(!is_excluded(
        Path::new(r"C:\repo\src\main.rs"),
        &patterns,
        DEFAULT_MAX_FILE_SIZE
    ));
}

#[test]
fn malformed_glob_errors() {
    assert!(parse_exclude("[a-c").is_err());
}
