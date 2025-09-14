use rootcause::scan::{read_file_cached, update_files_from_transform};
use rootcause::{is_excluded, parse_exclude, DEFAULT_MAX_FILE_SIZE};
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Instant;
use tempfile::tempdir;

type JsonValue = serde_json::Value;

fn build_result(n: usize) -> JsonValue {
    let files: Vec<JsonValue> = (0..n)
        .map(|i| {
            json!({
                "path": format!("file_{i}.txt"),
                "content_b64": format!("content_{i}"),
                "notes": ["note"]
            })
        })
        .collect();
    json!({"files": files})
}

#[test]
fn update_scales_linearly() {
    let measure = |n| {
        let mut files = Vec::new();
        let mut index = HashMap::new();
        let result = build_result(n);
        let iterations = 100;
        let start = Instant::now();
        for _ in 0..iterations {
            update_files_from_transform(&mut files, &mut index, &result);
        }
        start.elapsed().as_micros()
    };
    let t1 = measure(100);
    let t2 = measure(200);
    let t3 = measure(400);
    assert!(t2 <= t1 * 3, "runtime not linear: {t2} vs {t1}");
    assert!(t3 <= t1 * 6, "runtime not linear: {t3} vs {t1}");
}

#[test]
fn matches_exclude_patterns() {
    let patterns = vec![
        parse_exclude("**/node_modules/**").unwrap(),
        parse_exclude("**/*.lock").unwrap(),
    ];
    assert!(is_excluded(
        Path::new("/repo/a/node_modules/x/y"),
        &patterns,
        DEFAULT_MAX_FILE_SIZE
    ));
    assert!(is_excluded(
        Path::new("/repo/yarn.lock"),
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
fn file_cache_reads_once() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file = dir.path().join("a.txt");
    fs::write(&file, b"first")?;
    let mut cache = HashMap::new();
    let initial = read_file_cached(&file, &mut cache).unwrap().to_vec();
    fs::write(&file, b"second")?;
    let cached = read_file_cached(&file, &mut cache).unwrap().to_vec();
    assert_eq!(initial, cached);
    Ok(())
}
