use super::super::parse_java_project;
use crate::ParserMetrics;
use std::fs;
use tempfile::{tempdir, NamedTempFile};

#[test]
fn multi_file_project() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.project");
    let cache = NamedTempFile::new().unwrap();
    let (modules, parsed) = parse_java_project(&root, cache.path(), None).unwrap();
    assert_eq!(parsed, 2);
    assert!(modules.contains_key("Main"));
    assert!(modules.contains_key("pkg.Helper"));
    let main = modules.get("Main").unwrap();
    let call = main
        .nodes
        .iter()
        .any(|n| n.path == "call.pkg.Helper.source");
    assert!(call);
}

#[test]
fn incremental_reparse() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.project");
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("pkg")).unwrap();
    fs::copy(src.join("Main.java"), dir.path().join("Main.java")).unwrap();
    fs::copy(
        src.join("pkg").join("Helper.java"),
        dir.path().join("pkg").join("Helper.java"),
    )
    .unwrap();
    let cache = dir.path().join("cache.json");
    let mut metrics = ParserMetrics::default();
    let (_m1, p1) = parse_java_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p1, 2);
    let (_m2, p2) = parse_java_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p2, 0);
    fs::write(
        dir.path().join("Main.java"),
        "class Main { void test(){} }\n",
    )
    .unwrap();
    let (_m3, p3) = parse_java_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p3, 1);
}
