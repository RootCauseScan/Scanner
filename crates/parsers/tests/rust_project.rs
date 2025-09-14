use ir::SymbolKind;
use parsers::{parse_rust_project, parse_rust_project_uncached, ParserMetrics};
use tempfile::tempdir;

#[test]
fn rust_multi_file_analysis() {
    let dir = tempdir().unwrap();
    std::fs::write(
        dir.path().join("mod_a.rs"),
        "pub fn dangerous() -> i32 { unsafe { source() } }\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("main.rs"),
        "mod mod_a; use mod_a::dangerous; fn main() { println!(\"{}\", dangerous()); }\n",
    )
    .unwrap();
    let project = parse_rust_project_uncached(dir.path()).unwrap();
    let has_macro = project
        .values()
        .any(|f| f.nodes.iter().any(|n| n.path == "macro.println"));
    let has_unsafe = project
        .values()
        .any(|f| f.nodes.iter().any(|n| n.path == "unsafe"));
    assert!(has_macro && has_unsafe);
}

#[test]
fn rust_project_cache_incremental() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("a.rs"), "fn main() {}\n").unwrap();
    let cache = dir.path().join("cache.json");
    let mut metrics = ParserMetrics::default();
    let (_m1, p1) = parse_rust_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p1, 1);
    let (_m2, p2) = parse_rust_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p2, 0);
    std::fs::write(dir.path().join("a.rs"), "fn main(){ let _ = 1; }\n").unwrap();
    let (_m3, p3) = parse_rust_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p3, 1);
}

#[test]
fn rust_project_robustness() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("good.rs"), "fn ok(){}\n").unwrap();
    std::fs::write(dir.path().join("bad.rs"), "fn broken(\n").unwrap();
    let project = parse_rust_project_uncached(dir.path()).unwrap();
    assert!(project.contains_key("good"));
    assert!(project.contains_key("bad"));
    let bad = project.get("bad").unwrap();
    if let Some(kind) = bad.symbol_types.get("__parse_error__") {
        assert_eq!(kind, &SymbolKind::Special);
    }
}
