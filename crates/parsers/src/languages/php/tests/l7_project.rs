use crate::languages::php::parse_php_project;
use crate::ParserMetrics;
use std::path::Path;

#[test]
fn l7_multi_file_project() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/fixtures/php/project");
    let cache = dir.join("cache.json");
    let mut metrics = ParserMetrics::default();
    let (modules, parsed) =
        parse_php_project(&dir, &cache, Some(&mut metrics)).expect("parse project");
    assert_eq!(parsed, 2);
    assert!(modules.keys().any(|k| k.ends_with("main.php")));
    assert!(modules.keys().any(|k| k.ends_with("lib.php")));
    let _ = std::fs::remove_file(cache);
}

#[test]
fn l7_incremental_reparse() {
    use tempfile::tempdir;
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("a.php"), "<?php $a = 1;\n").unwrap();
    let cache = dir.path().join("cache.json");
    let mut metrics = ParserMetrics::default();
    let (_m1, p1) = parse_php_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p1, 1);
    let (_m2, p2) = parse_php_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p2, 0);
    std::fs::write(dir.path().join("a.php"), "<?php $a = 2;\n").unwrap();
    let (_m3, p3) = parse_php_project(dir.path(), &cache, Some(&mut metrics)).unwrap();
    assert_eq!(p3, 1);
}

#[test]
fn l7_variable_include_outside_root() {
    use tempfile::tempdir;
    let outer = tempdir().unwrap();
    let lib = outer.path().join("lib.php");
    std::fs::write(&lib, "<?php $a = 1;\n").unwrap();
    let proj = outer.path().join("proj");
    std::fs::create_dir(&proj).unwrap();
    std::fs::write(
        proj.join("main.php"),
        "<?php $f = __DIR__ . '/../lib.php'; require $f;\n",
    )
    .unwrap();
    let cache = proj.join("cache.json");
    let mut metrics = ParserMetrics::default();
    let (modules, parsed) = parse_php_project(&proj, &cache, Some(&mut metrics)).unwrap();
    assert_eq!(parsed, 2);
    assert!(modules.keys().any(|k| k.ends_with("lib.php")));
}

#[test]
fn l7_composer_autoload_files() {
    use tempfile::tempdir;
    let outer = tempdir().unwrap();
    let proj = outer.path().join("app");
    std::fs::create_dir(&proj).unwrap();
    let shared = outer.path().join("shared.php");
    std::fs::write(&shared, "<?php $x = 1;\n").unwrap();
    std::fs::write(proj.join("main.php"), "<?php echo 1;\n").unwrap();
    let composer = "{\"autoload\":{\"files\":[\"../shared.php\"]}}";
    std::fs::write(proj.join("composer.json"), composer).unwrap();
    let cache = proj.join("cache.json");
    let mut metrics = ParserMetrics::default();
    let (modules, _parsed) = parse_php_project(&proj, &cache, Some(&mut metrics)).unwrap();
    assert!(modules.keys().any(|k| k.ends_with("shared.php")));
}
