//! Maturity Level L2 Tests for PHP Parser
//!
//! These tests exercise the name-resolution capabilities documented in the
//! maturity guide: aliasing, complex import resolution, namespaced symbols
//! and detection of circular includes.

use crate::languages::php::parse_php_project;
use crate::parse_php;
use anyhow::Result;
use ir::{FileIR, Symbol};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/php/php.aliasing")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "php".into());
    parse_php(&content, &mut fir).expect("parse php fixture");
    fir
}

fn try_parse_snippet(code: &str) -> Result<FileIR> {
    let mut fir = FileIR::new("<mem>".into(), "php".into());
    parse_php(code, &mut fir)?;
    Ok(fir)
}

fn resolve_alias(name: &str, symbols: &HashMap<String, Symbol>) -> String {
    let mut current = name;
    let mut seen = HashSet::new();
    seen.insert(current.to_string());
    while let Some(next) = symbols
        .get(current)
        .and_then(|symbol| symbol.alias_of.as_deref())
    {
        if !seen.insert(next.to_string()) {
            break;
        }
        current = next;
    }
    current.to_string()
}

/// Aliasing and canonicalisation of symbol names through assignments
#[test]
fn l2_aliasing_y_canonicalizacion() {
    let fir = parse_fixture("good.php");
    assert_eq!(resolve_alias("b", &fir.symbols), "a");
    let symbol = fir.symbols.get("b").expect("alias symbol");
    assert!(
        symbol.sanitized,
        "sanitizer propagation should survive aliasing"
    );
}

#[test]
fn l2_aliasing_y_canonicalizacion_invalido() {
    let fir = parse_fixture("bad.php");
    assert_eq!(resolve_alias("b", &fir.symbols), "_GET");
    let symbol = fir.symbols.get("b").expect("alias symbol");
    assert!(
        !symbol.sanitized,
        "tainted value must remain tainted after aliasing"
    );
}

/// Complex import statements (require/include with computed paths)
#[test]
fn l2_imports_compuestos() {
    use tempfile::tempdir;

    let dir = tempdir().expect("temp project");
    let project = dir.path();
    let lib = project.join("lib.php");
    fs::write(&lib, "<?php function util() { return 1; }\n").unwrap();
    let main = project.join("main.php");
    fs::write(
        &main,
        "<?php\n$base = __DIR__;\nrequire $base . '/lib.php';\n",
    )
    .unwrap();

    let cache = project.join("cache.json");
    let (modules, parsed) = parse_php_project(project, &cache, None).expect("project parse");
    assert_eq!(parsed, 2, "Both files must be parsed exactly once");
    assert!(
        modules.keys().any(|k| k.ends_with("lib.php")),
        "Computed include paths must resolve to concrete modules"
    );
}

/// Namespaces and qualified identifiers must resolve correctly
#[test]
fn l2_namespace_resolution() {
    let code = r#"<?php
namespace App\Lib;
function local() { return 1; }
\App\Lib\local();
App\Lib\local();
"#;
    let fir = try_parse_snippet(code).expect("parse namespaced snippet");
    assert!(
        fir.nodes.iter().any(|n| n.path == "call.\\App\\Lib\\local"),
        "Fully-qualified calls should retain namespace prefix"
    );
    assert!(
        fir.nodes.iter().any(|n| n.path == "call.App\\Lib\\local"),
        "Relative calls inside namespace should resolve to qualified path"
    );
}

/// Circular includes should be detected without infinite recursion
#[test]
fn l2_import_cycle_detection() {
    use tempfile::tempdir;

    let dir = tempdir().expect("temp project");
    let project = dir.path();
    fs::write(project.join("a.php"), "<?php require __DIR__ . '/b.php';\n").unwrap();
    fs::write(project.join("b.php"), "<?php require __DIR__ . '/a.php';\n").unwrap();

    let cache = project.join("cache.json");
    let (_modules, parsed) = parse_php_project(project, &cache, None).expect("project parse");
    assert_eq!(parsed, 2, "Cycle should still parse each file exactly once");
}
