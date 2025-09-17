//! Maturity Level L3 Tests for PHP Parser
//!
//! Covers intra-procedural data flow, sanitizer handling and call graph
//! generation as described in the maturity guide.

use crate::{catalog, parse_php};
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(dir: &str, file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/php")
        .join(dir)
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "php".into());
    parse_php(&content, &mut fir).expect("parse php fixture");
    fir
}

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "php".into());
    parse_php(code, &mut fir).expect("parse php snippet");
    fir
}

/// Def/Use edges with sanitizers coming from the built-in catalog
#[test]
fn l3_def_use_y_sanitizers_catalogo() {
    let fir = parse_fixture("sanitization", "good.php");
    let dfg = fir.dfg.as_ref().expect("data flow graph");

    let source_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "_GET" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("superglobal definition");
    let sanitized_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "name" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("sanitized definition");

    assert!(dfg.edges.contains(&(source_def, sanitized_def)));
    let symbol = fir.symbols.get("name").expect("sanitized symbol");
    assert!(symbol.sanitized, "Sanitizer must propagate to symbol table");
}

/// Direct call graph generation inside a single file
#[test]
fn l3_call_graph_directo() {
    let code = "<?php\nfunction callee() {}\nfunction caller() { callee(); }\n";
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    let caller_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "caller")
        .map(|n| n.id)
        .expect("caller id");
    let callee_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "callee")
        .map(|n| n.id)
        .expect("callee id");
    assert!(
        dfg.calls.contains(&(caller_id, callee_id)),
        "Call graph must register caller → callee relation"
    );
}

/// Runtime catalog extensions should affect sanitizer detection
#[test]
fn l3_catalog_integration() {
    const SANITIZER: &str = "custom_php_catalog_escape";
    assert!(!catalog::is_sanitizer("php", SANITIZER));
    catalog::extend("php", &[], &[], &[SANITIZER]);
    assert!(catalog::is_sanitizer("php", SANITIZER));

    let code = r#"<?php
$name = $_GET['name'];
$name = custom_php_catalog_escape($name);
echo $name;
"#;
    let fir = parse_snippet(code);
    let symbol = fir.symbols.get("name").expect("sanitized symbol");
    assert!(
        symbol.sanitized,
        "Catalog-registered sanitizer must mark symbols"
    );
}

/// Basic taint propagation through assignments and sanitizers
#[test]
fn l3_taint_propagation_basic() {
    let code = r#"<?php
$tainted = $_GET['value'];
$copy = $tainted;
$clean_once = strip_tags($copy);
$clean_twice = htmlspecialchars($clean_once);
echo $clean_twice;
"#;
    let fir = parse_snippet(code);
    let symbols = &fir.symbols;

    let tainted = symbols.get("tainted").expect("tainted symbol");
    assert!(!tainted.sanitized);
    let copy = symbols.get("copy").expect("copy symbol");
    assert!(!copy.sanitized, "Assignment should propagate taint to copy");
    let clean_once = symbols.get("clean_once").expect("clean symbol");
    assert!(clean_once.sanitized, "strip_tags must clean the value");
    let clean_twice = symbols.get("clean_twice").expect("double-sanitized symbol");
    assert!(
        clean_twice.sanitized,
        "Multiple sanitizers remain sanitized"
    );
}
