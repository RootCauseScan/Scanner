//! Maturity Level L1 Tests for PHP Parser
//!
//! This module validates the foundational capabilities described in
//! `docs/architecture/crates/parsers/maturity.md`:
//! - Build a real AST with location metadata
//! - Emit IR events for imports/assignments/calls
//! - Perform basic canonicalisation of simple aliases
//! - Tolerate syntax errors without panicking

use crate::parse_php;
use anyhow::Result;
use ir::{DFNodeKind, FileIR, Symbol};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

fn try_parse_snippet(code: &str) -> Result<FileIR> {
    let mut fir = FileIR::new("<mem>".into(), "php".into());
    parse_php(code, &mut fir)?;
    Ok(fir)
}

fn parse_snippet(code: &str) -> FileIR {
    try_parse_snippet(code).expect("parse php snippet")
}

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

/// AST + IR smoke test covering imports, assignments, calls and metadata
#[test]
fn l1_ast_and_ir_minimos() {
    let code = r#"<?php
require 'lib.php';
function helper($value) {
    return strtoupper($value);
}
$input = $_GET['name'];
$result = helper($input);
echo $result;
"#;
    let fir = parse_snippet(code);

    assert!(
        fir.ast.is_some(),
        "AST should be generated from valid PHP code"
    );
    assert!(
        fir.nodes.iter().any(|n| n.path.starts_with("function.")),
        "IR must include function definitions"
    );
    assert!(
        fir.nodes.iter().any(|n| n.path.starts_with("call.")),
        "IR must include call events"
    );
    assert!(
        fir.nodes.iter().any(|n| n.path == "var._GET"),
        "Reading superglobals must register import-like events"
    );
    assert!(
        fir.nodes
            .iter()
            .all(|n| n.meta.line > 0 && n.meta.column > 0),
        "All IR nodes must carry positive line/column metadata"
    );

    let dfg = fir.dfg.expect("data flow graph should be present");
    assert!(
        dfg.nodes
            .iter()
            .any(|node| node.name == "result" && matches!(node.kind, DFNodeKind::Def)),
        "Assignments must create definition nodes"
    );
}

/// Basic canonicalisation through assignment aliases
#[test]
fn l1_canonicalizacion_basica() {
    let fir = parse_fixture("alias", "good.php");
    assert_eq!(resolve_alias("b", &fir.symbols), "_GET");

    let dfg = fir.dfg.expect("dfg");
    let get_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "_GET" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("_GET definition");
    let echo_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "b" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("alias use");
    assert!(
        dfg.edges.contains(&(get_def, echo_use)),
        "Alias should resolve back to original symbol in data flow"
    );
}

/// Syntax errors should not crash and still yield a partial AST
#[test]
fn l1_syntax_error_handling() {
    let code = r#"<?php
function broken($arg) {
    if ($arg) {
        echo "ok";
// missing closing braces
"#;

    let fir = try_parse_snippet(code).expect("parser must handle syntax errors gracefully");

    assert!(
        fir.ast.is_some(),
        "Parser should still build an AST even with errors"
    );
    assert!(
        fir.nodes.iter().any(|n| n.path == "call.echo"),
        "Valid statements before the error should be processed"
    );
    assert!(
        fir.nodes
            .iter()
            .all(|n| n.meta.line > 0 && n.meta.column > 0),
        "Recovered IR nodes still require location metadata"
    );
}
