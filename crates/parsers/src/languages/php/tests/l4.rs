//! Maturity Level L4 Tests for PHP Parser
//!
//! Validates interprocedural data flow (arguments → parameters, returns →
//! destinations) and taint propagation across function and method calls.

use crate::parse_php;
use ir::{DFNode, DFNodeKind, FileIR};
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

fn node<'a, F>(dfg: &'a [DFNode], name: &str, kind_predicate: F) -> &'a DFNode
where
    F: Fn(&DFNodeKind) -> bool,
{
    dfg.iter()
        .find(|n| n.name == name && kind_predicate(&n.kind))
        .unwrap_or_else(|| panic!("missing node {name}"))
}

/// Arguments must connect to parameters through the DFG
#[test]
fn l4_args_a_params() {
    let code = r#"<?php
function id($param) { return $param; }
$input = $_GET['name'];
$result = id($input);
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    let param = node(&dfg.nodes, "param", |k| matches!(k, DFNodeKind::Param));
    let incoming: Vec<_> = dfg
        .edges
        .iter()
        .filter(|(_, dst)| *dst == param.id)
        .collect();
    assert!(
        !incoming.is_empty(),
        "Parameter should receive data flow edges from call arguments"
    );
    let source_names: Vec<_> = incoming
        .into_iter()
        .map(|(src, _)| dfg.nodes[*src].name.as_str())
        .collect();
    assert!(
        source_names
            .iter()
            .any(|name| *name == "input" || *name == "_GET"),
        "Parameter should be linked to argument definitions"
    );
}

/// Return nodes must connect back to the caller assignment
#[test]
fn l4_returns_a_destino() {
    let code = r#"<?php
function id($param) { return $param; }
$input = $_GET['name'];
$result = id($input);
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    let result_def = node(&dfg.nodes, "result", |k| matches!(k, DFNodeKind::Def));
    let ret_node = node(&dfg.nodes, "param", |k| matches!(k, DFNodeKind::Return));
    assert!(
        dfg.edges.contains(&(ret_node.id, result_def.id)),
        "Return value should flow into caller destination"
    );
}

/// Taint propagation through function calls, with sanitization
#[test]
fn l4_taint_a_traves_de_llamada() {
    let good = parse_fixture("php.interproc", "good.php");
    let bad = parse_fixture("php.interproc", "bad.php");

    let good_symbol = good.symbols.get("y").expect("symbol y");
    assert!(
        good_symbol.sanitized,
        "Sanitized call must produce clean symbol"
    );

    let bad_symbol = bad.symbols.get("y").expect("symbol y");
    assert!(
        !bad_symbol.sanitized,
        "Unsanitized call must keep tainted value"
    );
}

/// Nested calls should keep propagating taint information
#[test]
fn l4_nested_calls() {
    let code = r#"<?php
function inner($value) { return $value; }
function outer($value) { return inner($value); }
$result = outer($_GET['name']);
"#;
    let fir = parse_snippet(code);
    let symbol = fir.symbols.get("result").expect("result symbol");
    assert!(
        !symbol.sanitized,
        "Nested unsanitized calls must keep the taint flag"
    );
}

/// Object method calls should propagate taint into parameters
#[test]
fn l4_method_calls() {
    let code = r#"<?php
class Controller {
    public function passthrough($value) { return $value; }
}
$ctrl = new Controller();
$output = $ctrl->passthrough($_GET['name']);
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let output_def = node(&dfg.nodes, "output", |k| matches!(k, DFNodeKind::Def));
    let get_def = node(&dfg.nodes, "_GET", |k| matches!(k, DFNodeKind::Def));
    assert!(
        dfg.edges.contains(&(get_def.id, output_def.id)),
        "Taint from superglobal must reach method call result"
    );
}
