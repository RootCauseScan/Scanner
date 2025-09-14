//! Level 1 ensures PHP parsing captures basic flow and sanitization.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_php;
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

// strip_tags should mark output as sanitized.
#[test]
fn recognizes_strip_tags_as_sanitizer() {
    let good = parse_fixture("xss", "good.php");
    let dfg = good.dfg.expect("missing data flow graph");
    assert!(dfg.nodes.iter().any(|n| n.name == "clean" && n.sanitized));
}

// Command injection sample should track tainted flow.
#[test]
fn tracks_flow_into_system_call() {
    let bad = parse_fixture("command_injection", "bad.php");
    let dfg = bad.dfg.expect("missing data flow graph");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "cmd" && matches!(n.kind, DFNodeKind::Use)));
}

// References propagate taint between variables.
#[test]
fn follows_reference_aliases() {
    let bad = parse_fixture("alias", "bad.php");
    let dfg = bad.dfg.expect("missing data flow graph");
    let get_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "_GET" && matches!(n.kind, DFNodeKind::Def))
        .expect("_GET def");
    let b_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "b" && matches!(n.kind, DFNodeKind::Use))
        .expect("b use");
    assert!(dfg
        .edges
        .iter()
        .any(|&(s, d)| s == get_def.id && d == b_use.id));
}

// Reference assignment operator shares taint.
#[test]
fn follows_reference_assignment_operator() {
    let code = "<?php\n$a = $_GET['name'];\n$b = &$a;\necho $b;\n";
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("missing data flow graph");
    let get_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "_GET" && matches!(n.kind, DFNodeKind::Def))
        .expect("_GET def");
    let b_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "b" && matches!(n.kind, DFNodeKind::Use))
        .expect("b use");
    assert!(dfg
        .edges
        .iter()
        .any(|&(s, d)| s == get_def.id && d == b_use.id));
}

// Sanitizer on reference cleans alias.
#[test]
fn sanitizes_reference_aliases() {
    let good = parse_fixture("alias", "good.php");
    let dfg = good.dfg.expect("missing data flow graph");
    assert!(dfg.nodes.iter().any(|n| n.name == "b" && n.sanitized));
}

// Custom sanitizer should be recognized.
#[test]
fn recognizes_custom_sanitizer() {
    let good = parse_fixture("sanitization", "good.php");
    let dfg = good.dfg.expect("missing data flow graph");
    assert!(dfg.nodes.iter().any(|n| n.name == "name" && n.sanitized));
}

// Function calls inside functions create call edges.
#[test]
fn records_call_edge_within_function() {
    let code = "<?php\nfunction callee() {}\nfunction caller() { callee(); }\n";
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("missing data flow graph");
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
    assert!(dfg.calls.contains(&(caller_id, callee_id)));
}

// Top-level calls are ignored in call graph.
#[test]
fn call_outside_function_has_no_edge() {
    let code = "<?php\ncallee();\nfunction callee() {}\n";
    let fir = parse_snippet(code);
    let dfg = fir.dfg.unwrap_or_default();
    assert!(dfg.calls.is_empty());
}
