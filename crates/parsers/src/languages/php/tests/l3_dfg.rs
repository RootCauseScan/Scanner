//! Level 3 validates def-use edges and direct call graph.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_php;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/php/php.dfg")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "php".into());
    parse_php(&content, &mut fir).expect("parse php fixture");
    fir
}

// Good example builds edges and call graph.
#[test]
fn l3_def_use_y_call_graph_directo() {
    let fir = parse_fixture("good.php");
    let dfg = fir.dfg.expect("dfg");
    let a_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "a" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("a def");
    let b_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "b" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("b def");
    assert!(dfg.edges.contains(&(a_def, b_def)));
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

// Calls outside functions should not appear in call graph.
#[test]
fn l3_call_graph_directo_invalido() {
    let fir = parse_fixture("bad.php");
    let dfg = fir.dfg.unwrap_or_default();
    assert!(dfg.calls.is_empty());
}
