//! Level 3 adds basic def-use data flow and call graph tracking.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_java;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.dfg")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    parse_java(&content, &mut fir).expect("parse java fixture");
    fir
}

// DFG nodes and call graph should be recorded for valid code.
#[test]
fn l3_def_use_y_call_graph() {
    let fir = parse_fixture("good.java");
    let dfg = fir.dfg.expect("missing data flow graph");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "result" && matches!(n.kind, DFNodeKind::Def)));
    assert_eq!(dfg.calls.len(), 1);
}

// Calls without definitions should not appear in call graph.
#[test]
fn l3_call_graph_invalido() {
    let fir = parse_fixture("bad.java");
    let dfg = fir.dfg.unwrap_or_default();
    assert!(dfg.calls.is_empty());
}
