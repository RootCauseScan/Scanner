//! Tests DFG handling of unsafe blocks.

use crate::parse_file;
use ir::{DFNodeKind, FileIR};
use std::path::Path;

fn load_ir(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

#[test]
fn records_edges_from_unsafe_block() {
    let ir = load_ir("dfg/unsafe.rs");
    let dfg = ir.dfg.expect("missing dfg");

    let unsafe_node = dfg
        .nodes
        .iter()
        .find(|n| n.name == "unsafe")
        .expect("unsafe node");
    let assign = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Assign))
        .expect("assignment");
    assert!(dfg.edges.contains(&(unsafe_node.id, assign.id)));
}

#[test]
fn ignores_safe_code() {
    let ir = load_ir("dfg/good.rs");
    let dfg = ir.dfg.expect("missing dfg");
    assert!(!dfg.nodes.iter().any(|n| n.name == "unsafe"));
}
