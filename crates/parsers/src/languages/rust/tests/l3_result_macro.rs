//! Tests DFG handling for Result and macro propagation.

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
fn propagates_through_ok() {
    let ir = load_ir("dfg/result.rs");
    let dfg = ir.dfg.expect("missing dfg");
    let a_id = ir.symbols.get("a").and_then(|s| s.def).expect("a def");
    let b_id = ir.symbols.get("b").and_then(|s| s.def).expect("b def");
    assert!(dfg.edges.contains(&(a_id, b_id)));
    let ret_id = dfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, DFNodeKind::Return))
        .expect("return node")
        .id;
    assert!(dfg.edges.contains(&(b_id, ret_id)));
}

#[test]
fn propagates_through_macro() {
    let ir = load_ir("dfg/macro.rs");
    let dfg = ir.dfg.expect("missing dfg");
    let a_id = ir.symbols.get("a").and_then(|s| s.def).expect("a def");
    let b_id = ir.symbols.get("b").and_then(|s| s.def).expect("b def");
    assert!(dfg.edges.contains(&(a_id, b_id)));
}
