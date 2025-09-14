//! Level 3 for Rust builds a DFG and tracks alias relationships.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_file;
use ir::FileIR;
use std::path::Path;

fn load_ir(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

// Good fixture should produce nodes and edges.
#[test]
fn builds_dfg_for_good_example() {
    let ir = load_ir("dfg/good.rs");
    let dfg = ir.dfg.expect("missing dfg");
    assert!(dfg.nodes.iter().any(|n| n.name == "x"));
    assert!(!dfg.edges.is_empty());
}

// Bad fixture still emits DFG information.
#[test]
fn builds_dfg_for_bad_example() {
    let ir = load_ir("dfg/bad.rs");
    let dfg = ir.dfg.expect("missing dfg");
    assert!(dfg.nodes.iter().any(|n| n.name == "y"));
    assert!(!dfg.edges.is_empty());
}

// Control blocks connect to assignments and returns.
#[test]
fn connects_control_blocks_with_assign_and_return() {
    use ir::DFNodeKind;
    let ir = load_ir("dfg/good.rs");
    let dfg = ir.dfg.expect("missing dfg");

    let assigns: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, DFNodeKind::Assign))
        .collect();
    assert!(!assigns.is_empty());

    let returns: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| matches!(n.kind, DFNodeKind::Return))
        .collect();
    assert!(!returns.is_empty());

    let if_id = dfg.nodes.iter().find(|n| n.name == "if").unwrap().id;
    let loop_id = dfg.nodes.iter().find(|n| n.name == "loop").unwrap().id;
    let match_id = dfg.nodes.iter().find(|n| n.name == "match").unwrap().id;
    assert!(dfg
        .edges
        .iter()
        .any(|(s, d)| *s == if_id && assigns.iter().any(|n| n.id == *d)));
    assert!(dfg
        .edges
        .iter()
        .any(|(s, d)| *s == loop_id && assigns.iter().any(|n| n.id == *d)));
    assert!(dfg
        .edges
        .iter()
        .any(|(s, d)| *s == match_id && assigns.iter().any(|n| n.id == *d)));
}

// Aliases create edges from original to alias.
#[test]
fn records_alias_relationships() {
    use ir::DFNodeKind;
    let ir = load_ir("dfg/alias.rs");
    let dfg = ir.dfg.expect("missing dfg");

    let sym_b = ir.symbols.get("b").expect("symbol b");
    assert_eq!(sym_b.alias_of.as_deref(), Some("a"));

    let a_id = ir.symbols.get("a").and_then(|s| s.def).unwrap();
    let b_id = sym_b.def.unwrap();
    assert!(dfg.edges.contains(&(a_id, b_id)));

    let ret_id = dfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, DFNodeKind::Return))
        .unwrap()
        .id;
    assert!(dfg.edges.contains(&(b_id, ret_id)));
}

// Undefined alias still links to return.
#[test]
fn handles_undefined_alias() {
    use ir::DFNodeKind;
    let ir = load_ir("dfg/alias_bad.rs");
    let dfg = ir.dfg.expect("missing dfg");

    assert!(!ir.symbols.contains_key("a"));
    let sym_b = ir.symbols.get("b").expect("symbol b");
    assert_eq!(sym_b.alias_of.as_deref(), Some("a"));
    let b_id = sym_b.def.unwrap();
    let ret_id = dfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, DFNodeKind::Return))
        .unwrap()
        .id;
    assert!(dfg.edges.contains(&(b_id, ret_id)));
    assert!(dfg.edges.iter().all(|(s, _)| *s == b_id));
}

// Field and index expressions create composite names and edges.
#[test]
fn tracks_field_and_index_assignments() {
    let ir = load_ir("dfg/field_index.rs");
    let dfg = ir.dfg.expect("missing dfg");

    let val_id = ir.symbols.get("val").and_then(|s| s.def).unwrap();
    let cfg_ep_id = ir.symbols.get("cfg.endpoint").and_then(|s| s.def).unwrap();
    let m_k_id = ir.symbols.get("m[\"k\"]").and_then(|s| s.def).unwrap();
    let x_id = ir.symbols.get("_x").and_then(|s| s.def).unwrap();

    assert!(dfg.nodes.iter().any(|n| n.name == "cfg.endpoint"));
    assert!(dfg.nodes.iter().any(|n| n.name == "m[\"k\"]"));
    assert!(dfg.edges.contains(&(val_id, cfg_ep_id)));
    assert!(dfg.edges.contains(&(cfg_ep_id, m_k_id)));
    assert!(dfg.edges.contains(&(m_k_id, x_id)));
}

// Missing definitions still produce composite nodes without edges.
#[test]
fn handles_undefined_field_and_index() {
    let ir = load_ir("dfg/field_index_bad.rs");
    let dfg = ir.dfg.expect("missing dfg");
    let cfg_ep_id = ir.symbols.get("cfg.endpoint").and_then(|s| s.def).unwrap();
    let m_k_id = ir.symbols.get("m[\"k\"]").and_then(|s| s.def).unwrap();
    assert!(dfg.nodes.iter().any(|n| n.id == cfg_ep_id));
    assert!(dfg.nodes.iter().any(|n| n.id == m_k_id));
    assert!(dfg
        .edges
        .iter()
        .all(|(_, d)| *d != cfg_ep_id && *d != m_k_id));
}

// Method calls transfer values between structures and variables.
#[test]
fn tracks_common_method_transfers() {
    let ir = load_ir("dfg/methods.rs");
    let dfg = ir.dfg.expect("missing dfg");

    let x_id = ir.symbols.get("x").and_then(|s| s.def).unwrap();
    let v_id = ir.symbols.get("v").and_then(|s| s.def).unwrap();
    assert!(dfg.edges.contains(&(x_id, v_id)));

    let val_id = ir.symbols.get("val").and_then(|s| s.def).unwrap();
    let m_id = ir.symbols.get("m").and_then(|s| s.def).unwrap();
    assert!(dfg.edges.contains(&(val_id, m_id)));
}

// Non-identifier parts should not create transfer edges.
#[test]
fn ignores_non_identifier_method_parts() {
    let ir = load_ir("dfg/methods_bad.rs");
    let dfg = ir.dfg.expect("missing dfg");

    let v_id = ir.symbols.get("v").and_then(|s| s.def).unwrap();
    let y_id = ir.symbols.get("y").and_then(|s| s.def).unwrap();
    assert!(!dfg.edges.contains(&(v_id, y_id)));
    assert!(dfg.edges.iter().all(|(_, d)| *d != v_id));
}
