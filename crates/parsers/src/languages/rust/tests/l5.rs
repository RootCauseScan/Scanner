//! Level 5 records branch context and merges state conservatively.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::languages::rust::parse_rust;
use ir::{DFNodeKind, FileIR};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "rust".into());
    parse_rust(code, &mut fir).unwrap();
    fir
}

// Sanitizing in one branch should not mark data clean.
#[test]
fn unsanitized_when_only_one_branch_cleans() {
    let code = r#"
fn main() {
    let mut data = source();
    if cond {
        data = source();
    } else {
        data = sanitize(data);
    }
    sink(data);
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let assign_nodes: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Assign))
        .collect();
    assert!(assign_nodes.iter().all(|n| n.branch.is_some()));
}

// Sanitizing in all branches should mark data clean.
#[test]
fn sanitized_when_all_branches_clean() {
    let code = r#"
fn main() {
    let mut data = source();
    if cond {
        data = sanitize(data);
    } else {
        data = sanitize(source());
    }
    sink(data);
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
}

// The condition variable of a while loop should be marked as a use and
// linked back to its definition.
#[test]
fn while_cond_use() {
    let code = r#"
fn main() {
    let mut flag = true;
    while flag {
        flag = false;
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "flag" && matches!(n.kind, DFNodeKind::Def))
        .expect("flag def");
    let use_node = dfg
        .nodes
        .iter()
        .find(|n| n.name == "flag" && matches!(n.kind, DFNodeKind::Use))
        .expect("flag use");
    assert!(dfg.edges.contains(&(def.id, use_node.id)));
}

// The iterable in a for loop should produce a use node and modifications in the
// loop body should merge conservatively.
#[test]
fn for_iterable_use() {
    let code = r#"
fn main() {
    let iterable = vec![1];
    let mut data = source();
    for _ in iterable {
        data = sanitize(data);
    }
    sink(data);
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "iterable" && matches!(n.kind, DFNodeKind::Def))
        .expect("iterable def");
    let use_node = dfg
        .nodes
        .iter()
        .find(|n| n.name == "iterable" && matches!(n.kind, DFNodeKind::Use))
        .expect("iterable use");
    assert!(dfg.edges.contains(&(def.id, use_node.id)));
    let assigns: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Assign))
        .collect();
    assert!(assigns.iter().all(|n| n.branch.is_some()));
}
