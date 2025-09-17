//! Maturity Level L5 Tests for Python Parser
//!
//! This module contains tests that verify the parser can:
//! - Distinguish between different execution paths (branches)
//! - Merge state information conservatively (path sensitivity)
//! - Ensure variables are only considered sanitized if sanitized in ALL paths
//! - Handle if/elif/else, while, for with coherent uses
//! - Prevent false negatives through conservative merging
//!
//! See docs/architecture/crates/parsers/maturity.md for detailed maturity criteria.

use crate::catalog;
use crate::languages::python::parse_python;
use ir::{DFNodeKind, FileIR};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

// Sanitization in only one branch should not mark variable clean.
#[test]
fn l5_merge_conservador() {
    catalog::extend("python", &["source"], &["sink"], &["sanitize"]);
    let code = r#"
if cond:
    data = source()
    data = sanitize(data)
else:
    data = source()

sink(data)
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let def_nodes: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Def))
        .collect();
    assert!(def_nodes.iter().all(|n| n.branch.is_some()));
    let use_node = dfg
        .nodes
        .iter()
        .find(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Use))
        .expect("use node");
    assert!(!use_node.sanitized);
}

// Sanitization in all branches marks variable clean.
#[test]
fn l5_merge_conservador_sanitizado() {
    catalog::extend("python", &["source"], &["sink"], &["sanitize"]);
    let code = r#"
if cond:
    data = source()
    data = sanitize(data)
else:
    data = source()
    data = sanitize(data)

sink(data)
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let use_node = dfg
        .nodes
        .iter()
        .find(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Use))
        .expect("use node");
    assert!(use_node.sanitized);
}

// Loops record uses of loop variables.
#[test]
fn l5_while_for_uso() {
    catalog::extend("python", &["source"], &["sink"], &["sanitize"]);
    let code = r#"
i = source()
while i:
    i = sanitize(i)
for j in range(2):
    sink(j)
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "i" && matches!(n.kind, DFNodeKind::Use)));
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "j" && matches!(n.kind, DFNodeKind::Use)));
}
