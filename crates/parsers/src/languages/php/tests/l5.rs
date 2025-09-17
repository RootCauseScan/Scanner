//! Level 5 records branch context and merges state conservatively.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_php;
use ir::{DFNodeKind, FileIR};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "php".into());
    parse_php(code, &mut fir).expect("parse php snippet");
    fir
}

// Sanitization in only one branch should not mark variable clean.
#[test]
fn l5_merge_conservador() {
    let code = r#"<?php
if ($c) {
    $data = source();
    $data = sanitize($data);
} else {
    $data = source();
}
 sink($data);
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
    let code = r#"<?php
if ($c) {
    $data = source();
    $data = sanitize($data);
} else {
    $data = source();
    $data = sanitize($data);
}
 sink($data);
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let use_node = dfg
        .nodes
        .iter()
        .find(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Use) && n.branch.is_none())
        .expect("use node");
    assert!(use_node.sanitized);
}

// Loops record uses of loop variables.
#[test]
fn l5_while_for_uso() {
    let code = r#"<?php
$i = source();
while ($i) {
    $i = sanitize($i);
}
for ($j = 0; $j < 2; $j++) {
    sink($j);
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "i" && matches!(n.kind, DFNodeKind::Use)));
}
