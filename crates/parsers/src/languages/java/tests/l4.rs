//! Level 4 links data across function boundaries and tracks sanitization.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_java;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.interproc")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    parse_java(&content, &mut fir).expect("parse java fixture");
    fir
}

// good.java: src = id(src); src = escapeHtml(src); sink(src)
// After inter-procedural linking: Param(p) receives src; src ends up sanitized.
#[test]
fn l4_args_y_sanitizacion() {
    let fir = parse_fixture("good.java");
    let dfg = fir.dfg.as_ref().expect("dfg");

    // There must be Param(p) in the id() method
    let param_p_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "p" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("Param(p) in id() must exist");

    // There must be at least one Def node named "src"
    let src_def_ids: Vec<usize> = dfg
        .nodes
        .iter()
        .filter(|n| n.name == "src" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .collect();
    assert!(!src_def_ids.is_empty(), "at least one Def(src) must exist");

    // Some Def(src) → Param(p) edge must exist via call_args inter-procedural linking
    let has_interproc_edge = src_def_ids
        .iter()
        .any(|&did| dfg.edges.contains(&(did, param_p_id)));
    assert!(
        has_interproc_edge,
        "inter-procedural edge from a Def(src) to Param(p) must exist"
    );

    // After src = escapeHtml(src), src must be sanitized in the symbol table
    let sym = fir.symbols.get("src").expect("src symbol must exist");
    assert!(sym.sanitized, "src must be sanitized after escapeHtml reassignment");
}

// Without sanitizer, taint remains.
#[test]
fn l4_args_y_sanitizacion_invalido() {
    let fir = parse_fixture("bad.java");
    let sym = fir.symbols.get("a").expect("a symbol");
    assert!(!sym.sanitized);
}
