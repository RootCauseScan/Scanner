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

// Argument flows through calls and sanitized data propagates.
#[test]
fn l4_args_y_sanitizacion() {
    let fir = parse_fixture("good.java");
    let dfg = fir.dfg.expect("dfg");
    let src_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "src" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("src def");
    let tmp_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "tmp" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("tmp def");
    assert!(dfg.edges.contains(&(src_def, tmp_def)));
    let sym = fir.symbols.get("s").expect("s symbol");
    assert!(sym.sanitized);
}

// Without sanitizer, taint remains.
#[test]
fn l4_args_y_sanitizacion_invalido() {
    let fir = parse_fixture("bad.java");
    let sym = fir.symbols.get("a").expect("a symbol");
    assert!(!sym.sanitized);
}
