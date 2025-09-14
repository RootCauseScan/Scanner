//! Level 2 focuses on resolving imports and aliases into canonical names.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_java;
use ir::FileIR;
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.aliasing")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    parse_java(&content, &mut fir).expect("parse java fixture");
    fir
}

// Static import allows calling method without class prefix while keeping original call.
#[test]
fn l2_aliasing_y_canonicalizacion() {
    let fir = parse_fixture("good.java");
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "call.Collections.emptyList"));
    assert!(fir.nodes.iter().any(|n| n.path == "call.emptyList"));
}

// Without import, only unqualified call remains.
#[test]
fn l2_aliasing_y_canonicalizacion_invalido() {
    let fir = parse_fixture("bad.java");
    assert!(fir.nodes.iter().any(|n| n.path == "call.emptyList"));
    assert!(!fir
        .nodes
        .iter()
        .any(|n| n.path == "call.Collections.emptyList"));
}
