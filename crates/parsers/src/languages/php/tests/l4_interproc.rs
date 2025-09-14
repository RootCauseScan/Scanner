//! Level 4 checks data propagation through function calls.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_php;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/php/php.interproc")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "php".into());
    parse_php(&content, &mut fir).expect("parse php fixture");
    fir
}

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "php".into());
    parse_php(code, &mut fir).expect("parse php snippet");
    fir
}

// Arguments should flow into destinations through calls.
#[test]
#[ignore]
fn l4_args_a_params_y_returns_a_destino() {
    let code = "<?php\nfunction id($p) { return $p; }\n$x = $_GET['name'];\n$y = id($x);\n";
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let x_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("x def");
    let y_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "y" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("y def");
    assert!(dfg.edges.contains(&(x_def, y_def)));
}

// Sanitization through calls should be preserved.
#[test]
fn l4_taint_a_traves_de_llamada() {
    let fir = parse_fixture("good.php");
    let sym = fir.symbols.get("y").expect("y symbol");
    assert!(sym.sanitized);
}

// Without sanitization taint remains after call.
#[test]
fn l4_taint_a_traves_de_llamada_invalido() {
    let fir = parse_fixture("bad.php");
    let sym = fir.symbols.get("y").expect("y symbol");
    assert!(!sym.sanitized);
}
