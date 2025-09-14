//! Level 4 connects arguments to parameters and returns to their uses.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::{languages::rust::parse_rust, parse_file};
use ir::{DFNodeKind, FileIR};
use std::path::Path;

fn load_ir(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "rust".into());
    parse_rust(code, &mut fir).unwrap();
    fir
}

// Function calls link args to params and returns to uses.
#[test]
fn links_args_and_returns() {
    let ir = load_ir("rs.interproc/good.rs");
    let dfg = ir.dfg.expect("dfg");
    let x_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .unwrap()
        .id;
    let param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "a" && matches!(n.kind, DFNodeKind::Param))
        .unwrap()
        .id;
    let ret = dfg
        .nodes
        .iter()
        .find(|n| n.name == "a" && matches!(n.kind, DFNodeKind::Return))
        .unwrap()
        .id;
    let y_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "y" && matches!(n.kind, DFNodeKind::Def))
        .unwrap()
        .id;
    let func_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "id" && matches!(n.kind, DFNodeKind::Def))
        .unwrap()
        .id;
    let main_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "main" && matches!(n.kind, DFNodeKind::Def))
        .unwrap()
        .id;
    assert!(dfg.edges.contains(&(x_def, param)));
    assert!(dfg.edges.contains(&(ret, y_def)));
    assert!(dfg.calls.contains(&(main_id, func_id)));
    assert!(dfg.call_returns.contains(&(y_def, func_id)));
}

// Missing function definitions produce no interproc edges.
#[test]
fn ignores_unknown_function() {
    let ir = load_ir("rs.interproc/missing.rs");
    let dfg = ir.dfg.expect("dfg");
    assert!(dfg.calls.is_empty());
    assert!(dfg.call_returns.is_empty());
}

// Sanitization through calls should be preserved.
#[test]
fn l4_taint_a_traves_de_llamada() {
    let code = r#"
fn id(p: i32) -> i32 { p }
fn main() {
    let y = sanitize(id(source()));
    sink(y);
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("y").expect("y symbol");
    assert!(sym.sanitized);
}

// Missing sanitizer leaves taint after call.
#[test]
fn l4_taint_a_traves_de_llamada_invalido() {
    let code = r#"
fn id(p: i32) -> i32 { p }
fn main() {
    let y = id(source());
    sink(y);
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("y").expect("y symbol");
    assert!(!sym.sanitized);
}

// Parameters should link to returned values.
#[test]
fn parameter_connects_to_return() {
    let fir = parse_snippet("fn id(x: i32) -> i32 { return x; }\n");
    let dfg = fir.dfg.expect("missing data flow graph");
    let def_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("missing parameter def");
    let ret_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Return))
        .map(|n| n.id)
        .expect("missing return node");
    assert!(dfg.edges.contains(&(def_id, ret_id)));
}

// Parameter with no return edge stays disconnected.
#[test]
fn parameter_without_return_has_no_edge() {
    let fir = parse_snippet("fn constant(x: i32) -> i32 { return 1; }\n");
    let dfg = fir.dfg.expect("missing data flow graph");
    let def_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("missing parameter def");
    assert!(dfg
        .nodes
        .iter()
        .all(|n| !(n.name == "x" && matches!(n.kind, DFNodeKind::Return))));
    assert!(dfg.edges.iter().all(|(from, _)| *from != def_id));
}
