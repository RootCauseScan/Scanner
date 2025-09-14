//! Level 4 links arguments to parameters and returns to destinations.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::languages::python::parse_python;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.dfg")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "python".into());
    parse_python(&content, &mut fir).unwrap();
    fir
}

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

// Argument definitions flow into function parameters.
#[test]
fn l4_args_a_params() {
    let code = r#"
def f(p):
    return p

x = source()
y = f(x)
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let edge_exists = dfg.edges.iter().any(|(from, to)| {
        let from_node = dfg.nodes.iter().find(|n| n.id == *from).unwrap();
        let to_node = dfg.nodes.iter().find(|n| n.id == *to).unwrap();
        from_node.name == "x"
            && matches!(from_node.kind, DFNodeKind::Def)
            && to_node.name == "p"
            && matches!(to_node.kind, DFNodeKind::Param)
    });
    assert!(edge_exists);
}

// Return values connect to caller destinations.
#[test]
fn l4_returns_a_destino() {
    let code = r#"
def f(p):
    return p

x = source()
y = f(x)
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let ret_p = dfg
        .nodes
        .iter()
        .find(|n| n.name == "p" && matches!(n.kind, DFNodeKind::Return))
        .map(|n| n.id)
        .expect("return p");
    let y_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "y" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("y def");
    assert!(dfg.edges.contains(&(ret_p, y_def)));
}

// Sanitization through calls should be preserved.
#[test]
fn l4_taint_a_traves_de_llamada() {
    let code = r#"
def f(p):
    return p

y = sanitize(f(source()))
sink(y)
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("y").expect("y symbol");
    assert!(sym.sanitized);
}

// Missing sanitizer leaves taint after call.
#[test]
fn l4_taint_a_traves_de_llamada_invalido() {
    let code = r#"
def f(p):
    return p

y = f(source())
sink(y)
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("y").expect("y symbol");
    assert!(!sym.sanitized);
}

// Parameters should link to returned values.
#[test]
fn parameter_connects_to_return() {
    let fir = parse_fixture("param_return.py");
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
    let fir = parse_snippet("def constant(x):\n    return 1\n");
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

// Data should propagate across simple call chains.
#[test]
fn propagates_across_functions() {
    let code = r#"def callee(p):
    return p

def caller(a):
    b = callee(a)
    return b
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("missing data flow graph");
    let a_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "a" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("missing a def");
    let p_param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "p" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("missing p param");
    let ret_p = dfg
        .nodes
        .iter()
        .find(|n| n.name == "p" && matches!(n.kind, DFNodeKind::Return))
        .map(|n| n.id)
        .expect("missing return node");
    let b_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "b" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("missing b def");
    assert!(dfg.edges.contains(&(a_def, p_param)));
    assert!(dfg.edges.contains(&(ret_p, b_def)));
    assert!(!dfg.edges.contains(&(a_def, b_def)));
}

// Constant returns stop propagation.
#[test]
fn no_propagation_when_callee_returns_constant() {
    let code = r#"def callee(p):
    return 1

def caller(a):
    b = callee(a)
    return b
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("missing data flow graph");
    let a_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "a" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("missing a def");
    let b_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "b" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("missing b def");
    assert!(!dfg.edges.contains(&(a_def, b_def)));
}
