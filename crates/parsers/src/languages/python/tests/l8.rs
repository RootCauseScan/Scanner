use crate::languages::python::parse_python;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.dfg_builder")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "python".into());
    parse_python(&content, &mut fir).unwrap();
    fir
}

#[test]
fn l8_aliasing_propagates() {
    let fir = parse_fixture("alias.py");
    let b_sym = fir.symbols.get("b").expect("b symbol");
    assert_eq!(b_sym.alias_of.as_deref(), Some("a"));
}

#[test]
fn l8_function_propagation() {
    let fir = parse_fixture("functions.py");
    let dfg = fir.dfg.expect("dfg");
    let x_def = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .unwrap();
    let p_param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "p" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .unwrap();
    assert!(dfg.edges.contains(&(x_def, p_param)));
    let ret_p = dfg
        .nodes
        .iter()
        .find(|n| n.name == "p" && matches!(n.kind, DFNodeKind::Return))
        .map(|n| n.id)
        .unwrap();
    let y_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "y" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .unwrap();
    assert!(dfg.edges.contains(&(ret_p, y_def)));
}
