use crate::languages::python::parse_python;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.async")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "python".into());
    parse_python(&content, &mut fir).unwrap();
    fir
}

#[test]
fn async_await_propagates() {
    let fir = parse_fixture("bad.py");
    let dfg = fir.dfg.expect("dfg");
    let x_def = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .unwrap();
    let ret_x = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Return))
        .map(|n| n.id)
        .unwrap();
    assert!(dfg.edges.contains(&(x_def, ret_x)));
}
