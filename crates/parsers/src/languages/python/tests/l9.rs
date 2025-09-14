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
fn l9_if_branch_flows() {
    let fir = parse_fixture("if_taint.py");
    let dfg = fir.dfg.expect("dfg");
    let defs: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .collect();
    let assign = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Assign))
        .map(|n| n.id)
        .expect("assign node");
    assert!(defs.iter().all(|d| dfg.edges.contains(&(*d, assign))));
    let use_x = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use node");
    assert!(dfg.edges.contains(&(assign, use_x)));
}
