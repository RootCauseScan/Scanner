use crate::parse_java;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.lambda-dfg")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    parse_java(&content, &mut fir).expect("parse java fixture");
    fir
}

#[test]
fn lambda_param_to_return() {
    let fir = parse_fixture("good.java");
    let dfg = fir.dfg.expect("dfg");
    let param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "s" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("param");
    let ret = dfg
        .nodes
        .iter()
        .find(|n| n.name == "s" && matches!(n.kind, DFNodeKind::Return))
        .map(|n| n.id)
        .expect("return");
    assert!(dfg.edges.contains(&(param, ret)));
}

#[test]
fn method_reference_node_present() {
    let fir = parse_fixture("good.java");
    let dfg = fir.dfg.expect("dfg");
    assert!(dfg.nodes.iter().any(|n| n.name.contains("String.valueOf")));
}
