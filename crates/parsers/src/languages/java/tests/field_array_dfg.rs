use crate::parse_java;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.dfg")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    parse_java(&content, &mut fir).expect("parse java fixture");
    fir
}

#[test]
fn field_and_array_access_edges() {
    let fir = parse_fixture("field_array.java");
    let dfg = fir.dfg.expect("missing data flow graph");

    let y_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "y" && matches!(n.kind, DFNodeKind::Param))
        .expect("y param")
        .id;
    let field_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "this.f" && matches!(n.kind, DFNodeKind::Def))
        .expect("field def")
        .id;
    let a_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "a" && matches!(n.kind, DFNodeKind::Def))
        .expect("a def")
        .id;
    let arr_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "arr[0]" && matches!(n.kind, DFNodeKind::Def))
        .expect("arr[0] def")
        .id;
    let b_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "b" && matches!(n.kind, DFNodeKind::Def))
        .expect("b def")
        .id;
    let field_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "this.f" && matches!(n.kind, DFNodeKind::Use))
        .expect("field use")
        .id;
    let arr_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "arr[0]" && matches!(n.kind, DFNodeKind::Use))
        .expect("arr[0] use")
        .id;

    assert!(dfg.edges.contains(&(y_def, field_def)));
    assert!(dfg.edges.contains(&(a_def, arr_def)));
    assert!(dfg.edges.contains(&(y_def, a_def)));
    assert!(dfg.edges.contains(&(a_def, b_def)));
    assert!(dfg.edges.contains(&(field_def, field_use)));
    assert!(dfg.edges.contains(&(arr_def, arr_use)));
}
