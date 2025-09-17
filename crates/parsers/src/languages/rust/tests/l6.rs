//! Level 6 handles field and index accesses after method calls like `get` or `pop`.

use crate::languages::rust::parse_rust;
use ir::{DFNodeKind, FileIR};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "rust".into());
    parse_rust(code, &mut fir).unwrap();
    fir
}

#[test]
fn get_then_field_tracks_flow() {
    let code = r#"
fn main() {
    let mut cfg = object();
    cfg["item"].endpoint = source();
    sink(cfg.get("item").endpoint);
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_id = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "cfg[\"item\"].endpoint" && matches!(n.kind, DFNodeKind::Assign))
        .map(|n| n.id)
        .expect("def cfg[\"item\"].endpoint");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "cfg[\"item\"].endpoint" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use cfg[\"item\"].endpoint");
    assert!(dfg.edges.contains(&(def_id, use_id)));
}

#[test]
fn get_then_index_tracks_flow() {
    let code = r#"
fn main() {
    let mut cfg = object();
    cfg["list"][0] = source();
    sink(cfg.get("list")[0]);
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_id = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "cfg[\"list\"][0]" && matches!(n.kind, DFNodeKind::Assign))
        .map(|n| n.id)
        .expect("def cfg[\"list\"][0]");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "cfg[\"list\"][0]" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use cfg[\"list\"][0]");
    assert!(dfg.edges.contains(&(def_id, use_id)));
}

#[test]
fn pop_then_field_tracks_flow() {
    let code = r#"
fn main() {
    let mut arr = object();
    arr[0].x = source();
    sink(arr.pop().x);
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_id = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "arr[0].x" && matches!(n.kind, DFNodeKind::Assign))
        .map(|n| n.id)
        .expect("def arr[0].x");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "arr[0].x" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use arr[0].x");
    assert!(dfg.edges.contains(&(def_id, use_id)));
}
