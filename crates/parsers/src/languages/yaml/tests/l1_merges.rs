//! Level 1 ensures YAML merges produce basic IR nodes.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_yaml;
use ir::FileIR;
use std::path::Path;

fn parse_fixture(name: &str) -> FileIR {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../examples/fixtures/yaml/{name}"));
    let content = std::fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into(), "yaml".into());
    parse_yaml(&content, &mut fir).unwrap();
    fir
}

// Valid merge keys should resolve into IR nodes.
#[test]
fn resolves_yaml_merges_into_ir_nodes() {
    let fir = parse_fixture("merge_good.yaml");
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "foo.a" && n.value == serde_json::json!(1)));
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "foo.b" && n.value == serde_json::json!(3)));
}

// Invalid merge should yield an error and no IR.
#[test]
fn yaml_returns_error_for_invalid_merge() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/fixtures/yaml/merge_bad.yaml");
    let content = std::fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into(), "yaml".into());
    assert!(parse_yaml(&content, &mut fir).is_err());
    assert!(fir.nodes.is_empty());
}
