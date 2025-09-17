//! Level 2 resolves Rust imports, macros, and call paths to canonical forms.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::{parse_file, parse_rust};
use ir::FileIR;
use serde_json::json;
use std::path::Path;

fn load_ir(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

// Macros and import aliases should appear in IR.
#[test]
fn captures_macros_and_import_alias() {
    let ir = load_ir("rs.macros/good.rs");
    assert!(ir.nodes.iter().any(|n| n.path == "macro.println"));
    assert!(ir.nodes.iter().any(|n| n.path == "macro_rules.my_macro"));
    assert!(ir
        .nodes
        .iter()
        .any(|n| n.path == "import.std::fmt::Result" && n.value == json!("FmtResult")));
    assert!(!ir.nodes.iter().any(|n| n.path == "unsafe"));
}

// Unsafe blocks should still be detected with macros.
#[test]
fn reports_unsafe_with_macros_and_alias() {
    let ir = load_ir("rs.macros/bad.rs");
    assert!(ir.nodes.iter().any(|n| n.path == "macro.println"));
    assert!(ir.nodes.iter().any(|n| n.path == "macro_rules.my_macro"));
    assert!(ir
        .nodes
        .iter()
        .any(|n| n.path == "import.std::fmt::Result" && n.value == json!("FmtResult")));
    assert!(ir.nodes.iter().any(|n| n.path == "unsafe"));
}

// Invalid macro input still records metadata.
#[test]
fn rust_macros_handle_invalid_input() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust/rs.macros/invalid.rs");
    let content = std::fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into(), "rust".into());
    parse_rust(&content, &mut fir).unwrap();
    assert!(fir
        .nodes
        .iter()
        .all(|n| n.meta.line > 0 && n.meta.column > 0));
}

// Nested use lists expand into multiple import nodes.
#[test]
fn captures_nested_use_list_imports() {
    let ir = load_ir("rs.use-list/good.rs");
    assert!(ir
        .nodes
        .iter()
        .any(|n| n.path == "import.std::fmt" && n.value.is_null()));
    assert!(ir
        .nodes
        .iter()
        .any(|n| n.path == "import.std::fmt::Result" && n.value == json!("FmtResult")));
    assert!(ir
        .nodes
        .iter()
        .any(|n| n.path == "import.std::io" && n.value == json!("io_self")));
    assert!(ir
        .nodes
        .iter()
        .any(|n| n.path == "import.std::io::Write" && n.value.is_null()));
}

// Invalid use list still yields metadata.
#[test]
fn rust_use_list_handles_invalid_input() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust/rs.use-list/invalid.rs");
    let content = std::fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into(), "rust".into());
    parse_rust(&content, &mut fir).unwrap();
    assert!(fir
        .nodes
        .iter()
        .all(|n| n.meta.line > 0 && n.meta.column > 0));
}

// Namespaced calls resolve to full path.
#[test]
fn canonicalizes_calls_with_namespace() {
    let ir = load_ir("rs.call-path/namespace.rs");
    assert!(ir
        .nodes
        .iter()
        .any(|n| n.path == "call.outer::inner::local"));
    assert!(ir.nodes.iter().any(|n| n.path == "call.outer::shared"));
}

// use aliases should canonicalize call paths.
#[test]
fn canonicalizes_calls_with_use_alias() {
    let ir = load_ir("rs.call-path/use_alias.rs");
    let matched: Vec<_> = ir
        .nodes
        .iter()
        .filter(|n| n.path == "call.utils::helper")
        .collect();
    assert_eq!(matched.len(), 2);
    assert!(ir.nodes.iter().all(|n| n.path != "call.h"));
    assert!(ir.nodes.iter().all(|n| n.path != "call.u::helper"));
}

// Invalid call paths still produce metadata.
#[test]
fn rust_canonical_call_path_handles_invalid_input() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust/rs.call-path/invalid.rs");
    let content = std::fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into(), "rust".into());
    parse_rust(&content, &mut fir).unwrap();
    assert!(fir
        .nodes
        .iter()
        .all(|n| n.meta.line > 0 && n.meta.column > 0));
}
