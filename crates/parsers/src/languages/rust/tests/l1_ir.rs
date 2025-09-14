//! Level 1 validates Rust IR for basic unsafe and unwrap patterns.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_file;
use ir::FileIR;
use std::path::Path;

fn load_ir(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

// unwrap() should appear in IR for bad samples.
#[test]
fn detects_unwrap_calls() {
    let ir = load_ir("rs.no-unwrap/bad.rs");
    assert!(ir.nodes.iter().any(|n| n.path == "call.unwrap"));
}

// Safe code should have no unwrap nodes.
#[test]
fn ignores_unwrap_in_good_code() {
    let ir = load_ir("rs.no-unwrap/good.rs");
    assert!(!ir.nodes.iter().any(|n| n.path == "call.unwrap"));
}

// Bad sample uses unsafe multiple times.
#[test]
fn detects_multiple_unsafe_usages() {
    let ir = load_ir("rs.no-unsafe/bad.rs");
    let count = ir.nodes.iter().filter(|n| n.path == "unsafe").count();
    assert!(
        count >= 2,
        "expected at least 2 unsafe nodes, found {count}"
    );
}

// Safe sample should not contain unsafe nodes.
#[test]
fn ignores_unsafe_in_safe_code() {
    let ir = load_ir("rs.no-unsafe/good.rs");
    assert!(!ir.nodes.iter().any(|n| n.path == "unsafe"));
}

// expect() should appear in IR for bad samples.
#[test]
fn detects_expect_calls() {
    let ir = load_ir("rs.no-expect/bad.rs");
    assert!(ir.nodes.iter().any(|n| n.path == "call.expect"));
}

// Safe code should have no expect nodes.
#[test]
fn ignores_expect_in_good_code() {
    let ir = load_ir("rs.no-expect/good.rs");
    assert!(!ir.nodes.iter().any(|n| n.path == "call.expect"));
}

// panic! macro should be captured in bad samples.
#[test]
fn detects_panic_macro() {
    let ir = load_ir("rs.no-panic/bad.rs");
    assert!(ir.nodes.iter().any(|n| n.path == "macro.panic"));
}

// Good samples should not include panic! macro.
#[test]
fn ignores_panic_in_good_code() {
    let ir = load_ir("rs.no-panic/good.rs");
    assert!(!ir.nodes.iter().any(|n| n.path == "macro.panic"));
}
