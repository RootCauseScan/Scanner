//! Maturity Level L9 Tests for Python Parser
//!
//! This module contains tests for experimental/advanced features that go beyond L8:
//! - Advanced branch flow analysis
//! - Experimental taint tracking improvements
//! - Cutting-edge analysis techniques
//!
//! Note: These tests are marked with #[ignore] as they represent experimental features
//! that may not be fully implemented or stable yet.
//!
//! See docs/architecture/crates/parsers/maturity.md for detailed maturity criteria.

use crate::catalog;
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

/// Test advanced if branch flow analysis (experimental)
///
/// This test verifies experimental capabilities for:
/// - Advanced branch flow analysis beyond standard path sensitivity
/// - Complex taint tracking through conditional branches
/// - Enhanced data flow analysis in conditional contexts
///
/// Note: This test is ignored as it represents experimental features
/// that may not be fully implemented or stable yet.
#[test]
#[ignore]
fn l9_if_branch_flows() {
    catalog::extend("python", &["input"], &["sink"], &[]);
    let fir = parse_fixture("if_taint.py");
    let dfg = fir
        .dfg
        .expect("DFG should be generated for advanced analysis");

    // Find all definitions of variable x
    let defs: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .collect();

    // Find assignment of variable x
    let assign = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Assign))
        .map(|n| n.id)
        .expect("Assignment node should exist for variable x");

    // Verify all definitions flow to the assignment
    assert!(
        defs.iter().all(|d| dfg.edges.contains(&(*d, assign))),
        "All definitions of x should flow to the assignment"
    );

    // Find use of variable x
    let use_x = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("Use node should exist for variable x");

    // Verify assignment flows to use
    assert!(
        dfg.edges.contains(&(assign, use_x)),
        "Assignment should flow to use of variable x"
    );
}
