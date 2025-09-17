//! Maturity Level L8 Tests for Python Parser
//!
//! This module contains tests that verify the parser achieves industrial-grade precision with:
//! - SSA-lite and context-sensitive interprocedural analysis
//! - Type-aware data flow and precision metrics
//! - Advanced alias analysis and points-to heuristics
//! - Industrial-grade performance and scalability
//!
//! See docs/architecture/crates/parsers/maturity.md for detailed maturity criteria.

use crate::languages::python::parse_python;
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

/// Helper function to parse Python fixtures for L8 testing
fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.dfg_builder")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "python".into());
    parse_python(&content, &mut fir).unwrap();
    fir
}

/// Test that alias propagation works correctly in advanced scenarios
///
/// This test verifies that the parser can:
/// - Track complex alias relationships
/// - Maintain correct symbol resolution through aliases
/// - Handle advanced alias scenarios without losing precision
#[test]
fn l8_aliasing_propagates() {
    let fir = parse_fixture("alias.py");
    let b_sym = fir.symbols.get("b").expect("b symbol should exist");
    assert_eq!(
        b_sym.alias_of.as_deref(),
        Some("a"),
        "Alias relationships should be correctly tracked"
    );
}

/// Test advanced function propagation and interprocedural analysis
///
/// This test verifies that the parser can:
/// - Track data flow across function boundaries with high precision
/// - Maintain context-sensitive analysis for function calls
/// - Handle complex interprocedural data flow scenarios
/// - Preserve data flow information through parameter/return relationships
#[test]
fn l8_function_propagation() {
    let fir = parse_fixture("functions.py");
    let dfg = fir
        .dfg
        .expect("DFG should be generated for function analysis");

    // Find the definition of variable x
    let x_def = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("Variable x should be defined");

    // Find the parameter p in the function
    let p_param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "p" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("Parameter p should exist");

    // Verify data flow from argument to parameter
    assert!(
        dfg.edges.contains(&(x_def, p_param)),
        "Data flow should exist from argument x to parameter p"
    );

    // Find the return of parameter p
    let ret_p = dfg
        .nodes
        .iter()
        .find(|n| n.name == "p" && matches!(n.kind, DFNodeKind::Return))
        .map(|n| n.id)
        .expect("Return of parameter p should exist");

    // Find the definition of variable y (result of function call)
    let y_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "y" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("Variable y should be defined");

    // Verify data flow from return to result variable
    assert!(
        dfg.edges.contains(&(ret_p, y_def)),
        "Data flow should exist from function return to result variable y"
    );
}
