//! Maturity Level L3 Tests for Java Parser
//!
//! This module contains tests that verify the parser can:
//! - Build Def–Use DFG and intra taint with centralized catalog
//! - Track data flow within functions (Def/Use/Assign)
//! - Use central catalog of sources/sinks/sanitizers (extensible at runtime)
//! - Build direct call graph (callee by simple name)
//! - Handle Java-specific features like lambdas, fields, and arrays
//! - Handle taint propagation and sanitization
//!
//! See docs/architecture/crates/parsers/maturity.md for detailed maturity criteria.

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

// DFG nodes and call graph should be recorded for valid code.
#[test]
fn l3_def_use_y_call_graph() {
    let fir = parse_fixture("good.java");
    let dfg = fir.dfg.expect("missing data flow graph");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "result" && matches!(n.kind, DFNodeKind::Def)));
    assert_eq!(dfg.calls.len(), 1);
}

/// Test that calls without definitions don't appear in call graph
///
/// This test verifies error handling:
/// - Invalid code doesn't create spurious call graph entries
/// - Parser handles malformed Java gracefully
/// - DFG remains consistent even with bad input
#[test]
fn l3_call_graph_invalido() {
    let fir = parse_fixture("bad.java");
    let dfg = fir.dfg.unwrap_or_default();
    assert!(
        dfg.calls.is_empty(),
        "Invalid code should not create call graph entries"
    );
}

/// Helper function to parse Java lambda fixtures
fn parse_lambda_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java/java.lambda-dfg")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    parse_java(&content, &mut fir).expect("parse java fixture");
    fir
}

/// Test that data flows from lambda parameters to returns
///
/// This test verifies Java lambda handling:
/// - Lambda parameters are tracked in DFG
/// - Data flows correctly through lambda expressions
/// - Return values are properly connected
#[test]
fn lambda_param_to_return() {
    let fir = parse_lambda_fixture("good.java");
    let dfg = fir.dfg.expect("DFG should be generated for lambda code");
    let param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "s" && matches!(n.kind, DFNodeKind::Param))
        .map(|n| n.id)
        .expect("Lambda parameter should exist");
    let ret = dfg
        .nodes
        .iter()
        .find(|n| n.name == "s" && matches!(n.kind, DFNodeKind::Return))
        .map(|n| n.id)
        .expect("Lambda return should exist");
    assert!(
        dfg.edges.contains(&(param, ret)),
        "Data should flow from lambda parameter to return"
    );
}

/// Test that method references are tracked in DFG
///
/// This test verifies Java method reference handling:
/// - Method references are captured in DFG
/// - Static method references are properly named
/// - Method reference nodes are present in the graph
#[test]
fn method_reference_node_present() {
    let fir = parse_lambda_fixture("good.java");
    let dfg = fir.dfg.expect("DFG should be generated");
    assert!(
        dfg.nodes.iter().any(|n| n.name.contains("String.valueOf")),
        "Method reference nodes should be present in DFG"
    );
}

/// Test that field and array access creates proper data flow edges
///
/// This test verifies Java field and array handling:
/// - Field access (this.f) is tracked correctly
/// - Array access (arr[0]) creates proper nodes
/// - Data flow through fields and arrays is maintained
#[test]
fn field_and_array_access_edges() {
    let fir = parse_fixture("field_array.java");
    let dfg = fir.dfg.expect("Data flow graph should be generated");

    // Find all the relevant nodes
    let y_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "y" && matches!(n.kind, DFNodeKind::Param))
        .expect("Parameter y should exist")
        .id;
    let field_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "this.f" && matches!(n.kind, DFNodeKind::Def))
        .expect("Field definition should exist")
        .id;
    let a_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "a" && matches!(n.kind, DFNodeKind::Def))
        .expect("Variable a definition should exist")
        .id;
    let arr_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "arr[0]" && matches!(n.kind, DFNodeKind::Def))
        .expect("Array element definition should exist")
        .id;
    let b_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "b" && matches!(n.kind, DFNodeKind::Def))
        .expect("Variable b definition should exist")
        .id;
    let field_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "this.f" && matches!(n.kind, DFNodeKind::Use))
        .expect("Field use should exist")
        .id;
    let arr_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "arr[0]" && matches!(n.kind, DFNodeKind::Use))
        .expect("Array element use should exist")
        .id;

    // Verify all the expected data flow edges
    assert!(
        dfg.edges.contains(&(y_def, field_def)),
        "Data should flow from parameter to field"
    );
    assert!(
        dfg.edges.contains(&(a_def, arr_def)),
        "Data should flow from variable to array element"
    );
    assert!(
        dfg.edges.contains(&(y_def, a_def)),
        "Data should flow from parameter to variable"
    );
    assert!(
        dfg.edges.contains(&(a_def, b_def)),
        "Data should flow between variables"
    );
    assert!(
        dfg.edges.contains(&(field_def, field_use)),
        "Data should flow from field definition to use"
    );
    assert!(
        dfg.edges.contains(&(arr_def, arr_use)),
        "Data should flow from array definition to use"
    );
}
