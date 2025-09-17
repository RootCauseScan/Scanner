//! Maturity Level L1 Tests for Python Parser
//!
//! This module contains tests that verify the parser can:
//! - Build real AST from Python source code
//! - Extract basic semantic events (import, assign, call) into IR
//! - Handle syntax errors gracefully
//! - Provide correct file/line/column metadata
//!
//! See docs/architecture/crates/parsers/maturity.md for detailed maturity criteria.

use crate::languages::python::parse_python;
use ir::FileIR;

/// Helper function to parse Python code snippets for testing
fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

/// Test that AST exists and IR captures basic events with metadata
///
/// This test verifies the fundamental capability of the parser to:
/// - Generate a valid AST from Python source code
/// - Extract import, assignment, and call events into IR
/// - Provide accurate line/column metadata for all nodes
/// - Build basic data flow graph with definitions
#[test]
fn l1_ast_and_ir_minimos() {
    let code = "import os\nx = 1\nprint(x)\n";
    let fir = parse_snippet(code);

    // Verify AST exists
    assert!(
        fir.ast.is_some(),
        "AST should be generated from valid Python code"
    );

    // Verify IR contains expected events
    assert!(
        fir.nodes.iter().any(|n| n.path == "import.os"),
        "IR should contain import events"
    );

    // Verify DFG contains variable definitions
    let dfg = fir.dfg.as_ref().expect("DFG should be generated");
    assert!(
        dfg.nodes
            .iter()
            .any(|n| n.name == "x" && matches!(n.kind, ir::DFNodeKind::Def)),
        "DFG should contain variable definitions"
    );

    // Verify function calls are captured
    assert!(
        fir.nodes.iter().any(|n| n.path == "call.print"),
        "IR should contain call events"
    );

    // Verify metadata is present and valid
    assert!(
        fir.nodes
            .iter()
            .all(|n| n.meta.line > 0 && n.meta.column > 0),
        "All nodes should have valid line and column metadata"
    );
}

/// Test graceful handling of invalid syntax
///
/// This test verifies that the parser:
/// - Doesn't crash on syntax errors
/// - Returns empty IR for invalid syntax
/// - Handles malformed import statements gracefully
#[test]
fn l1_ast_and_ir_minimos_invalido() {
    let code = "import\n";
    let fir = parse_snippet(code);
    assert!(
        fir.nodes.is_empty(),
        "Invalid syntax should produce no IR nodes"
    );
}

/// Test basic alias resolution in import statements
///
/// This test verifies that the parser can:
/// - Resolve import aliases (import x as y)
/// - Use canonical names in function calls
/// - Maintain correct symbol resolution
#[test]
fn l1_canonicalizacion_basica() {
    let code = "import pkg.mod as m\nm.func()\n";
    let fir = parse_snippet(code);
    assert!(
        fir.nodes.iter().any(|n| n.path == "call.pkg.mod.func"),
        "Aliased imports should resolve to canonical call paths"
    );
}

/// Test that broken aliasing doesn't resolve call paths
///
/// This test verifies that malformed import aliases:
/// - Don't create invalid call paths
/// - Fail gracefully without crashing
/// - Don't produce incorrect canonical names
#[test]
fn l1_canonicalizacion_basica_invalido() {
    let code = "import pkg.mod as\nm.func()\n";
    let fir = parse_snippet(code);
    assert!(
        !fir.nodes.iter().any(|n| n.path == "call.pkg.mod.func"),
        "Broken aliasing should not resolve to canonical call paths"
    );
}

/// Test that entirely invalid code produces no analysis artifacts
///
/// This test verifies that the parser:
/// - Handles completely malformed code gracefully
/// - Doesn't produce partial or incorrect analysis results
/// - Maintains consistency when syntax is invalid
#[test]
fn ignores_invalid_syntax() {
    let code = "def f(:\n  pass";
    let fir = parse_snippet(code);

    assert!(
        fir.nodes.is_empty(),
        "IR nodes should be empty for invalid code"
    );
    assert!(
        fir.dfg.is_none(),
        "DFG should not be produced for invalid code"
    );
    assert!(
        fir.symbols.is_empty(),
        "No symbols should be recorded for invalid code"
    );
}

/// Test that functions decorated with @timeit are marked as special
///
/// This test verifies that the parser can:
/// - Recognize special decorators like @timeit
/// - Mark decorated functions with appropriate symbol types
/// - Handle decorator syntax correctly
#[test]
fn marks_timeit_function_as_special() {
    let code = "@timeit\ndef timed():\n    pass\n";
    let fir = parse_snippet(code);
    assert!(
        matches!(fir.symbol_types.get("timed"), Some(ir::SymbolKind::Special)),
        "Functions decorated with @timeit should be marked as special"
    );
}

/// Test that normal functions are not treated as special
///
/// This test verifies that the parser:
/// - Distinguishes between decorated and normal functions
/// - Only marks appropriately decorated functions as special
/// - Maintains correct symbol types for regular functions
#[test]
fn ignores_normal_function() {
    let code = "def regular():\n    pass\n";
    let fir = parse_snippet(code);
    assert!(
        !matches!(
            fir.symbol_types.get("regular"),
            Some(ir::SymbolKind::Special)
        ),
        "Normal functions should not be marked as special"
    );
}
