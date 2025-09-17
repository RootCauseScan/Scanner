//! Maturity Level L3 Tests for Rust Parser
//!
//! This module contains tests that verify the parser can:
//! - Build Def–Use DFG and intra taint with centralized catalog
//! - Track data flow within functions (Def/Use/Assign)
//! - Use central catalog of sources/sinks/sanitizers (extensible at runtime)
//! - Build direct call graph (callee by simple name)
//! - Handle Rust-specific features like Result types, macros, and unsafe blocks
//! - Handle taint propagation and sanitization
//!
//! See docs/architecture/crates/parsers/maturity.md for detailed maturity criteria.

use crate::{catalog, parse_file};
use ir::{DFNodeKind, FileIR};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

/// Helper function to load Rust IR from fixtures
fn load_ir(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

/// Helper function to load taint analysis fixtures
fn load_taint(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust/taint")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

/// Helper function to find taint paths in data flow graph
fn find_path(fir: &FileIR) -> Option<Vec<usize>> {
    let dfg = fir.dfg.as_ref()?;
    let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut indegree: HashMap<usize, usize> = HashMap::new();
    for &(from, to) in &dfg.edges {
        adj.entry(from).or_default().push(to);
        *indegree.entry(to).or_default() += 1;
    }
    let mut queue: VecDeque<(usize, Vec<usize>)> = VecDeque::new();
    let mut visited = HashSet::new();
    for node in &dfg.nodes {
        if matches!(node.kind, DFNodeKind::Def)
            && indegree.get(&node.id).copied().unwrap_or(0) == 0
            && fir.symbols.get(&node.name).is_none_or(|s| !s.sanitized)
        {
            queue.push_back((node.id, vec![node.id]));
            visited.insert(node.id);
        }
    }
    while let Some((current, path)) = queue.pop_front() {
        let cur_node = &dfg.nodes[current];
        if matches!(cur_node.kind, DFNodeKind::Use)
            && fir.symbols.get(&cur_node.name).is_none_or(|s| !s.sanitized)
        {
            return Some(path);
        }
        if let Some(neigh) = adj.get(&current) {
            for &next in neigh {
                if visited.contains(&next)
                    || fir
                        .symbols
                        .get(&dfg.nodes[next].name)
                        .is_some_and(|s| s.sanitized)
                {
                    continue;
                }
                let mut next_path = path.clone();
                next_path.push(next);
                visited.insert(next);
                queue.push_back((next, next_path));
            }
        }
    }
    None
}

/// Test that DFG is built for good Rust examples
///
/// This test verifies that the parser can:
/// - Build valid data flow graphs for correct Rust code
/// - Track variable definitions and uses
/// - Create proper edges between related nodes
#[test]
fn builds_dfg_for_good_example() {
    let ir = load_ir("dfg/good.rs");
    let dfg = ir.dfg.expect("Data flow graph should be generated");
    assert!(
        dfg.nodes.iter().any(|n| n.name == "x"),
        "DFG should contain variable definitions"
    );
    assert!(!dfg.edges.is_empty(), "DFG should contain data flow edges");
}

/// Test that DFG is built even for bad Rust examples
///
/// This test verifies that the parser:
/// - Handles malformed code gracefully
/// - Still produces useful DFG information where possible
/// - Maintains robustness in analysis
#[test]
fn builds_dfg_for_bad_example() {
    let ir = load_ir("dfg/bad.rs");
    let dfg = ir.dfg.expect("DFG should be generated even for bad code");
    assert!(
        dfg.nodes.iter().any(|n| n.name == "y"),
        "DFG should contain recoverable variable information"
    );
    assert!(
        !dfg.edges.is_empty(),
        "DFG should contain data flow edges where possible"
    );
}

/// Test that data propagates through Result types
///
/// This test verifies Rust-specific features:
/// - Handling of Result<T, E> types
/// - Data flow through Ok() constructors
/// - Return value propagation
#[test]
fn propagates_through_ok() {
    let ir = load_ir("dfg/result.rs");
    let dfg = ir.dfg.expect("DFG should be generated");
    let a_id = ir
        .symbols
        .get("a")
        .and_then(|s| s.def)
        .expect("Variable 'a' should be defined");
    let b_id = ir
        .symbols
        .get("b")
        .and_then(|s| s.def)
        .expect("Variable 'b' should be defined");
    assert!(
        dfg.edges.contains(&(a_id, b_id)),
        "Data should flow from 'a' to 'b' through Result"
    );
    let ret_id = dfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, DFNodeKind::Return))
        .expect("Return node should exist")
        .id;
    assert!(
        dfg.edges.contains(&(b_id, ret_id)),
        "Data should flow from 'b' to return value"
    );
}

/// Test that data propagates through macros
///
/// This test verifies Rust macro handling:
/// - Macro expansion in data flow analysis
/// - Data propagation through macro calls
/// - Correct tracking of macro-generated code
#[test]
fn propagates_through_macro() {
    let ir = load_ir("dfg/macro.rs");
    let dfg = ir.dfg.expect("DFG should be generated for macro code");
    let a_id = ir
        .symbols
        .get("a")
        .and_then(|s| s.def)
        .expect("Variable 'a' should be defined");
    let b_id = ir
        .symbols
        .get("b")
        .and_then(|s| s.def)
        .expect("Variable 'b' should be defined");
    assert!(
        dfg.edges.contains(&(a_id, b_id)),
        "Data should flow through macros from 'a' to 'b'"
    );
}

/// Test that sanitized data blocks tainted paths
///
/// This test verifies sanitization tracking:
/// - Recognition of sanitized data
/// - Blocking of taint propagation through sanitizers
/// - Correct alias handling with sanitization
#[test]
fn ignores_sanitized_flow_with_alias() {
    let ir = load_ir("dfg/sanitizer.rs");
    assert!(
        ir.symbols.get("data").is_some_and(|s| s.sanitized),
        "Sanitized data should be marked as sanitized"
    );
    assert!(
        find_path(&ir).is_none(),
        "Sanitized data should block taint propagation"
    );
}

/// Test that unsanitized data creates taint paths
///
/// This test verifies taint detection:
/// - Recognition of unsanitized data
/// - Detection of taint paths to sinks
/// - Proper taint analysis through aliases
#[test]
fn detects_unsanitized_flow_with_alias() {
    let ir = load_ir("dfg/sanitizer_bad.rs");
    assert!(
        ir.symbols.get("data").is_some_and(|s| !s.sanitized),
        "Unsanitized data should not be marked as sanitized"
    );
    assert!(
        find_path(&ir).is_some(),
        "Unsanitized data should create detectable taint paths"
    );
}

/// Test that sanitizer status propagates through aliases
///
/// This test verifies alias sanitization:
/// - Propagation of sanitization status through aliases
/// - Correct marking of aliased variables
/// - DFG node sanitization tracking
#[test]
fn propagates_sanitized_to_aliases() {
    let ir = load_ir("dfg/sanitizer_alias.rs");
    assert!(
        ir.symbols.get("copy").is_some_and(|s| s.sanitized),
        "Aliases of sanitized data should be marked as sanitized"
    );
    let def = ir
        .symbols
        .get("copy")
        .and_then(|s| s.def)
        .expect("Copy variable should have definition");
    let dfg = ir.dfg.as_ref().expect("DFG should exist");
    assert!(
        dfg.nodes[def].sanitized,
        "DFG nodes for sanitized aliases should be marked as sanitized"
    );
}

/// Test that cleaning an alias doesn't sanitize the original
///
/// This test verifies sanitization isolation:
/// - Aliases can be sanitized independently
/// - Original values remain unsanitized if not directly cleaned
/// - Proper isolation of sanitization effects
#[test]
fn does_not_sanitize_original_when_alias_cleaned() {
    let ir = load_ir("dfg/sanitizer_alias_bad.rs");
    assert!(
        ir.symbols.get("copy").is_some_and(|s| s.sanitized),
        "Sanitized alias should be marked as sanitized"
    );
    assert!(
        ir.symbols.get("data").is_some_and(|s| !s.sanitized),
        "Original data should remain unsanitized when only alias is cleaned"
    );
}

/// Test that catalog entries are recognized correctly
///
/// This test verifies catalog integration:
/// - Recognition of sources, sinks, and sanitizers from catalog
/// - Proper marking of symbol types
/// - Correct sanitization of data through catalog sanitizers
#[test]
fn recognizes_catalog_sanitizers() {
    let files = [
        ("good.rs", "sanitize"),
        ("reclass.rs", "clean"),
        ("escape.rs", "escape"),
    ];
    for (file, func) in files {
        let ir = load_taint(file);
        assert!(
            ir.symbols.get("user").is_some_and(|s| s.sanitized),
            "User data should be sanitized by {}",
            func
        );
        assert!(
            matches!(ir.symbol_types.get("source"), Some(ir::SymbolKind::Source)),
            "source should be marked as Source"
        );
        assert!(
            matches!(ir.symbol_types.get("sink"), Some(ir::SymbolKind::Sink)),
            "sink should be marked as Sink"
        );
        assert!(
            matches!(ir.symbol_types.get(func), Some(ir::SymbolKind::Sanitizer)),
            "{} should be marked as Sanitizer",
            func
        );
    }
}

/// Test that unknown functions don't sanitize data
///
/// This test verifies sanitization specificity:
/// - Unknown functions don't provide sanitization
/// - Data remains tainted through unknown functions
/// - Catalog is authoritative for sanitization
#[test]
fn ignores_unknown_functions() {
    let ir = load_taint("filter.rs");
    assert!(
        ir.symbols.get("user").is_some_and(|s| !s.sanitized),
        "Data should remain unsanitized through unknown functions"
    );
    assert!(
        !ir.symbol_types.contains_key("filter"),
        "Unknown functions should not be categorized"
    );
}

/// Test that taint propagates through macro sinks
///
/// This test verifies macro sink handling:
/// - Macros can be marked as sinks in catalog
/// - Taint propagation to macro sinks
/// - Correct handling of macro:: prefixed symbols
#[test]
fn propagates_taint_through_macro_sink() {
    catalog::extend("rust", &[], &["macro::println"], &[]);
    let ir = load_taint("macro_sink.rs");
    assert!(
        matches!(ir.symbol_types.get("println"), Some(ir::SymbolKind::Sink)),
        "println macro should be marked as Sink"
    );
    assert!(
        find_path(&ir).is_some(),
        "Taint should propagate to macro sinks"
    );
}

/// Test that macro sanitizers clean their arguments
///
/// This test verifies macro sanitizer handling:
/// - Macros can be marked as sanitizers in catalog
/// - Macro sanitizers clean their arguments
/// - Proper sanitization through macro calls
#[test]
fn macro_sanitizer_marks_data_clean() {
    catalog::extend("rust", &[], &[], &["macro::clean_macro"]);
    let ir = load_taint("macro_sanitizer.rs");
    assert!(
        matches!(
            ir.symbol_types.get("clean_macro"),
            Some(ir::SymbolKind::Sanitizer)
        ),
        "clean_macro should be marked as Sanitizer"
    );
    assert!(
        ir.symbols.get("user").is_some_and(|s| s.sanitized),
        "Data should be sanitized by macro sanitizer"
    );
    assert!(
        find_path(&ir).is_none(),
        "Sanitized data should not create taint paths"
    );
}
