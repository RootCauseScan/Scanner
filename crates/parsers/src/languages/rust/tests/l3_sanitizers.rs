//! Level 3 tracks sanitized and unsanitized flows in Rust.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::{catalog, parse_file};
use ir::{DFNodeKind, FileIR};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

fn load_ir(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

fn load_taint(rel: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/rust/taint")
        .join(rel);
    parse_file(&path, None, None).expect("parse").expect("ir")
}

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

// Sanitized data should block tainted paths.
#[test]
fn ignores_sanitized_flow_with_alias() {
    let ir = load_ir("dfg/sanitizer.rs");
    assert!(ir.symbols.get("data").is_some_and(|s| s.sanitized));
    assert!(find_path(&ir).is_none());
}

// Unsanitized alias should expose a path.
#[test]
fn detects_unsanitized_flow_with_alias() {
    let ir = load_ir("dfg/sanitizer_bad.rs");
    assert!(ir.symbols.get("data").is_some_and(|s| !s.sanitized));
    assert!(find_path(&ir).is_some());
}
// Sanitizer status propagates through aliases.
#[test]
fn propagates_sanitized_to_aliases() {
    let ir = load_ir("dfg/sanitizer_alias.rs");
    assert!(ir.symbols.get("copy").is_some_and(|s| s.sanitized));
    let def = ir
        .symbols
        .get("copy")
        .and_then(|s| s.def)
        .expect("copy def");
    let dfg = ir.dfg.as_ref().expect("dfg");
    assert!(dfg.nodes[def].sanitized);
}

// Cleaning alias should not sanitize original value.
#[test]
fn does_not_sanitize_original_when_alias_cleaned() {
    let ir = load_ir("dfg/sanitizer_alias_bad.rs");
    assert!(ir.symbols.get("copy").is_some_and(|s| s.sanitized));
    assert!(ir.symbols.get("data").is_some_and(|s| !s.sanitized));
}

// Catalog entries mark sources, sinks, and sanitizers.
#[test]
fn recognizes_catalog_sanitizers() {
    let files = [
        ("good.rs", "sanitize"),
        ("reclass.rs", "clean"),
        ("escape.rs", "escape"),
    ];
    for (file, func) in files {
        let ir = load_taint(file);
        assert!(ir.symbols.get("user").is_some_and(|s| s.sanitized));
        assert!(
            matches!(ir.symbol_types.get("source"), Some(ir::SymbolKind::Source)),
            "source not marked as Source"
        );
        assert!(
            matches!(ir.symbol_types.get("sink"), Some(ir::SymbolKind::Sink)),
            "sink not marked as Sink"
        );
        assert!(
            matches!(ir.symbol_types.get(func), Some(ir::SymbolKind::Sanitizer)),
            "{func} not marked as Sanitizer"
        );
    }
}

// Unknown functions leave data unsanitized.
#[test]
fn ignores_unknown_functions() {
    let ir = load_taint("filter.rs");
    assert!(ir.symbols.get("user").is_some_and(|s| !s.sanitized));
    assert!(!ir.symbol_types.contains_key("filter"));
}

// Macro invocation should propagate taint to sinks.
#[test]
fn propagates_taint_through_macro_sink() {
    catalog::extend("rust", &[], &["macro::println"], &[]);
    let ir = load_taint("macro_sink.rs");
    assert!(matches!(
        ir.symbol_types.get("println"),
        Some(ir::SymbolKind::Sink)
    ));
    assert!(find_path(&ir).is_some());
}

// Macros marked as sanitizers clean their arguments.
#[test]
fn macro_sanitizer_marks_data_clean() {
    catalog::extend("rust", &[], &[], &["macro::clean_macro"]);
    let ir = load_taint("macro_sanitizer.rs");
    assert!(matches!(
        ir.symbol_types.get("clean_macro"),
        Some(ir::SymbolKind::Sanitizer)
    ));
    assert!(ir.symbols.get("user").is_some_and(|s| s.sanitized));
    assert!(find_path(&ir).is_none());
}
