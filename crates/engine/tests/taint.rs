use engine::dataflow::{CallGraph, TaintTracker};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[test]
fn detects_interprocedural_taint() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/taint/interproc.py");
    if !path.exists() {
        eprintln!("Skipping test, fixture not found at {}", path.display());
        return;
    }
    let mut file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    if file.source.is_none() {
        file.source = std::fs::read_to_string(&path).ok();
    }
    let mut edges = HashMap::new();
    edges.insert("source".to_string(), {
        let mut s = HashSet::new();
        s.insert("sink".to_string());
        s
    });
    let cg = CallGraph { edges };
    let mut tracker = TaintTracker::new(&cg);
    tracker.mark_source("source");
    tracker.mark_sink("sink");
    assert!(tracker.has_flow());
}
