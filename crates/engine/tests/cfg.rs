use engine::{build_file_cfg, prepare_file};
use ir::CfgEdgeKind;
use std::path::PathBuf;

fn parse_java(rel: &str) -> ir::FileIR {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    if !path.exists() {
        let mut fir = ir::FileIR::new("missing".into(), "java".into());
        eprintln!("Skipping: fixture not found at {}", path.display());
        return fir;
    }
    parsers::parse_file(&path, None, None)
        .expect("parse")
        .expect("file")
}

#[test]
fn java_cfg_built_by_prepare_file() {
    let mut fir = parse_java("../../examples/fixtures/java/java.cfg/Sample.java");
    if fir.file_path == "missing" {
        return;
    }
    prepare_file(&mut fir);
    assert!(fir.cfg.is_some(), "prepare_file should build CFG for Java");

    let cfg = fir.cfg.unwrap();
    // Sample.java has 4 methods: run, sanitize, sink, log
    assert!(cfg.functions.contains_key("run"), "run() should be in functions map");
    assert!(cfg.functions.contains_key("sanitize"), "sanitize() should be in functions map");

    // run() contains an if/else — at minimum: entry, if_true, if_false, if_merge, exit = 5
    let (run_entry, run_exit) = cfg.functions["run"];
    assert!(run_entry != run_exit, "entry and exit should be distinct blocks");

    // There should be ConditionalTrue and ConditionalFalse edges
    assert!(
        cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::ConditionalTrue),
        "if-statement in run() should produce ConditionalTrue edge"
    );
    assert!(
        cfg.edges.iter().any(|e| e.kind == CfgEdgeKind::ConditionalFalse),
        "if-statement in run() should produce ConditionalFalse edge"
    );
}

#[test]
fn java_cfg_block_ids_stamped_on_dfg_nodes() {
    let mut fir = parse_java("../../examples/fixtures/java/java.cfg/Sample.java");
    if fir.file_path == "missing" {
        return;
    }
    prepare_file(&mut fir);
    let dfg = fir.dfg.as_ref().expect("DFG should exist for Sample.java");
    // At least some DFG nodes with line info should have block_id stamped
    let nodes_with_block = dfg.nodes.iter().filter(|n| n.line > 0 && n.block_id.is_some()).count();
    assert!(
        nodes_with_block > 0,
        "link_cfg_to_dfg should stamp block_id on DFG nodes with known line numbers"
    );
}

#[test]
fn build_file_cfg_returns_none_for_unknown_language() {
    let fir = ir::FileIR::new("test.rb".into(), "ruby".into());
    assert!(build_file_cfg(&fir).is_none());
}
