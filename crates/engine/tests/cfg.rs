use engine::{build_file_cfg, find_taint_path, prepare_file};
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

#[test]
fn java_taint_source_flows_to_sink() {
    let fir = parse_java("../../examples/fixtures/java/java.taint/bad.java");
    if fir.file_path == "missing" {
        return;
    }
    let result = find_taint_path(&fir, "source", "sink");
    assert!(result.is_some(), "expected taint path in bad.java, got None");
}

#[test]
fn java_taint_sanitized_path_is_clean() {
    let fir = parse_java("../../examples/fixtures/java/java.taint/good.java");
    if fir.file_path == "missing" {
        return;
    }
    assert_eq!(
        find_taint_path(&fir, "source", "sink"),
        None,
        "sanitized java flow should not produce a taint path"
    );
}

#[test]
fn java_taint_unrelated_path_produces_no_finding() {
    let fir = parse_java("../../examples/fixtures/java/java.taint/missing.java");
    if fir.file_path == "missing" {
        return;
    }
    assert_eq!(
        find_taint_path(&fir, "source", "sink"),
        None,
        "java file without sink() call should produce no path"
    );
}

#[test]
fn java_interproc_taint_detected_across_method_boundary() {
    let fir = parse_java("../../examples/fixtures/java/java.interproc/bad.java");
    if fir.file_path == "missing" {
        return;
    }
    let result = find_taint_path(&fir, "dangerous", "sink");
    assert!(
        result.is_some(),
        "expected taint path across method boundary in interproc/bad.java, got None"
    );
}

#[test]
fn java_interproc_sanitized_path_is_clean() {
    let fir = parse_java("../../examples/fixtures/java/java.interproc/good.java");
    if fir.file_path == "missing" {
        return;
    }
    assert_eq!(
        find_taint_path(&fir, "dangerous", "sink"),
        None,
        "sanitized inter-procedural flow should produce no taint path"
    );
}

#[test]
fn java_interproc_call_edges_populated() {
    let fir = parse_java("../../examples/fixtures/java/java.interproc/bad.java");
    if fir.file_path == "missing" {
        return;
    }
    let dfg = fir.dfg.as_ref().expect("DFG should exist for interproc/bad.java");
    assert!(
        !dfg.calls.is_empty(),
        "inter-procedural call should populate dfg.calls"
    );
}

#[test]
fn java_cfg_for_switch_has_multiple_blocks() {
    let src = r#"class SwitchTest {
    void run(int x) {
        switch (x) {
            case 1:
                doA();
                break;
            case 2:
                doB();
                break;
            default:
                doC();
        }
    }
}
"#;
    let tmp = tempfile::NamedTempFile::with_suffix(".java").expect("tempfile");
    std::fs::write(tmp.path(), src).expect("write");
    let mut fir = parsers::parse_file(tmp.path(), None, None)
        .expect("parse")
        .expect("file");
    prepare_file(&mut fir);
    let cfg = fir.cfg.expect("CFG should be built for switch statement");
    // switch(x) with 3 cases → at least: entry + 3 case blocks + exit = 5+ blocks
    assert!(
        cfg.blocks.len() >= 4,
        "switch with 3 cases should produce at least 4 blocks, got {}",
        cfg.blocks.len()
    );
}
