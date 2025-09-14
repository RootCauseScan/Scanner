use super::*;
use ir::{DFNode, DFNodeKind, DataFlowGraph, FileIR, Symbol};
use std::path::PathBuf;

fn parse(path: &str) -> FileIR {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    if !path.exists() {
        eprintln!("Skipping test, fixture not found at {}", path.display());
        return FileIR::new("missing".into(), "python".into());
    }
    parsers::parse_file(&path, None, None).unwrap().unwrap()
}

#[test]
fn detects_unsanitized_flow_in_python() {
    let file = parse("../../examples/fixtures/python/taint/bad.py");
    assert_eq!(find_taint_path(&file, "source", "sink"), Some(vec![1, 2]));
}

#[test]
fn ignores_sanitized_flow_in_python() {
    let file = parse("../../examples/fixtures/python/taint/good.py");
    assert_eq!(find_taint_path(&file, "source", "sink"), None);
}

#[test]
fn ignores_unrelated_flow_in_python() {
    let file = parse("../../examples/fixtures/python/taint/missing.py");
    assert_eq!(find_taint_path(&file, "source", "sink"), None);
}

#[test]
fn detects_unsanitized_flow_in_typescript() {
    let file = parse("../../examples/fixtures/typescript/taint/bad.ts");
    assert_eq!(find_taint_path(&file, "source", "sink"), Some(vec![0, 1]));
}

#[test]
fn ignores_sanitized_flow_in_typescript() {
    let file = parse("../../examples/fixtures/typescript/taint/good.ts");
    assert_eq!(find_taint_path(&file, "source", "sink"), None);
}

#[test]
fn ignores_unrelated_flow_in_typescript() {
    let file = parse("../../examples/fixtures/typescript/taint/missing.ts");
    assert_eq!(find_taint_path(&file, "source", "sink"), None);
}

#[test]
fn detects_unsanitized_flow_in_php() {
    let file = parse("../../examples/fixtures/php/taint/bad.php");
    assert_eq!(find_taint_path(&file, "source", "sink"), Some(vec![0, 2]));
}

#[test]
fn ignores_sanitized_flow_in_php() {
    let file = parse("../../examples/fixtures/php/taint/good.php");
    assert_eq!(find_taint_path(&file, "source", "sink"), None);
}

#[test]
fn ignores_unrelated_flow_in_php() {
    let file = parse("../../examples/fixtures/php/taint/missing.php");
    assert_eq!(find_taint_path(&file, "source", "sink"), None);
}

#[test]
fn debug_php_good_dfg() {
    let file = parse("../../examples/fixtures/php/taint/good.php");
    println!("DFG nodes:");
    if let Some(dfg) = &file.dfg {
        for (i, node) in dfg.nodes.iter().enumerate() {
            println!(
                "  {}: {} ({:?}) sanitized={}",
                i, node.name, node.kind, node.sanitized
            );
        }
        println!("DFG edges: {:?}", dfg.edges);
    }
    println!("Symbols:");
    for (name, sym) in &file.symbols {
        println!("  {}: sanitized={}, def={:?}", name, sym.sanitized, sym.def);
    }
    let result = find_taint_path(&file, "source", "sink");
    println!("find_taint_path result: {result:?}");
}

#[test]
fn finds_multi_step_path() {
    let mut file = FileIR::new("test".into(), "python".into());
    let dfg = DataFlowGraph {
        nodes: vec![
            DFNode {
                id: 0,
                name: "a".into(),
                kind: DFNodeKind::Def,
                sanitized: false,
                branch: None,
            },
            DFNode {
                id: 1,
                name: "b".into(),
                kind: DFNodeKind::Def,
                sanitized: false,
                branch: None,
            },
            DFNode {
                id: 2,
                name: "b".into(),
                kind: DFNodeKind::Use,
                sanitized: false,
                branch: None,
            },
        ],
        edges: vec![(0, 1), (1, 2)],
        ..Default::default()
    };
    file.dfg = Some(dfg);
    file.symbols.insert(
        "a".into(),
        Symbol {
            name: "a".into(),
            sanitized: false,
            def: Some(0),
            alias_of: None,
        },
    );
    file.symbols.insert(
        "b".into(),
        Symbol {
            name: "b".into(),
            sanitized: false,
            def: Some(1),
            alias_of: None,
        },
    );
    assert_eq!(
        find_taint_path(&file, "source", "sink"),
        Some(vec![0, 1, 2])
    );
}

#[test]
fn stops_at_sanitized_node() {
    let mut file = FileIR::new("test".into(), "python".into());
    let dfg = DataFlowGraph {
        nodes: vec![
            DFNode {
                id: 0,
                name: "a".into(),
                kind: DFNodeKind::Def,
                sanitized: false,
                branch: None,
            },
            DFNode {
                id: 1,
                name: "b".into(),
                kind: DFNodeKind::Def,
                sanitized: true,
                branch: None,
            },
            DFNode {
                id: 2,
                name: "b".into(),
                kind: DFNodeKind::Use,
                sanitized: false,
                branch: None,
            },
        ],
        edges: vec![(0, 1), (1, 2)],
        ..Default::default()
    };
    file.dfg = Some(dfg);
    file.symbols.insert(
        "a".into(),
        Symbol {
            name: "a".into(),
            sanitized: false,
            def: Some(0),
            alias_of: None,
        },
    );
    file.symbols.insert(
        "b".into(),
        Symbol {
            name: "b".into(),
            sanitized: true,
            def: Some(1),
            alias_of: None,
        },
    );
    assert_eq!(find_taint_path(&file, "source", "sink"), None);
}
