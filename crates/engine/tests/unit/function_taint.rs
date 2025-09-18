use super::canonical::TEST_MUTEX;
use super::*;
use engine::function_taint::parse_call;
use ir::{AstNode, DFNode, DFNodeKind, DataFlowGraph, FileAst, Meta, Symbol};
use serde_json::json;

fn tainted_file() -> FileIR {
    let mut file = FileIR::new("t1".into(), "python".into());
    file.source = Some(
        "def source():\n    pass\nuser = source()\nsink(user)\nclean = 1\nsink(clean)\n".into(),
    );

    let mut ast = FileAst::new("t1".into(), "python".into());
    ast.push(AstNode {
        id: 1,
        parent: None,
        kind: "CallExpression".into(),
        value: json!(null),
        children: Vec::new(),
        meta: Meta {
            file: "t1".into(),
            line: 3,
            column: 1,
        },
    });
    ast.push(AstNode {
        id: 2,
        parent: None,
        kind: "CallExpression".into(),
        value: json!(null),
        children: Vec::new(),
        meta: Meta {
            file: "t1".into(),
            line: 4,
            column: 1,
        },
    });
    ast.push(AstNode {
        id: 3,
        parent: None,
        kind: "CallExpression".into(),
        value: json!(null),
        children: Vec::new(),
        meta: Meta {
            file: "t1".into(),
            line: 6,
            column: 1,
        },
    });
    ast.push(AstNode {
        id: 0,
        parent: None,
        kind: "Function".into(),
        value: json!("source"),
        children: Vec::new(),
        meta: Meta {
            file: "t1".into(),
            line: 1,
            column: 1,
        },
    });
    file.ast = Some(ast);

    file.dfg = Some(DataFlowGraph {
        nodes: vec![
            DFNode {
                id: 0,
                name: "user".into(),
                kind: DFNodeKind::Def,
                sanitized: false,
                branch: None,
            },
            DFNode {
                id: 1,
                name: "user".into(),
                kind: DFNodeKind::Use,
                sanitized: false,
                branch: None,
            },
            DFNode {
                id: 2,
                name: "clean".into(),
                kind: DFNodeKind::Def,
                sanitized: false,
                branch: None,
            },
            DFNode {
                id: 3,
                name: "clean".into(),
                kind: DFNodeKind::Use,
                sanitized: false,
                branch: None,
            },
        ],
        edges: vec![(0, 1), (2, 3)],
        ..Default::default()
    });
    file.symbols.insert(
        "user".into(),
        Symbol {
            name: "user".into(),
            sanitized: false,
            def: Some(0),
            alias_of: None,
        },
    );
    file.symbols.insert(
        "clean".into(),
        Symbol {
            name: "clean".into(),
            sanitized: true,
            def: Some(2),
            alias_of: None,
        },
    );
    file
}

fn clean_file() -> FileIR {
    let mut file = FileIR::new("t2".into(), "python".into());
    file.source = Some("safe = 1\nsink(safe)\n".into());

    let mut ast = FileAst::new("t2".into(), "python".into());
    ast.push(AstNode {
        id: 0,
        parent: None,
        kind: "CallExpression".into(),
        value: json!(null),
        children: Vec::new(),
        meta: Meta {
            file: "t2".into(),
            line: 2,
            column: 1,
        },
    });
    file.ast = Some(ast);

    file.dfg = Some(DataFlowGraph {
        nodes: vec![
            DFNode {
                id: 0,
                name: "safe".into(),
                kind: DFNodeKind::Def,
                sanitized: false,
                branch: None,
            },
            DFNode {
                id: 1,
                name: "safe".into(),
                kind: DFNodeKind::Use,
                sanitized: false,
                branch: None,
            },
        ],
        edges: vec![(0, 1)],
        ..Default::default()
    });
    file.symbols.insert(
        "safe".into(),
        Symbol {
            name: "safe".into(),
            sanitized: true,
            def: Some(0),
            alias_of: None,
        },
    );
    file
}

fn wrap_file() -> FileIR {
    let mut file = FileIR::new("wrap".into(), "python".into());
    file.source = Some("def wrap():\n    data = source()\n".into());

    let mut ast = FileAst::new("wrap".into(), "python".into());
    ast.push(AstNode {
        id: 10,
        parent: None,
        kind: "Function".into(),
        value: json!("wrap"),
        children: vec![AstNode {
            id: 11,
            parent: Some(10),
            kind: "CallExpression".into(),
            value: json!(null),
            children: Vec::new(),
            meta: Meta {
                file: "wrap".into(),
                line: 2,
                column: 1,
            },
        }],
        meta: Meta {
            file: "wrap".into(),
            line: 1,
            column: 1,
        },
    });
    file.ast = Some(ast);

    file.dfg = Some(DataFlowGraph {
        nodes: vec![DFNode {
            id: 0,
            name: "data".into(),
            kind: DFNodeKind::Def,
            sanitized: false,
            branch: None,
        }],
        edges: vec![],
        calls: vec![(10, 0)],
        call_returns: vec![(0, 0)],
        merges: vec![],
    });
    file.symbols.insert(
        "data".into(),
        Symbol {
            name: "data".into(),
            sanitized: false,
            def: Some(0),
            alias_of: None,
        },
    );
    file
}

fn main_file() -> FileIR {
    let mut file = FileIR::new("main".into(), "python".into());
    file.source = Some("tmp = wrap()\nsink(tmp)\n".into());

    let mut ast = FileAst::new("main".into(), "python".into());
    ast.push(AstNode {
        id: 20,
        parent: None,
        kind: "CallExpression".into(),
        value: json!(null),
        children: Vec::new(),
        meta: Meta {
            file: "main".into(),
            line: 1,
            column: 1,
        },
    });
    ast.push(AstNode {
        id: 21,
        parent: None,
        kind: "CallExpression".into(),
        value: json!(null),
        children: Vec::new(),
        meta: Meta {
            file: "main".into(),
            line: 2,
            column: 1,
        },
    });
    file.ast = Some(ast);

    file.dfg = Some(DataFlowGraph {
        nodes: vec![
            DFNode {
                id: 0,
                name: "tmp".into(),
                kind: DFNodeKind::Def,
                sanitized: false,
                branch: None,
            },
            DFNode {
                id: 1,
                name: "tmp".into(),
                kind: DFNodeKind::Use,
                sanitized: false,
                branch: None,
            },
        ],
        edges: vec![(0, 1)],
        calls: vec![],
        call_returns: vec![(0, 10)],
        merges: vec![],
    });
    file.symbols.insert(
        "tmp".into(),
        Symbol {
            name: "tmp".into(),
            sanitized: false,
            def: Some(0),
            alias_of: None,
        },
    );
    file
}

fn bad_call_file() -> FileIR {
    let mut file = FileIR::new("bad".into(), "python".into());
    file.source = Some("v = mystery()\n".into());

    let mut ast = FileAst::new("bad".into(), "python".into());
    ast.push(AstNode {
        id: 0,
        parent: None,
        kind: "CallExpression".into(),
        value: json!(null),
        children: Vec::new(),
        meta: Meta {
            file: "bad".into(),
            line: 1,
            column: 1,
        },
    });
    file.ast = Some(ast);

    file.dfg = Some(DataFlowGraph {
        nodes: vec![DFNode {
            id: 0,
            name: "v".into(),
            kind: DFNodeKind::Def,
            sanitized: true,
            branch: None,
        }],
        edges: vec![],
        calls: vec![],
        call_returns: vec![(0, 999)],
        merges: vec![],
    });
    file.symbols.insert(
        "v".into(),
        Symbol {
            name: "v".into(),
            sanitized: true,
            def: Some(0),
            alias_of: None,
        },
    );
    file
}

#[test]
fn tracks_arg_and_return_taint() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_function_taints();
    let file = tainted_file();

    record_function_taints(&file).expect("record taints");

    let sink = get_function_taint("sink").expect("sink taint");
    assert!(sink.tainted_args.contains(&0));
    assert!(!sink.tainted_return);

    let source = get_function_taint("source").expect("source taint");
    assert!(source.tainted_return);
    assert!(source.tainted_args.is_empty());
}

#[test]
fn ignores_clean_arguments() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_function_taints();
    let file = clean_file();

    record_function_taints(&file).expect("record taints");

    assert!(get_function_taint("sink").is_none());
}

#[test]
fn accumulates_across_files() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_function_taints();
    let f1 = tainted_file();
    let f2 = clean_file();

    record_function_taints(&f1).expect("record taints");
    record_function_taints(&f2).expect("record taints");

    let sink = get_function_taint("sink").expect("persisted taint");
    assert!(sink.tainted_args.contains(&0));
}

#[test]
fn resets_between_scans() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let f1 = tainted_file();
    let f2 = clean_file();
    let rules = RuleSet::default();
    let cfg = EngineConfig::default();
    reset_function_taints();
    record_function_taints(&f1).expect("record taints");
    assert!(get_function_taint("sink").is_some());

    analyze_files_with_config(&[f2], &rules, &cfg, None, None);
    assert!(get_function_taint("sink").is_none());
}

#[test]
fn propagates_across_modules() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_function_taints();
    let src = tainted_file();
    let wrap = wrap_file();
    let main = main_file();

    record_function_taints(&src).expect("record taints");
    record_function_taints(&wrap).expect("record taints");
    record_function_taints(&main).expect("record taints");

    let sink = get_function_taint("sink").expect("cross-file taint");
    assert!(sink.tainted_args.contains(&0));
    let wrap = get_function_taint("wrap").expect("wrap taint");
    assert!(wrap.tainted_return);
}

#[test]
fn ignores_unknown_call_ids() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_function_taints();
    let file = bad_call_file();

    record_function_taints(&file).expect("record taints");

    assert!(all_function_taints().is_empty());
}

#[test]
fn parse_call_handles_nested_parentheses() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let (name, args) = parse_call("foo(bar(baz(1, 2)), qux(3, 4))").expect("parse call");
    assert_eq!(name, "foo");
    assert_eq!(args, vec!["bar(baz(1, 2))", "qux(3, 4)"],);
}

#[test]
fn parse_call_handles_generics() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let call = "foo(HashMap<String, Vec<(i32, i32)>>::new(), default())";
    let (name, args) = parse_call(call).expect("parse call");
    assert_eq!(name, "foo");
    assert_eq!(
        args,
        vec!["HashMap<String, Vec<(i32, i32)>>::new()", "default()",],
    );
}
