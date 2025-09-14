use super::*;
use ir::{AstNode, FileAst, Meta};

#[test]
fn builds_cfg_nodes_with_source_lines() {
    let mut ast = FileAst::new("/tmp/test.ts".into(), "typescript".into());
    ast.push(AstNode {
        id: 0,
        parent: None,
        kind: "CallExpression".into(),
        value: serde_json::Value::Null,
        children: vec![],
        meta: Meta {
            file: "/tmp/test.ts".into(),
            line: 1,
            column: 1,
        },
    });
    ast.push(AstNode {
        id: 1,
        parent: None,
        kind: "CallExpression".into(),
        value: serde_json::Value::Null,
        children: vec![],
        meta: Meta {
            file: "/tmp/test.ts".into(),
            line: 2,
            column: 1,
        },
    });
    let mut file = FileIR::new("/tmp/test.ts".into(), "typescript".into());
    file.ast = Some(ast);
    file.source = Some("foo();\nbar();\n".into());

    let cfg = build_cfg(&file).expect("cfg");
    assert_eq!(cfg.nodes.len(), 2);
    assert_eq!(cfg.nodes[0].line, 1);
    assert_eq!(cfg.nodes[0].code, "foo();");
    assert_eq!(cfg.nodes[1].line, 2);
    assert_eq!(cfg.nodes[1].code, "bar();");
    assert_eq!(cfg.edges, vec![(0, 1)]);
}
