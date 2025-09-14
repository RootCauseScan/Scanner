use super::*;
use serde_json::{self, Value as JsonValue};
// Tests for JSON roundtrips of FileIR and AstNode.

#[test]
fn file_ir_serialization_preserves_meta() {
    let meta = Meta {
        file: "main.rs".into(),
        line: 1,
        column: 2,
    };
    let node = IRNode {
        id: 0,
        kind: "Kind".into(),
        path: "path".into(),
        value: JsonValue::String("value".into()),
        meta: meta.clone(),
    };
    let mut file_ir = FileIR::new("main.rs".into(), "rust".into());
    file_ir.push(node);

    let json = serde_json::to_string(&file_ir).unwrap();
    let v: JsonValue = serde_json::from_str(&json).unwrap();
    let meta_json = &v["nodes"][0]["meta"];
    assert_eq!(meta_json["file"], meta.file);
    assert_eq!(meta_json["line"], meta.line);
    assert_eq!(meta_json["column"], meta.column);

    let deser: FileIR = serde_json::from_str(&json).unwrap();
    let dmeta = &deser.nodes[0].meta;
    assert_eq!(dmeta.file, meta.file);
    assert_eq!(dmeta.line, meta.line);
    assert_eq!(dmeta.column, meta.column);
}

#[test]
fn ast_node_serialization_preserves_meta() {
    let meta = Meta {
        file: "lib.rs".into(),
        line: 10,
        column: 5,
    };
    let node = AstNode {
        id: 0,
        parent: None,
        kind: "Identifier".into(),
        value: JsonValue::String("x".into()),
        children: vec![],
        meta: meta.clone(),
    };

    let json = serde_json::to_string(&node).unwrap();
    let v: JsonValue = serde_json::from_str(&json).unwrap();
    let meta_json = &v["meta"];
    assert_eq!(meta_json["file"], meta.file);
    assert_eq!(meta_json["line"], meta.line);
    assert_eq!(meta_json["column"], meta.column);

    let deser: AstNode = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.meta.file, meta.file);
    assert_eq!(deser.meta.line, meta.line);
    assert_eq!(deser.meta.column, meta.column);
}

#[test]
fn file_ir_deserialization_fails_without_meta() {
    let json = r#"{\"file_path\":\"main.rs\",\"file_type\":\"rust\",\"nodes\":[{\"kind\":\"Kind\",\"path\":\"path\",\"value\":\"value\"}],\"ast\":null}"#;
    assert!(serde_json::from_str::<FileIR>(json).is_err());
}

#[test]
fn ast_node_deserialization_fails_without_meta() {
    let json =
        r#"{\"id\":0,\"parent\":null,\"kind\":\"Identifier\",\"value\":\"x\",\"children\":[]}"#;
    assert!(serde_json::from_str::<AstNode>(json).is_err());
}

#[test]
fn file_ast_parent_child_navigation() {
    let root_meta = Meta {
        file: "main.rs".into(),
        line: 1,
        column: 1,
    };
    let child_meta = Meta {
        file: "main.rs".into(),
        line: 2,
        column: 1,
    };
    let child = AstNode {
        id: 1,
        parent: Some(0),
        kind: "Child".into(),
        value: JsonValue::Null,
        children: vec![],
        meta: child_meta,
    };
    let root = AstNode {
        id: 0,
        parent: None,
        kind: "Root".into(),
        value: JsonValue::Null,
        children: vec![child],
        meta: root_meta,
    };
    let mut file_ast = FileAst::new("main.rs".into(), "rust".into());
    file_ast.push(root);
    let parent = file_ast.parent(1).expect("parent");
    assert_eq!(parent.kind, "Root");
    let children = file_ast.children(0);
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].id, 1);
    assert!(file_ast.parent(0).is_none());
    assert!(file_ast.children(1).is_empty());
    assert!(file_ast.parent(42).is_none());
    assert!(file_ast.children(42).is_empty());
}

#[test]
fn file_ir_symbol_metadata_roundtrip() {
    let mut fir = FileIR::new("main.rs".into(), "rust".into());
    fir.symbol_types
        .insert("user_input".into(), SymbolKind::Source);
    fir.symbol_scopes
        .insert("user_input".into(), "global".into());
    fir.symbol_modules
        .insert("user_input".into(), "mod_a".into());

    let json = serde_json::to_string(&fir).unwrap();
    let deser: FileIR = serde_json::from_str(&json).unwrap();
    assert_eq!(
        deser.symbol_types.get("user_input"),
        Some(&SymbolKind::Source)
    );
    assert_eq!(deser.symbol_scopes.get("user_input").unwrap(), "global");
    assert_eq!(deser.symbol_modules.get("user_input").unwrap(), "mod_a");
}

#[test]
fn file_ir_deserialization_fails_invalid_symbol_type() {
    let json = "{\"file_path\":\"a\",\"file_type\":\"rust\",\"nodes\":[],\"ast\":null,\"source\":null,\"suppressed\":[],\"dfg\":null,\"symbols\":{},\"symbol_types\":{\"x\":\"invalid\"},\"symbol_scopes\":{},\"symbol_modules\":{}}";
    assert!(serde_json::from_str::<FileIR>(json).is_err());
}
