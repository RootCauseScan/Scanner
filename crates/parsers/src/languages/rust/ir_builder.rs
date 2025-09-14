use super::imports::{canonical_call_path, walk_use};
use super::symbols::mark_symbol_type;
use ir::{FileIR, IRNode, Meta};
use std::collections::HashMap;

pub(super) fn walk_ir(
    node: tree_sitter::Node,
    src: &str,
    fir: &mut FileIR,
    namespace: &mut Vec<String>,
    imports: &mut HashMap<String, String>,
) {
    match node.kind() {
        "mod_item" => {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(id) = name.utf8_text(src.as_bytes()) {
                    namespace.push(id.to_string());
                    if let Some(body) = node.child_by_field_name("body") {
                        walk_ir(body, src, fir, namespace, imports);
                    }
                    namespace.pop();
                    return;
                }
            }
        }
        "function_item" => {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(id) = name.utf8_text(src.as_bytes()) {
                    let pos = node.start_position();
                    fir.push(IRNode {
                        id: 0,
                        kind: "rust".to_string(),
                        path: format!("function.{id}"),
                        value: serde_json::Value::Null,
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
                }
            }
        }
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                let id = match func.kind() {
                    "field_expression" => func
                        .child_by_field_name("field")
                        .and_then(|f| f.utf8_text(src.as_bytes()).ok())
                        .map(|s| s.to_string()),
                    _ => func.utf8_text(src.as_bytes()).ok().map(|s| s.to_string()),
                };
                if let Some(id) = id {
                    let id = canonical_call_path(&id, namespace, imports);
                    let pos = node.start_position();
                    if let Some(name) = id.rsplit("::").next() {
                        mark_symbol_type(fir, name);
                    }
                    fir.push(IRNode {
                        id: 0,
                        kind: "rust".to_string(),
                        path: format!("call.{id}"),
                        value: serde_json::Value::Null,
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
                }
            }
        }
        "macro_invocation" => {
            if let Some(mac) = node.child_by_field_name("macro") {
                if let Ok(id) = mac.utf8_text(src.as_bytes()) {
                    let pos = node.start_position();
                    fir.push(IRNode {
                        id: 0,
                        kind: "rust".to_string(),
                        path: format!("macro.{id}"),
                        value: serde_json::Value::Null,
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
                }
            }
        }
        "macro_definition" => {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(id) = name.utf8_text(src.as_bytes()) {
                    let pos = node.start_position();
                    fir.push(IRNode {
                        id: 0,
                        kind: "rust".to_string(),
                        path: format!("macro_rules.{id}"),
                        value: serde_json::Value::Null,
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
                }
            }
        }
        "use_declaration" => {
            if let Some(arg) = node.child_by_field_name("argument") {
                walk_use(arg, String::new(), src, fir, imports);
            }
        }
        "let_declaration" => {
            if let Some(pat) = node.child_by_field_name("pattern") {
                if pat.kind() == "identifier" {
                    if let Ok(id) = pat.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "rust".to_string(),
                            path: format!("assign.{id}"),
                            value: serde_json::Value::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                    }
                }
            }
        }
        "unsafe_block" => {
            let pos = node.start_position();
            fir.push(IRNode {
                id: 0,
                kind: "rust".to_string(),
                path: "unsafe".to_string(),
                value: serde_json::Value::Null,
                meta: Meta {
                    file: fir.file_path.clone(),
                    line: pos.row + 1,
                    column: pos.column + 1,
                },
            });
        }
        "unsafe" => {
            if node.parent().map(|p| p.kind()) != Some("unsafe_block") {
                let pos = node.start_position();
                fir.push(IRNode {
                    id: 0,
                    kind: "rust".to_string(),
                    path: "unsafe".to_string(),
                    value: serde_json::Value::Null,
                    meta: Meta {
                        file: fir.file_path.clone(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                    },
                });
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ir(child, src, fir, namespace, imports);
    }
}
