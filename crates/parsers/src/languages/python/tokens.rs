use ir::{stable_id, FileIR, IRNode, Meta, Symbol};
use std::collections::HashMap;
use std::path::{Component, Path};

use super::symbol_table::resolve_alias;

pub(crate) fn canonical_call_path(raw: &str, symbols: &HashMap<String, Symbol>) -> String {
    let segments: Vec<&str> = raw.split('.').collect();
    if segments.is_empty() {
        return raw.to_string();
    }
    let first = resolve_alias(segments[0], symbols);
    let mut parts: Vec<String> = first.split('.').map(|s| s.to_string()).collect();
    for seg in segments.into_iter().skip(1) {
        parts.push(seg.to_string());
    }
    parts.join(".")
}

pub(crate) fn walk_ir(node: tree_sitter::Node, src: &str, fir: &mut FileIR) {
    match node.kind() {
        "call" => {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(raw) = func.utf8_text(src.as_bytes()) {
                    let id = canonical_call_path(raw, &fir.symbols);
                    let pos = node.start_position();
                    let meta = Meta {
                        file: fir.file_path.clone(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                    };
                    let path = format!("call.{id}");
                    let nid = stable_id(&fir.file_path, meta.line, meta.column, &path);
                    fir.push(IRNode {
                        id: nid,
                        kind: "python".to_string(),
                        path,
                        value: serde_json::Value::Null,
                        meta,
                    });
                    let tail = id.rsplit('.').next().unwrap_or(&id);
                    if tail == "getattr" || tail == "setattr" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut ac = args.walk();
                            let arg_nodes: Vec<tree_sitter::Node> =
                                args.named_children(&mut ac).collect();
                            if arg_nodes.len() >= 2 && arg_nodes[1].kind() == "string" {
                                if let (Ok(obj), Ok(attr)) = (
                                    arg_nodes[0].utf8_text(src.as_bytes()),
                                    arg_nodes[1].utf8_text(src.as_bytes()),
                                ) {
                                    let attr_name = attr.trim_matches(['"', '\'']).to_string();
                                    let path = format!("{tail}.{obj}.{attr_name}");
                                    let meta = Meta {
                                        file: fir.file_path.clone(),
                                        line: pos.row + 1,
                                        column: pos.column + 1,
                                    };
                                    let nid =
                                        stable_id(&fir.file_path, meta.line, meta.column, &path);
                                    fir.push(IRNode {
                                        id: nid,
                                        kind: "python".to_string(),
                                        path,
                                        value: serde_json::Value::Null,
                                        meta,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        "assignment" => {
            if let Some(left) = node.child_by_field_name("left") {
                if let Ok(id) = left.utf8_text(src.as_bytes()) {
                    if let Some(right) = node.child_by_field_name("right") {
                        if right.kind() == "string" {
                            let pos = node.start_position();
                            let meta = Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            };
                            let path = format!("assign.{id}");
                            let nid = stable_id(&fir.file_path, meta.line, meta.column, &path);
                            fir.push(IRNode {
                                id: nid,
                                kind: "python".to_string(),
                                path,
                                value: serde_json::Value::Null,
                                meta,
                            });
                        }
                    }
                }
            }
        }
        "import_statement" => {
            fn handle_import(node: tree_sitter::Node, src: &str, fir: &mut FileIR) {
                match node.kind() {
                    "dotted_name" => {
                        if let Ok(name) = node.utf8_text(src.as_bytes()) {
                            let pos = node.start_position();
                            let path = format!("import.{name}");
                            let meta = Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            };
                            let nid = stable_id(&fir.file_path, meta.line, meta.column, &path);
                            fir.push(IRNode {
                                id: nid,
                                kind: "python".to_string(),
                                path,
                                value: serde_json::Value::Null,
                                meta,
                            });
                        }
                    }
                    "aliased_import" => {
                        if let Some(name_node) = node.child_by_field_name("name") {
                            if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                                let alias = node
                                    .child_by_field_name("alias")
                                    .and_then(|a| a.utf8_text(src.as_bytes()).ok())
                                    .map(str::to_string);
                                let pos = node.start_position();
                                let path = format!("import.{name}");
                                let meta = Meta {
                                    file: fir.file_path.clone(),
                                    line: pos.row + 1,
                                    column: pos.column + 1,
                                };
                                let nid = stable_id(&fir.file_path, meta.line, meta.column, &path);
                                fir.push(IRNode {
                                    id: nid,
                                    kind: "python".to_string(),
                                    path,
                                    value: alias
                                        .as_ref()
                                        .map_or(serde_json::Value::Null, |a| serde_json::json!(a)),
                                    meta,
                                });
                                if let Some(a) = alias {
                                    let target = name.to_string();
                                    fir.symbols.insert(
                                        a.clone(),
                                        Symbol {
                                            name: a,
                                            sanitized: false,
                                            def: None,
                                            alias_of: Some(target),
                                        },
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            let mut cursor2 = node.walk();
            for child in node.children(&mut cursor2) {
                if child.kind() == "import_list" {
                    let mut cursor3 = child.walk();
                    for grand in child.children(&mut cursor3) {
                        handle_import(grand, src, fir);
                    }
                } else {
                    handle_import(child, src, fir);
                }
            }
        }
        "import_from_statement" => {
            fn handle_import(child: tree_sitter::Node, module: &str, src: &str, fir: &mut FileIR) {
                // handle wildcard imports like `from module import *`
                if let Ok("*") = child.utf8_text(src.as_bytes()) {
                    let pos = child.start_position();
                    let path = if module.is_empty() {
                        "import_from.*".to_string()
                    } else {
                        format!("import_from.{module}.*")
                    };
                    let meta = Meta {
                        file: fir.file_path.clone(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                    };
                    let nid = stable_id(&fir.file_path, meta.line, meta.column, &path);
                    fir.push(IRNode {
                        id: nid,
                        kind: "python".to_string(),
                        path,
                        value: serde_json::Value::Null,
                        meta,
                    });
                    return;
                }
                match child.kind() {
                    "dotted_name" => {
                        if let Ok(name) = child.utf8_text(src.as_bytes()) {
                            let pos = child.start_position();
                            let path = if module.is_empty() {
                                format!("import_from.{name}")
                            } else {
                                format!("import_from.{module}.{name}")
                            };
                            let meta = Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            };
                            let nid = stable_id(&fir.file_path, meta.line, meta.column, &path);
                            fir.push(IRNode {
                                id: nid,
                                kind: "python".to_string(),
                                path,
                                value: serde_json::Value::Null,
                                meta,
                            });
                            let target = if module.is_empty() {
                                name.to_string()
                            } else {
                                format!("{module}.{name}")
                            };
                            fir.symbols.insert(
                                name.to_string(),
                                Symbol {
                                    name: name.to_string(),
                                    sanitized: false,
                                    def: None,
                                    alias_of: Some(target),
                                },
                            );
                        }
                    }
                    "aliased_import" => {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                                let alias = child
                                    .child_by_field_name("alias")
                                    .and_then(|a| a.utf8_text(src.as_bytes()).ok())
                                    .map(str::to_string);
                                let pos = child.start_position();
                                let path = if module.is_empty() {
                                    format!("import_from.{name}")
                                } else {
                                    format!("import_from.{module}.{name}")
                                };
                                let meta = Meta {
                                    file: fir.file_path.clone(),
                                    line: pos.row + 1,
                                    column: pos.column + 1,
                                };
                                let nid = stable_id(&fir.file_path, meta.line, meta.column, &path);
                                fir.push(IRNode {
                                    id: nid,
                                    kind: "python".to_string(),
                                    path,
                                    value: alias
                                        .as_ref()
                                        .map_or(serde_json::Value::Null, |a| serde_json::json!(a)),
                                    meta,
                                });
                                if let Some(a) = alias {
                                    let target = if module.is_empty() {
                                        name.to_string()
                                    } else {
                                        format!("{module}.{name}")
                                    };
                                    fir.symbols.insert(
                                        a.clone(),
                                        Symbol {
                                            name: a,
                                            sanitized: false,
                                            def: None,
                                            alias_of: Some(target),
                                        },
                                    );
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            let mut module_name = String::new();
            let mut relative_level = 0usize;
            let mut imports: Vec<tree_sitter::Node> = Vec::new();
            let mut in_import_list = false;
            let mut cursor2 = node.walk();
            for child in node.children(&mut cursor2) {
                match child.kind() {
                    "relative_import" => {
                        if let Ok(txt) = child.utf8_text(src.as_bytes()) {
                            relative_level = txt.chars().filter(|&c| c == '.').count();
                        }
                        let mut rc = child.walk();
                        for grand in child.children(&mut rc) {
                            if grand.kind() == "dotted_name" {
                                if let Ok(m) = grand.utf8_text(src.as_bytes()) {
                                    module_name = m.to_string();
                                }
                            }
                        }
                    }
                    "dotted_name" if !in_import_list && module_name.is_empty() => {
                        if let Ok(m) = child.utf8_text(src.as_bytes()) {
                            module_name = m.to_string();
                        }
                    }
                    "import" => {
                        in_import_list = true;
                    }
                    _ if in_import_list => imports.push(child),
                    _ => {}
                }
            }

            let base_module = if relative_level > 0 {
                let mut comps: Vec<String> = Path::new(&fir.file_path)
                    .parent()
                    .map(|p| {
                        p.components()
                            .filter_map(|c| match c {
                                Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                                _ => None,
                            })
                            .collect::<Vec<String>>()
                    })
                    .unwrap_or_default();
                let remove = relative_level.min(comps.len());
                comps.truncate(comps.len().saturating_sub(remove));
                comps.join(".")
            } else {
                String::new()
            };

            let full_module = if module_name.is_empty() {
                base_module.clone()
            } else if base_module.is_empty() {
                module_name.clone()
            } else {
                format!("{base_module}.{module_name}")
            };

            for child in imports {
                if child.kind() == "import_list" {
                    let mut cursor3 = child.walk();
                    for grand in child.children(&mut cursor3) {
                        handle_import(grand, &full_module, src, fir);
                    }
                } else {
                    handle_import(child, &full_module, src, fir);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ir(child, src, fir);
    }
}
