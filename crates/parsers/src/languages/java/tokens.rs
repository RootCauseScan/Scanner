use ir::{IRNode, Meta};
use std::collections::HashMap;
use tree_sitter::Node;

fn node_text(node: Node, src: &str) -> Option<String> {
    node.utf8_text(src.as_bytes())
        .ok()
        .map(|s| s.trim().to_string())
}

fn string_literal_value(node: Node, src: &str) -> Option<String> {
    if node.kind() != "string_literal" {
        return None;
    }
    let raw = node.utf8_text(src.as_bytes()).ok()?.trim().to_string();
    let bytes = raw.as_bytes();
    if bytes.len() < 2 {
        return None;
    }
    let quote = bytes[0];
    if (quote == b'"' && bytes.last() == Some(&b'"'))
        || (quote == b'\'' && bytes.last() == Some(&b'\''))
    {
        let inner = &raw[1..raw.len() - 1];
        // basic unescape for quotes commonly used in reflection literals.
        Some(inner.replace("\\\"", "\"").replace("\\'", "'"))
    } else {
        Some(raw)
    }
}

fn first_string_argument(node: Node, src: &str) -> Option<String> {
    let args = node.child_by_field_name("arguments")?;
    let mut cursor = args.walk();
    for arg in args.children(&mut cursor).filter(|n| n.is_named()) {
        if let Some(val) = string_literal_value(arg, src) {
            return Some(val);
        }
    }
    None
}

fn extract_inline_string(text: &str) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut idx = 0;
    while idx < chars.len() {
        let ch = chars[idx];
        if ch == '"' || ch == '\'' {
            let quote = ch;
            let mut j = idx + 1;
            while j < chars.len() {
                if chars[j] == quote && (j == idx + 1 || chars[j - 1] != '\\') {
                    let segment: String = chars[idx + 1..j].iter().collect();
                    return Some(segment.replace("\\\"", "\"").replace("\\'", "'"));
                }
                j += 1;
            }
            break;
        }
        idx += 1;
    }
    None
}

fn reflection_metadata(node: Node, src: &str) -> Option<(&'static str, String)> {
    let method_name = node
        .child_by_field_name("name")
        .and_then(|n| node_text(n, src))?;
    let object_text = node
        .child_by_field_name("object")
        .and_then(|n| node_text(n, src));

    match method_name.as_str() {
        "forName" => {
            let object = object_text.as_deref()?;
            if object != "Class" && !object.ends_with("Class") {
                return None;
            }
            let target = first_string_argument(node, src)
                .or_else(|| object_text.clone())
                .unwrap_or_else(|| "unknown".to_string());
            Some(("for_name", target))
        }
        "loadClass" => {
            let object = object_text.as_deref()?;
            if !object.contains("ClassLoader") {
                return None;
            }
            let target = first_string_argument(node, src)
                .or_else(|| object_text.clone())
                .unwrap_or_else(|| "unknown".to_string());
            Some(("load_class", target))
        }
        "newInstance" => {
            let object = object_text.as_deref().unwrap_or("unknown");
            if !object.contains("Constructor")
                && !object.contains("getConstructor")
                && !object.contains("getDeclaredConstructor")
                && object != "Class"
            {
                return None;
            }
            let target = extract_inline_string(object)
                .or_else(|| first_string_argument(node, src))
                .unwrap_or_else(|| object.to_string());
            Some(("new_instance", target))
        }
        "invoke" => {
            let object = object_text.as_deref().unwrap_or("unknown");
            let lower = object.to_ascii_lowercase();
            if !object.contains("Method")
                && !object.contains("getMethod")
                && !object.contains("getDeclaredMethod")
                && !lower.contains("method")
            {
                return None;
            }
            let target = extract_inline_string(object)
                .or_else(|| first_string_argument(node, src))
                .unwrap_or_else(|| object.to_string());
            Some(("invoke", target))
        }
        _ => None,
    }
}

fn extract_call_path(node: Node, src: &str) -> Option<String> {
    if node.kind() != "method_invocation" {
        return None;
    }
    let mut name = String::new();
    if let Some(obj) = node.child_by_field_name("object") {
        if let Ok(t) = obj.utf8_text(src.as_bytes()) {
            name.push_str(t);
            name.push('.');
        }
    }
    if let Some(id) = node.child_by_field_name("name") {
        if let Ok(t) = id.utf8_text(src.as_bytes()) {
            name.push_str(t);
        }
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn resolve_import(
    path: &str,
    imports: &HashMap<String, String>,
    wildcards: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((first, rest)) = path.split_once('.') {
        if let Some(full) = imports.get(first) {
            out.push(format!("{full}.{rest}"));
        } else if !wildcards.iter().any(|w| w == first) {
            for pkg in wildcards {
                out.push(format!("{pkg}.{path}"));
            }
        }
    } else if let Some(full) = imports.get(path) {
        out.push(full.clone());
    }
    out
}

pub fn walk_ir(
    node: Node,
    src: &str,
    fir: &mut ir::FileIR,
    imports: &mut HashMap<String, String>,
    wildcards: &mut Vec<String>,
) {
    match node.kind() {
        "import_declaration" => {
            if let Ok(text) = node.utf8_text(src.as_bytes()) {
                let mut raw = text.trim_start_matches("import").trim();
                let is_static = raw.starts_with("static ");
                if is_static {
                    raw = raw.trim_start_matches("static").trim();
                }
                let path = raw.trim_end_matches(';').trim();
                if !path.is_empty() {
                    let kind = match (is_static, path.ends_with(".*")) {
                        (false, false) => "normal",
                        (false, true) => "wildcard",
                        (true, false) => "static",
                        (true, true) => "static_wildcard",
                    };
                    if path.ends_with(".*") {
                        wildcards.push(path.trim_end_matches(".*").to_string());
                        let key = path.to_string();
                        fir.symbols.entry(key.clone()).or_insert(ir::Symbol {
                            name: key.clone(),
                            sanitized: false,
                            def: None,
                            alias_of: Some(path.to_string()),
                        });
                        fir.symbol_modules.insert(key.clone(), path.to_string());
                        fir.symbol_scopes
                            .insert(key.clone(), format!("import|{kind}|{path}"));
                    } else {
                        let alias = path.rsplit('.').next().unwrap_or(path).to_string();
                        imports.insert(alias.clone(), path.to_string());
                        fir.symbols.entry(alias.clone()).or_insert(ir::Symbol {
                            name: alias.clone(),
                            sanitized: false,
                            def: None,
                            alias_of: Some(path.to_string()),
                        });
                        fir.symbol_modules.insert(alias.clone(), path.to_string());
                        fir.symbol_scopes
                            .insert(alias.clone(), format!("import|{kind}|{path}"));
                    }
                    let pos = node.start_position();
                    fir.push(IRNode {
                        id: 0,
                        kind: "java".into(),
                        path: format!("import.{path}"),
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
        "method_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                    let pos = name_node.start_position();
                    fir.push(IRNode {
                        id: 0,
                        kind: "java".into(),
                        path: format!("function.{name}"),
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
        "method_invocation" => {
            if let Some(path) = extract_call_path(node, src) {
                let pos = node.start_position();
                fir.push(IRNode {
                    id: 0,
                    kind: "java".into(),
                    path: format!("call.{path}"),
                    value: serde_json::Value::Null,
                    meta: Meta {
                        file: fir.file_path.clone(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                    },
                });
                for full in resolve_import(&path, imports, wildcards) {
                    fir.push(IRNode {
                        id: 0,
                        kind: "java".into(),
                        path: format!("call.{full}"),
                        value: serde_json::Value::Null,
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
                }
                if let Some((kind, target)) = reflection_metadata(node, src) {
                    fir.push(IRNode {
                        id: 0,
                        kind: "java".into(),
                        path: format!("call.reflect.{kind}.target"),
                        value: serde_json::Value::String(target),
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
                }
            }
        }
        "object_creation_expression" => {
            if let Some(type_node) = node.child_by_field_name("type") {
                if let Ok(type_name) = type_node.utf8_text(src.as_bytes()) {
                    let pos = node.start_position();
                    let path = format!("new {}", type_name);
                    fir.push(IRNode {
                        id: 0,
                        kind: "java".into(),
                        path: format!("call.{path}"),
                        value: serde_json::Value::Null,
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
                    for full in resolve_import(type_name, imports, wildcards) {
                        let full_path = format!("new {}", full);
                        fir.push(IRNode {
                            id: 0,
                            kind: "java".into(),
                            path: format!("call.{full_path}"),
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
        "assignment_expression" => {
            if let Some(left) = node.child_by_field_name("left") {
                if let Ok(var) = left.utf8_text(src.as_bytes()) {
                    let pos = left.start_position();
                    fir.push(IRNode {
                        id: 0,
                        kind: "java".into(),
                        path: format!("assign.{var}"),
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
        "local_variable_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(var) = name_node.utf8_text(src.as_bytes()) {
                            let pos = name_node.start_position();
                            fir.push(IRNode {
                                id: 0,
                                kind: "java".into(),
                                path: format!("assign.{var}"),
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
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ir(child, src, fir, imports, wildcards);
    }
}

pub fn walk_ir_tolerant(
    node: Node,
    src: &str,
    fir: &mut ir::FileIR,
    imports: &mut HashMap<String, String>,
    wildcards: &mut Vec<String>,
) {
    if node.is_error() {
        return;
    }
    if node.has_error() {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_ir_tolerant(child, src, fir, imports, wildcards);
        }
    } else {
        walk_ir(node, src, fir, imports, wildcards);
    }
}
