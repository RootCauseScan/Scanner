use ir::{FileIR, IRNode, Meta};
use std::collections::HashMap;

pub(super) fn walk_use(
    node: tree_sitter::Node,
    prefix: String,
    src: &str,
    fir: &mut FileIR,
    imports: &mut HashMap<String, String>,
) {
    match node.kind() {
        "use_list" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.is_named() {
                    walk_use(child, prefix.clone(), src, fir, imports);
                }
            }
        }
        "scoped_use_list" => {
            let mut new_prefix = prefix;
            if let Some(pn) = node.child_by_field_name("path") {
                if let Some(p) = build_path(pn, src) {
                    new_prefix = if new_prefix.is_empty() {
                        p
                    } else {
                        format!("{new_prefix}::{p}")
                    };
                }
            }
            if let Some(list) = node.child_by_field_name("list") {
                walk_use(list, new_prefix, src, fir, imports);
            }
        }
        "use_as_clause" => {
            let path_node = node.child_by_field_name("path");
            let alias_node = node.child_by_field_name("alias");
            if let Some(pn) = path_node {
                if let Some(orig) = build_path(pn, src) {
                    let full = if orig == "self" {
                        prefix.clone()
                    } else if prefix.is_empty() {
                        orig
                    } else {
                        format!("{prefix}::{orig}")
                    };
                    let alias = alias_node.and_then(|a| a.utf8_text(src.as_bytes()).ok());
                    push_import(full, alias.map(|s| s.to_string()), node, fir, imports);
                }
            }
        }
        "use_wildcard" => {
            if let Some(pn) = node.child_by_field_name("path") {
                if let Some(base) = build_path(pn, src) {
                    let full = if prefix.is_empty() {
                        format!("{base}::*")
                    } else {
                        format!("{prefix}::{base}::*")
                    };
                    push_import(full, None, node, fir, imports);
                }
            }
        }
        "scoped_identifier" => {
            let mut new_prefix = prefix;
            if let Some(pn) = node.child_by_field_name("path") {
                if let Some(p) = build_path(pn, src) {
                    new_prefix = if new_prefix.is_empty() {
                        p
                    } else {
                        format!("{new_prefix}::{p}")
                    };
                }
            }
            if let Some(nn) = node.child_by_field_name("name") {
                walk_use(nn, new_prefix, src, fir, imports);
            }
        }
        "identifier" => {
            if let Ok(id) = node.utf8_text(src.as_bytes()) {
                let full = if id == "self" {
                    prefix
                } else if prefix.is_empty() {
                    id.to_string()
                } else {
                    format!("{prefix}::{id}")
                };
                push_import(full, None, node, fir, imports);
            }
        }
        "self" => {
            let full = prefix;
            push_import(full, None, node, fir, imports);
        }
        _ => {}
    }
}

pub(super) fn canonical_call_path(
    raw: &str,
    namespace: &[String],
    imports: &HashMap<String, String>,
) -> String {
    let segments: Vec<&str> = raw.split("::").collect();
    if segments.is_empty() {
        return raw.to_string();
    }
    match segments[0] {
        "self" => {
            let mut out: Vec<String> = namespace.to_vec();
            out.extend(segments.iter().skip(1).map(|s| s.to_string()));
            return out.join("::");
        }
        "super" => {
            let mut out: Vec<String> = if namespace.is_empty() {
                Vec::new()
            } else {
                namespace[..namespace.len() - 1].to_vec()
            };
            out.extend(segments.iter().skip(1).map(|s| s.to_string()));
            return out.join("::");
        }
        "crate" => {
            return segments
                .iter()
                .skip(1)
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join("::");
        }
        first => {
            if let Some(mapped) = imports.get(first) {
                let mut out: Vec<String> = mapped.split("::").map(|s| s.to_string()).collect();
                out.extend(segments.iter().skip(1).map(|s| s.to_string()));
                return out.join("::");
            }
        }
    }
    if segments.len() == 1 {
        if let Some(mapped) = imports.get(segments[0]) {
            return mapped.clone();
        }
        if !namespace.is_empty() {
            let mut out: Vec<String> = namespace.to_vec();
            out.push(segments[0].to_string());
            return out.join("::");
        }
    }
    raw.to_string()
}

fn push_import(
    path: String,
    alias: Option<String>,
    node: tree_sitter::Node,
    fir: &mut FileIR,
    imports: &mut HashMap<String, String>,
) {
    let mapping_path = path.clone();
    let pos = node.start_position();
    fir.push(IRNode {
        id: 0,
        kind: "rust".to_string(),
        path: format!("import.{path}"),
        value: match &alias {
            Some(a) => serde_json::json!(a),
            None => serde_json::Value::Null,
        },
        meta: Meta {
            file: fir.file_path.clone(),
            line: pos.row + 1,
            column: pos.column + 1,
        },
    });
    let key = alias.clone().or_else(|| {
        if mapping_path.ends_with("::*") {
            None
        } else {
            mapping_path.split("::").last().map(|s| s.to_string())
        }
    });
    if let Some(k) = key {
        imports.insert(k, mapping_path);
    }
}

fn build_path(node: tree_sitter::Node, src: &str) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(src.as_bytes()).ok().map(|s| s.to_string()),
        "scoped_identifier" => {
            let mut parts = Vec::new();
            if let Some(path) = node.child_by_field_name("path") {
                if let Some(p) = build_path(path, src) {
                    parts.push(p);
                }
            }
            if let Some(name) = node.child_by_field_name("name") {
                if let Some(n) = build_path(name, src) {
                    parts.push(n);
                }
            }
            Some(parts.join("::"))
        }
        _ => node.utf8_text(src.as_bytes()).ok().map(|s| s.to_string()),
    }
}
