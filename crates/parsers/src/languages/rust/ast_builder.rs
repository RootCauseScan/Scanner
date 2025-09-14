use ir::{AstNode, Meta};

fn to_camel(kind: &str) -> String {
    let mut out = String::new();
    let mut up = true;
    for ch in kind.chars() {
        if ch == '_' {
            up = true;
        } else if up {
            out.push(ch.to_ascii_uppercase());
            up = false;
        } else {
            out.push(ch);
        }
    }
    out
}

pub(super) fn walk_ast(
    node: tree_sitter::Node,
    src: &str,
    file: &str,
    counter: &mut usize,
    parent: Option<usize>,
) -> AstNode {
    let id = *counter;
    *counter += 1;
    let kind = to_camel(node.kind());
    let mut value = serde_json::Value::Null;
    if kind == "FunctionItem" {
        if let Some(name) = node.child_by_field_name("name") {
            if let Ok(id) = name.utf8_text(src.as_bytes()) {
                value = serde_json::json!(id);
            }
        }
    } else if kind == "CallExpression" {
        if let Some(func) = node.child_by_field_name("function") {
            let id = match func.kind() {
                "field_expression" => func
                    .child_by_field_name("field")
                    .and_then(|f| f.utf8_text(src.as_bytes()).ok())
                    .map(|s| s.to_string()),
                _ => func.utf8_text(src.as_bytes()).ok().map(|s| s.to_string()),
            };
            if let Some(id) = id {
                value = serde_json::json!(id);
            }
        }
    } else if kind == "LetDeclaration" {
        if let Some(pat) = node.child_by_field_name("pattern") {
            if pat.kind() == "identifier" {
                if let Ok(id) = pat.utf8_text(src.as_bytes()) {
                    value = serde_json::json!(id);
                }
            }
        }
    }
    let pos = node.start_position();
    let mut children = Vec::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        children.push(walk_ast(child, src, file, counter, Some(id)));
    }
    AstNode {
        id,
        parent,
        kind,
        value,
        children,
        meta: Meta {
            file: file.to_string(),
            line: pos.row + 1,
            column: pos.column + 1,
        },
    }
}
