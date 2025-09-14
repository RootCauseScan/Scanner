use ir::{AstNode, FileAst, Meta};

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

fn walk_ast(
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
    if kind == "Call" {
        if let Some(func) = node.child_by_field_name("function") {
            if let Ok(id) = func.utf8_text(src.as_bytes()) {
                value = serde_json::json!(id);
            }
        }
    } else if kind == "Assignment" {
        if let Some(left) = node.child_by_field_name("left") {
            if let Ok(id) = left.utf8_text(src.as_bytes()) {
                if let Some(right) = node.child_by_field_name("right") {
                    if right.kind() == "string" {
                        value = serde_json::json!(id);
                    }
                }
            }
        }
    } else if kind == "FunctionDefinition" {
        if let Some(name) = node.child_by_field_name("name") {
            if let Ok(id) = name.utf8_text(src.as_bytes()) {
                value = serde_json::json!(id);
            }
        }
    } else if kind == "ImportStatement" || kind == "ImportFromStatement" {
        if let Ok(text) = node.utf8_text(src.as_bytes()) {
            value = serde_json::json!(text.trim());
        }
    } else if kind == "AliasedImport" {
        if let Some(alias) = node.child_by_field_name("alias") {
            if let Ok(id) = alias.utf8_text(src.as_bytes()) {
                value = serde_json::json!(id);
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

pub(crate) fn build_ast(root: tree_sitter::Node, src: &str, file: &str) -> FileAst {
    let mut file_ast = FileAst::new(file.to_string(), "python".into());
    let mut cursor = root.walk();
    let mut counter = 0usize;
    for child in root.children(&mut cursor) {
        file_ast.push(walk_ast(child, src, file, &mut counter, None));
    }
    file_ast
}
