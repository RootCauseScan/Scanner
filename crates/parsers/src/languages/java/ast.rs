use ir::{AstNode, FileAst, Meta};
use tree_sitter::Node;

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

fn walk_ast(
    node: Node,
    src: &str,
    file: &str,
    counter: &mut usize,
    parent: Option<usize>,
) -> AstNode {
    let id = *counter;
    *counter += 1;
    let kind = to_camel(node.kind());
    let mut value = serde_json::Value::Null;
    if kind == "MethodDeclaration" {
        if let Some(name) = node.child_by_field_name("name") {
            if let Ok(n) = name.utf8_text(src.as_bytes()) {
                value = serde_json::json!(n);
            }
        }
    } else if kind == "MethodInvocation" {
        if let Some(call) = extract_call_path(node, src) {
            value = serde_json::json!(call);
        }
    } else if kind == "LocalVariableDeclaration" {
        if let Some(var) = node
            .child_by_field_name("declarators")
            .and_then(|d| d.child(0))
            .and_then(|v| v.child_by_field_name("name"))
        {
            if let Ok(n) = var.utf8_text(src.as_bytes()) {
                value = serde_json::json!(n);
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

fn walk_ast_tolerant(node: Node, src: &str, file: &str, counter: &mut usize, out: &mut FileAst) {
    if node.is_error() {
        return;
    }
    if node.has_error() {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_ast_tolerant(child, src, file, counter, out);
        }
    } else {
        out.push(walk_ast(node, src, file, counter, None));
    }
}

pub fn build_ast(root: Node, content: &str, file_path: &str) -> FileAst {
    let mut file_ast = FileAst::new(file_path.to_string(), "java".into());
    let mut counter = 0usize;
    let has_errors = root.has_error() || root.is_error();

    if has_errors {
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            walk_ast_tolerant(child, content, file_path, &mut counter, &mut file_ast);
        }
    } else {
        let mut cursor = root.walk();
        for child in root.children(&mut cursor) {
            file_ast.push(walk_ast(child, content, file_path, &mut counter, None));
        }
    }

    file_ast
}
