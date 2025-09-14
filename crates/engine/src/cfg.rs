//! Utilities for building and querying simplified control flow graphs
//! based on call expressions.

use ir::{AstNode, CFGNode, FileIR, CFG};

/// Builds a very simple CFG by collecting call expressions.
/// Each detected call is linked to the next in order, ignoring
/// branches, loops or other control structures. Only JavaScript/TypeScript
/// and Python files are supported.
pub fn build_cfg(file: &FileIR) -> Option<CFG> {
    match file.file_type.as_str() {
        "typescript" | "javascript" | "python" => {}
        _ => return None,
    }
    let ast = file.ast.as_ref()?;
    let src = file.source.as_deref().unwrap_or("");
    let src_lines = src.split('\n').collect::<Vec<_>>();
    let mut nodes = Vec::new();
    for node in &ast.nodes {
        collect_calls(node, &src_lines, &mut nodes);
    }
    let edges = nodes
        .iter()
        .zip(nodes.iter().skip(1))
        .map(|(a, b)| (a.id, b.id))
        .collect();
    Some(CFG { nodes, edges })
}

fn collect_calls(node: &AstNode, src_lines: &[&str], out: &mut Vec<CFGNode>) {
    if node.kind == "CallExpression" || node.kind == "Call" {
        let line = node.meta.line;
        let code = src_lines
            .get(line - 1)
            .copied()
            .unwrap_or("")
            .trim()
            .to_string();
        let id = out.len();
        out.push(CFGNode { id, line, code });
    }
    for child in &node.children {
        collect_calls(child, src_lines, out);
    }
}

/// Check if there is a path from request data to a response without sanitization.
pub fn has_unsanitized_route(file: &FileIR) -> bool {
    let ast = match &file.ast {
        Some(ast) => ast,
        None => return false,
    };
    let src = file.source.as_deref().unwrap_or("");

    match file.file_type.as_str() {
        "typescript" | "javascript" => ast.nodes.iter().any(|n| has_unsanitized_js_like(n, src)),
        "python" => ast.nodes.iter().any(|n| has_unsanitized_python(n, src)),
        _ => false,
    }
}

fn has_unsanitized_js_like(node: &AstNode, src: &str) -> bool {
    if node.kind == "CallExpression" {
        if let Some(func) = node.value.as_str() {
            if func == "res.send" {
                let has_req = find_ident(node, src, "req");
                let sanitized = subtree_has_call(node, "sanitize");
                return has_req && !sanitized;
            }
        }
    }
    node.children
        .iter()
        .any(|c| has_unsanitized_js_like(c, src))
}

fn has_unsanitized_python(node: &AstNode, src: &str) -> bool {
    if node.kind == "ReturnStatement" {
        let sanitized = subtree_has_call(node, "sanitize");
        let has_req = subtree_has_call_prefix(node, "request.") || find_ident(node, src, "request");
        return has_req && !sanitized;
    }
    node.children.iter().any(|c| has_unsanitized_python(c, src))
}

fn subtree_has_call(node: &AstNode, name: &str) -> bool {
    if (node.kind == "CallExpression" || node.kind == "Call") && node.value.as_str() == Some(name) {
        return true;
    }
    node.children.iter().any(|c| subtree_has_call(c, name))
}

fn subtree_has_call_prefix(node: &AstNode, prefix: &str) -> bool {
    if node.kind == "CallExpression" || node.kind == "Call" {
        if let Some(val) = node.value.as_str() {
            if val.starts_with(prefix) {
                return true;
            }
        }
    }
    node.children
        .iter()
        .any(|c| subtree_has_call_prefix(c, prefix))
}

fn find_ident(node: &AstNode, src: &str, target: &str) -> bool {
    if (node.kind == "Identifier" || node.kind == "PropertyIdentifier")
        && extract_ident(node, src) == target
    {
        return true;
    }
    node.children.iter().any(|c| find_ident(c, src, target))
}

fn extract_ident(node: &AstNode, src: &str) -> String {
    let line = node.meta.line;
    let col = node.meta.column;
    if let Some(text) = src.lines().nth(line - 1) {
        let start = col - 1;
        let ident: String = text[start..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        ident
    } else {
        String::new()
    }
}
