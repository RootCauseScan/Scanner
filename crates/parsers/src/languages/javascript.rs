use ir::{AstNode, DFNode, DFNodeKind, DataFlowGraph, FileAst, FileIR, IRNode, Meta, Symbol};
use std::collections::HashMap;

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

fn node_text(node: tree_sitter::Node, src: &str) -> Option<String> {
    node.utf8_text(src.as_bytes())
        .ok()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn expression_name(node: tree_sitter::Node, src: &str) -> Option<String> {
    match node.kind() {
        "identifier" | "property_identifier" | "private_property_identifier" => {
            node_text(node, src)
        }
        "this" | "super" => Some(node.kind().to_string()),
        "member_expression" => {
            let object = node
                .child_by_field_name("object")
                .and_then(|child| expression_name(child, src));
            let property = node
                .child_by_field_name("property")
                .and_then(|child| expression_name(child, src));
            match (object, property) {
                (Some(lhs), Some(rhs)) => Some(format!("{lhs}.{rhs}")),
                (Some(lhs), None) => Some(lhs),
                (None, Some(rhs)) => Some(rhs),
                _ => node_text(node, src),
            }
        }
        "subscript_expression" => {
            let object = node
                .child_by_field_name("object")
                .and_then(|child| expression_name(child, src));
            let index = node
                .child_by_field_name("index")
                .and_then(|child| node_text(child, src));
            match (object, index) {
                (Some(lhs), Some(rhs)) => Some(format!("{lhs}[{rhs}]")),
                _ => node_text(node, src),
            }
        }
        _ => node_text(node, src),
    }
}

fn push_ir(fir: &mut FileIR, path: String, value: serde_json::Value, pos: tree_sitter::Point) {
    fir.push(IRNode {
        id: 0,
        kind: "javascript".to_string(),
        path,
        value,
        meta: Meta {
            file: fir.file_path.clone(),
            line: pos.row + 1,
            column: pos.column + 1,
        },
    });
}

fn walk_ir(node: tree_sitter::Node, src: &str, fir: &mut FileIR) {
    let pos = node.start_position();
    match node.kind() {
        "function_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|child| node_text(child, src))
            {
                push_ir(
                    fir,
                    format!("function.{name}"),
                    serde_json::json!(name),
                    pos,
                );
            }
        }
        "method_definition" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|child| expression_name(child, src))
            {
                push_ir(fir, format!("method.{name}"), serde_json::json!(name), pos);
            }
        }
        "class_declaration" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|child| node_text(child, src))
            {
                push_ir(fir, format!("class.{name}"), serde_json::json!(name), pos);
            }
        }
        "variable_declarator" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|child| expression_name(child, src))
            {
                push_ir(fir, format!("var.{name}"), serde_json::json!(name), pos);
            }
        }
        "for_statement" | "for_in_statement" | "for_of_statement" => {
            push_ir(fir, "loop.for".to_string(), serde_json::Value::Null, pos);
        }
        "while_statement" | "do_statement" => {
            push_ir(fir, "loop.while".to_string(), serde_json::Value::Null, pos);
        }
        "new_expression" => {
            if let Some(constructor) = node
                .child_by_field_name("constructor")
                .and_then(|child| expression_name(child, src))
            {
                push_ir(
                    fir,
                    format!("new.{constructor}"),
                    serde_json::json!(constructor),
                    pos,
                );
            }
        }
        "call_expression" => {
            if let Some(call) = node
                .child_by_field_name("function")
                .and_then(|child| expression_name(child, src))
            {
                push_ir(fir, format!("call.{call}"), serde_json::json!(call), pos);
            }
        }
        "import_statement" => {
            if let Some(source) = node
                .child_by_field_name("source")
                .and_then(|child| node_text(child, src))
            {
                push_ir(
                    fir,
                    format!("import.{source}"),
                    serde_json::json!(source),
                    pos,
                );
            }
        }
        "export_statement" => {
            let target = node
                .child_by_field_name("declaration")
                .and_then(|child| expression_name(child, src))
                .or_else(|| node_text(node, src))
                .unwrap_or_else(|| "unknown".to_string());
            push_ir(
                fir,
                format!("export.{target}"),
                serde_json::json!(target),
                pos,
            );
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_ir(child, src, fir);
    }
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

    match node.kind() {
        "call_expression" => {
            if let Some(call) = node
                .child_by_field_name("function")
                .and_then(|child| expression_name(child, src))
            {
                value = serde_json::json!(call);
            }
        }
        "assignment_expression" => {
            if let Some(left) = node
                .child_by_field_name("left")
                .and_then(|child| expression_name(child, src))
            {
                value = serde_json::json!(left);
            }
        }
        "variable_declarator" => {
            if let Some(name) = node
                .child_by_field_name("name")
                .and_then(|child| expression_name(child, src))
            {
                value = serde_json::json!(name);
            }
        }
        "new_expression" => {
            if let Some(constructor) = node
                .child_by_field_name("constructor")
                .and_then(|child| expression_name(child, src))
            {
                value = serde_json::json!(constructor);
            }
        }
        "member_expression" => {
            if let Some(member) = expression_name(node, src) {
                value = serde_json::json!(member);
            }
        }
        _ => {}
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

fn push_dfg_node(fir: &mut FileIR, name: String, kind: DFNodeKind, line: usize) -> usize {
    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
    let id = dfg.nodes.len();
    dfg.nodes.push(DFNode {
        id,
        name,
        kind,
        sanitized: false,
        branch: None,
        line,
        ..Default::default()
    });
    id
}

fn mark_symbol_def(scopes: &mut [HashMap<String, Symbol>], var: String, def_id: usize) {
    if let Some(scope) = scopes.last_mut() {
        scope.insert(
            var.clone(),
            Symbol {
                name: var,
                sanitized: false,
                def: Some(def_id),
                alias_of: None,
            },
        );
    }
}

fn resolve_symbol<'a>(scopes: &'a [HashMap<String, Symbol>], var: &str) -> Option<&'a Symbol> {
    scopes.iter().rev().find_map(|scope| scope.get(var))
}

fn mark_sanitized(scopes: &mut [HashMap<String, Symbol>], var: &str) {
    for scope in scopes.iter_mut().rev() {
        if let Some(sym) = scope.get_mut(var) {
            sym.sanitized = true;
            return;
        }
    }
}

fn build_dfg(
    node: tree_sitter::Node,
    src: &str,
    fir: &mut FileIR,
    scopes: &mut Vec<HashMap<String, Symbol>>,
    fn_ids: &mut HashMap<String, usize>,
    current_fn_id: Option<usize>,
) {
    let line = node.start_position().row + 1;

    // Register function declarations so calls can reference them
    if node.kind() == "function_declaration" || node.kind() == "method_definition" {
        if let Some(name) = node
            .child_by_field_name("name")
            .and_then(|c| node_text(c, src))
        {
            let fn_node_id = push_dfg_node(fir, name.clone(), DFNodeKind::Def, line);
            fn_ids.insert(name, fn_node_id);
        }
    }

    match node.kind() {
        "statement_block" | "class_body" => scopes.push(HashMap::new()),
        _ => {}
    }

    match node.kind() {
        "variable_declarator" => {
            if let Some(var) = node
                .child_by_field_name("name")
                .and_then(|child| expression_name(child, src))
            {
                let def_id = push_dfg_node(fir, var.clone(), DFNodeKind::Def, line);
                mark_symbol_def(scopes, var, def_id);
            }
        }
        "assignment_expression" => {
            if let Some(target) = node
                .child_by_field_name("left")
                .and_then(|child| expression_name(child, src))
            {
                let assign_id = push_dfg_node(fir, target.clone(), DFNodeKind::Assign, line);
                if let Some(def_id) = resolve_symbol(scopes, &target).and_then(|symbol| symbol.def)
                {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    dfg.edges.push((def_id, assign_id));
                }
                // Track call_returns: if RHS is a call_expression to a known function
                if let Some(rhs) = node.child_by_field_name("right") {
                    if rhs.kind() == "call_expression" {
                        let callee = rhs
                            .child_by_field_name("function")
                            .and_then(|c| expression_name(c, src));
                        if let Some(callee_fn_id) = callee.as_deref().and_then(|n| fn_ids.get(n).copied()) {
                            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                            dfg.call_returns.push((assign_id, callee_fn_id));
                        }
                    }
                }
                mark_symbol_def(scopes, target, assign_id);
            }
        }
        "call_expression" => {
            let callee_name = node
                .child_by_field_name("function")
                .and_then(|child| expression_name(child, src));

            // Record call edge caller→callee
            if let (Some(caller_id), Some(ref callee)) = (current_fn_id, &callee_name) {
                if let Some(&callee_fn_id) = fn_ids.get(callee.as_str()) {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    dfg.calls.push((caller_id, callee_fn_id));
                }
            }

            if let Some(args) = node.child_by_field_name("arguments") {
                let mut cursor = args.walk();
                for arg in args.children(&mut cursor) {
                    if arg.kind() != "identifier" {
                        continue;
                    }
                    let Some(var) = node_text(arg, src) else {
                        continue;
                    };
                    let use_id = push_dfg_node(fir, var.clone(), DFNodeKind::Use, line);
                    if let Some(def_id) = resolve_symbol(scopes, &var).and_then(|symbol| symbol.def)
                    {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        dfg.edges.push((def_id, use_id));
                    }
                    if callee_name.as_deref() == Some("sanitize")
                        || callee_name
                            .as_deref()
                            .is_some_and(|c| crate::catalog::is_sanitizer("javascript", c))
                    {
                        mark_sanitized(scopes, &var);
                    }
                }
            }
        }
        "if_statement" => {
            // Track which DFG Assign nodes are created in each branch by comparing
            // node-list lengths before/after each branch. This avoids scope-snapshot
            // issues caused by statement_block scopes being pushed/popped inside.
            let idx_before = fir.dfg.as_ref().map_or(0, |d| d.nodes.len());

            if let Some(cons) = node.child_by_field_name("consequence") {
                build_dfg(cons, src, fir, scopes, fn_ids, current_fn_id);
            }
            let idx_after_true = fir.dfg.as_ref().map_or(0, |d| d.nodes.len());

            if let Some(alt) = node.child_by_field_name("alternative") {
                build_dfg(alt, src, fir, scopes, fn_ids, current_fn_id);
            }
            let idx_after_false = fir.dfg.as_ref().map_or(0, |d| d.nodes.len());

            // Collect Assign nodes from each branch, keyed by variable name
            let collect_assigns = |start: usize, end: usize, dfg: &DataFlowGraph| -> HashMap<String, usize> {
                dfg.nodes[start..end]
                    .iter()
                    .filter(|n| matches!(n.kind, DFNodeKind::Assign))
                    .map(|n| (n.name.clone(), n.id))
                    .collect()
            };

            if let Some(dfg) = fir.dfg.as_ref() {
                let true_assigns = collect_assigns(idx_before, idx_after_true, dfg);
                let false_assigns = collect_assigns(idx_after_true, idx_after_false, dfg);

                let mut merges_to_add: Vec<(String, usize, Vec<usize>)> = Vec::new();
                let all_vars: std::collections::HashSet<String> = true_assigns
                    .keys()
                    .chain(false_assigns.keys())
                    .cloned()
                    .collect();
                for var in all_vars {
                    let mut sources = Vec::new();
                    if let Some(&id) = true_assigns.get(&var) { sources.push(id); }
                    if let Some(&id) = false_assigns.get(&var) { sources.push(id); }
                    if !sources.is_empty() {
                        merges_to_add.push((var, line, sources));
                    }
                }
                for (var, ln, sources) in merges_to_add {
                    let merge_id = push_dfg_node(fir, var.clone(), DFNodeKind::Assign, ln);
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    dfg.merges.push((merge_id, sources));
                    mark_symbol_def(scopes, var, merge_id);
                }
            }
            return;
        }
        _ => {}
    }

    // Determine current_fn_id for children
    let child_fn_id = if node.kind() == "function_declaration" || node.kind() == "method_definition" {
        node.child_by_field_name("name")
            .and_then(|c| node_text(c, src))
            .and_then(|name| fn_ids.get(&name).copied())
            .or(current_fn_id)
    } else {
        current_fn_id
    };

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        build_dfg(child, src, fir, scopes, fn_ids, child_fn_id);
    }

    match node.kind() {
        "statement_block" | "class_body" => {
            let _ = scopes.pop();
        }
        _ => {}
    }
}

pub fn parse_javascript(content: &str, fir: &mut FileIR) {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_javascript::language())
        .expect("load javascript grammar");

    if let Some(tree) = parser.parse(content, None) {
        let root = tree.root_node();
        walk_ir(root, content, fir);

        let mut scopes: Vec<HashMap<String, Symbol>> = vec![HashMap::new()];
        let mut fn_ids: HashMap<String, usize> = HashMap::new();
        build_dfg(root, content, fir, &mut scopes, &mut fn_ids, None);
        fir.symbols = scopes.remove(0);

        let mut file_ast = FileAst::new(fir.file_path.clone(), "javascript".into());
        let mut cursor = root.walk();
        let mut counter = 0usize;
        for child in root.children(&mut cursor) {
            file_ast.push(walk_ast(child, content, &fir.file_path, &mut counter, None));
        }
        fir.ast = Some(file_ast);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_javascript;
    use ir::FileIR;

    #[test]
    fn captures_richer_ir_nodes() {
        let src = r#"
        import fs from 'fs';
        class UserService {
          save(user) { return sink(user); }
        }
        function run(input) {
          const clean = sanitize(input);
          return new UserService().save(clean);
        }
        export { run };
        "#;

        let mut fir = FileIR::new("test.js".into(), "javascript".into());
        parse_javascript(src, &mut fir);

        assert!(fir.nodes.iter().any(|n| n.path == "import.'fs'"));
        assert!(fir.nodes.iter().any(|n| n.path == "class.UserService"));
        assert!(fir.nodes.iter().any(|n| n.path == "method.save"));
        assert!(fir.nodes.iter().any(|n| n.path == "call.sanitize"));
        assert!(fir.nodes.iter().any(|n| n.path == "new.UserService"));
        assert!(fir.nodes.iter().any(|n| n.path.starts_with("export.")));
    }

    #[test]
    fn captures_dynamic_javascript_calls_and_members() {
        let src = r#"
        function invoke(api, method, payload) {
          const fnRef = api[method];
          return api[method](payload) + window.handlers[method](payload);
        }
        "#;

        let mut fir = FileIR::new("dynamic.js".into(), "javascript".into());
        parse_javascript(src, &mut fir);

        assert!(fir.nodes.iter().any(|n| n.path == "var.fnRef"));
        assert!(fir.nodes.iter().any(|n| n.path == "call.api[method]"));
        assert!(fir
            .nodes
            .iter()
            .any(|n| n.path == "call.window.handlers[method]"));
    }
    #[test]
    fn builds_basic_dfg_relationships() {
        let src = r#"
        function handler(input) {
          let data = input;
          data = sanitize(data);
          sink(data);
        }
        "#;
        let mut fir = FileIR::new("test.js".into(), "javascript".into());
        parse_javascript(src, &mut fir);

        let dfg = fir.dfg.as_ref().expect("dfg should be generated");
        assert!(dfg.nodes.iter().any(|n| n.name == "data"));
        assert!(!dfg.edges.is_empty());
    }

    #[test]
    fn dfg_nodes_have_line_numbers() {
        let src = "function foo() {\n  let x = 1;\n}\n";
        let mut fir = FileIR::new("test.js".into(), "javascript".into());
        parse_javascript(src, &mut fir);
        let dfg = fir.dfg.as_ref().expect("dfg");
        assert!(dfg.nodes.iter().any(|n| n.line > 0), "DFNodes should have line numbers");
    }

    #[test]
    fn dfg_calls_populated_for_intra_file_calls() {
        let src = r#"
function helper() {}
function main() { helper(); }
"#;
        let mut fir = FileIR::new("test.js".into(), "javascript".into());
        parse_javascript(src, &mut fir);
        let dfg = fir.dfg.as_ref().expect("dfg");
        assert!(!dfg.calls.is_empty(), "dfg.calls should record intra-file function calls");
    }

    #[test]
    fn dfg_merges_populated_for_if_redefine() {
        let src = r#"
function f(cond) {
  let x = 1;
  if (cond) { x = 2; } else { x = 3; }
  return x;
}
"#;
        let mut fir = FileIR::new("test.js".into(), "javascript".into());
        parse_javascript(src, &mut fir);
        let dfg = fir.dfg.as_ref().expect("dfg");
        assert!(!dfg.merges.is_empty(), "dfg.merges should have a merge node for x redefined in both branches");
    }
}
