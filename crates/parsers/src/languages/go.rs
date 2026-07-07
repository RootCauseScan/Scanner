use ir::{AstNode, DFNode, DFNodeKind, DataFlowGraph, FileAst, FileIR, IRNode, Meta, Symbol};
use std::collections::HashMap;

pub fn parse_go(content: &str, fir: &mut FileIR) {
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

    fn walk_ir(node: tree_sitter::Node, src: &str, fir: &mut FileIR) {
        match node.kind() {
            "function_declaration" => {
                if let Some(name) = node.child_by_field_name("name") {
                    if let Ok(id) = name.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "go".to_string(),
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
                    if let Ok(id) = func.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "go".to_string(),
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
        if kind == "FunctionDeclaration" {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(id) = name.utf8_text(src.as_bytes()) {
                    value = serde_json::json!(id);
                }
            }
        } else if kind == "CallExpression" {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(id) = func.utf8_text(src.as_bytes()) {
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

    fn go_name(node: tree_sitter::Node, src: &str) -> Option<String> {
        match node.kind() {
            "identifier" | "field_identifier" | "package_identifier" => {
                node.utf8_text(src.as_bytes()).ok().map(|s| s.trim().to_string())
            }
            "selector_expression" => {
                let operand = node.child_by_field_name("operand")
                    .and_then(|c| go_name(c, src));
                let field = node.child_by_field_name("field")
                    .and_then(|c| go_name(c, src));
                match (operand, field) {
                    (Some(o), Some(f)) => Some(format!("{o}.{f}")),
                    (Some(o), None) => Some(o),
                    _ => None,
                }
            }
            _ => node.utf8_text(src.as_bytes()).ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty() && !s.contains('\n')),
        }
    }

    fn push_go_node(fir: &mut FileIR, name: String, kind: DFNodeKind, line: usize) -> usize {
        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
        let id = dfg.nodes.len();
        dfg.nodes.push(DFNode { id, name, kind, line, ..Default::default() });
        id
    }

    fn go_mark_def(scopes: &mut [HashMap<String, Symbol>], var: String, def_id: usize) {
        if let Some(scope) = scopes.last_mut() {
            scope.insert(var.clone(), Symbol { name: var, sanitized: false, def: Some(def_id), alias_of: None });
        }
    }

    fn go_resolve<'a>(scopes: &'a [HashMap<String, Symbol>], var: &str) -> Option<&'a Symbol> {
        scopes.iter().rev().find_map(|s| s.get(var))
    }

    fn go_sanitize(scopes: &mut [HashMap<String, Symbol>], var: &str) {
        for scope in scopes.iter_mut().rev() {
            if let Some(sym) = scope.get_mut(var) { sym.sanitized = true; return; }
        }
    }

    fn build_dfg_go(
        node: tree_sitter::Node,
        src: &str,
        fir: &mut FileIR,
        scopes: &mut Vec<HashMap<String, Symbol>>,
        fn_ids: &mut HashMap<String, usize>,
        current_fn_id: Option<usize>,
    ) {
        let line = node.start_position().row + 1;

        // Register function/method declarations
        if matches!(node.kind(), "function_declaration" | "method_declaration") {
            if let Some(name) = node.child_by_field_name("name")
                .and_then(|c| go_name(c, src))
            {
                let fn_node_id = push_go_node(fir, name.clone(), DFNodeKind::Def, line);
                fn_ids.insert(name, fn_node_id);
            }
        }

        match node.kind() {
            "block" => scopes.push(HashMap::new()),
            _ => {}
        }

        match node.kind() {
            // := short variable declaration: x, y := expr1, expr2
            "short_var_declaration" => {
                if let Some(left) = node.child_by_field_name("left") {
                    let mut cursor = left.walk();
                    for lhs in left.children(&mut cursor) {
                        if let Some(var) = go_name(lhs, src) {
                            if var != "_" {
                                let id = push_go_node(fir, var.clone(), DFNodeKind::Def, line);
                                go_mark_def(scopes, var.clone(), id);

                                // check if RHS is a call expression for call_returns
                                if let Some(right) = node.child_by_field_name("right") {
                                    let mut rc = right.walk();
                                    for rhs in right.children(&mut rc) {
                                        if rhs.kind() == "call_expression" {
                                            let callee = rhs.child_by_field_name("function")
                                                .and_then(|c| go_name(c, src));
                                            if let Some(&callee_fn) = callee.as_deref().and_then(|n| fn_ids.get(n)) {
                                                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                                dfg.call_returns.push((id, callee_fn));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                // Process RHS for identifier uses
                if let Some(right) = node.child_by_field_name("right") {
                    let mut cursor = right.walk();
                    for rhs in right.children(&mut cursor) {
                        if rhs.kind() == "identifier" {
                            if let Some(var) = go_name(rhs, src) {
                                if let Some(def_id) = go_resolve(scopes, &var).and_then(|s| s.def) {
                                    let use_id = push_go_node(fir, var.clone(), DFNodeKind::Use, line);
                                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                    dfg.edges.push((def_id, use_id));
                                }
                            }
                        }
                    }
                }
            }

            // = assignment
            "assignment_statement" => {
                if let Some(left) = node.child_by_field_name("left") {
                    let mut cursor = left.walk();
                    for lhs in left.children(&mut cursor) {
                        if let Some(var) = go_name(lhs, src) {
                            if var != "_" {
                                let assign_id = push_go_node(fir, var.clone(), DFNodeKind::Assign, line);
                                if let Some(def_id) = go_resolve(scopes, &var).and_then(|s| s.def) {
                                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                    dfg.edges.push((def_id, assign_id));
                                }
                                go_mark_def(scopes, var, assign_id);
                            }
                        }
                    }
                }
            }

            // var declaration
            "var_declaration" | "var_spec" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "var_spec" {
                        let mut sc = child.walk();
                        for name_node in child.children(&mut sc) {
                            if name_node.kind() == "identifier" {
                                if let Some(var) = go_name(name_node, src) {
                                    let id = push_go_node(fir, var.clone(), DFNodeKind::Def, line);
                                    go_mark_def(scopes, var, id);
                                }
                            }
                        }
                    } else if child.kind() == "identifier" {
                        if let Some(var) = go_name(child, src) {
                            let id = push_go_node(fir, var.clone(), DFNodeKind::Def, line);
                            go_mark_def(scopes, var, id);
                        }
                    }
                }
            }

            // call_expression: process arguments as Use nodes
            "call_expression" => {
                let callee_name = node.child_by_field_name("function")
                    .and_then(|c| go_name(c, src));

                // Record call edge
                if let (Some(caller_id), Some(ref callee)) = (current_fn_id, &callee_name) {
                    if let Some(&callee_fn_id) = fn_ids.get(callee.as_str()) {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        dfg.calls.push((caller_id, callee_fn_id));
                    }
                }

                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut cursor = args.walk();
                    for arg in args.children(&mut cursor) {
                        if arg.kind() != "identifier" { continue; }
                        if let Some(var) = go_name(arg, src) {
                            let use_id = push_go_node(fir, var.clone(), DFNodeKind::Use, line);
                            if let Some(def_id) = go_resolve(scopes, &var).and_then(|s| s.def) {
                                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                dfg.edges.push((def_id, use_id));
                            }
                            if callee_name.as_deref() == Some("sanitize") {
                                go_sanitize(scopes, &var);
                            }
                        }
                    }
                }
            }

            // return_statement
            "return_statement" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        if let Some(var) = go_name(child, src) {
                            let ret_id = push_go_node(fir, var.clone(), DFNodeKind::Return, line);
                            if let Some(def_id) = go_resolve(scopes, &var).and_then(|s| s.def) {
                                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                dfg.edges.push((def_id, ret_id));
                            }
                        }
                    }
                }
            }

            // parameter_declaration — register params as Param nodes in current scope
            "parameter_declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "identifier" {
                        if let Some(var) = go_name(child, src) {
                            let id = push_go_node(fir, var.clone(), DFNodeKind::Param, line);
                            go_mark_def(scopes, var, id);
                        }
                    }
                }
            }

            _ => {}
        }

        let child_fn_id = if matches!(node.kind(), "function_declaration" | "method_declaration") {
            node.child_by_field_name("name")
                .and_then(|c| go_name(c, src))
                .and_then(|name| fn_ids.get(&name).copied())
                .or(current_fn_id)
        } else {
            current_fn_id
        };

        // Handle if_statement branches with merge tracking
        if node.kind() == "if_statement" {
            let idx_before = fir.dfg.as_ref().map_or(0, |d| d.nodes.len());
            if let Some(cons) = node.child_by_field_name("consequence") {
                build_dfg_go(cons, src, fir, scopes, fn_ids, child_fn_id);
            }
            let idx_after_true = fir.dfg.as_ref().map_or(0, |d| d.nodes.len());
            if let Some(alt) = node.child_by_field_name("alternative") {
                build_dfg_go(alt, src, fir, scopes, fn_ids, child_fn_id);
            }
            let idx_after_false = fir.dfg.as_ref().map_or(0, |d| d.nodes.len());

            if let Some(dfg) = fir.dfg.as_ref() {
                let collect = |start: usize, end: usize| -> HashMap<String, usize> {
                    dfg.nodes[start..end].iter()
                        .filter(|n| matches!(n.kind, DFNodeKind::Assign))
                        .map(|n| (n.name.clone(), n.id))
                        .collect()
                };
                let true_assigns = collect(idx_before, idx_after_true);
                let false_assigns = collect(idx_after_true, idx_after_false);
                let all_vars: std::collections::HashSet<String> = true_assigns.keys().chain(false_assigns.keys()).cloned().collect();
                let _ = dfg;
                for var in all_vars {
                    let mut sources = Vec::new();
                    if let Some(&id) = true_assigns.get(&var) { sources.push(id); }
                    if let Some(&id) = false_assigns.get(&var) { sources.push(id); }
                    if !sources.is_empty() {
                        let merge_id = push_go_node(fir, var.clone(), DFNodeKind::Assign, line);
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        dfg.merges.push((merge_id, sources));
                        go_mark_def(scopes, var, merge_id);
                    }
                }
            }
            match node.kind() {
                "block" => { let _ = scopes.pop(); }
                _ => {}
            }
            return;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            build_dfg_go(child, src, fir, scopes, fn_ids, child_fn_id);
        }

        match node.kind() {
            "block" => { let _ = scopes.pop(); }
            _ => {}
        }
    }

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_go::language())
        .expect("load go grammar");
    if let Some(tree) = parser.parse(content, None) {
        let root = tree.root_node();
        walk_ir(root, content, fir);
        let mut file_ast = FileAst::new(fir.file_path.clone(), "go".into());
        let mut cursor = root.walk();
        let mut counter = 0usize;
        for child in root.children(&mut cursor) {
            file_ast.push(walk_ast(child, content, &fir.file_path, &mut counter, None));
        }
        fir.ast = Some(file_ast);

        let mut scopes: Vec<HashMap<String, Symbol>> = vec![HashMap::new()];
        let mut fn_ids: HashMap<String, usize> = HashMap::new();
        build_dfg_go(root, content, fir, &mut scopes, &mut fn_ids, None);
        fir.symbols = scopes.remove(0);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_go;
    use ir::FileIR;

    #[test]
    fn go_dfg_short_var_decl_creates_def() {
        let src = "package main\nfunc main() {\n\tx := 1\n\t_ = x\n}\n";
        let mut fir = FileIR::new("main.go".into(), "go".into());
        parse_go(src, &mut fir);
        let dfg = fir.dfg.as_ref().expect("dfg should be generated for go");
        assert!(dfg.nodes.iter().any(|n| n.name == "x"), "Def node for x should exist");
    }

    #[test]
    fn go_dfg_function_call_creates_use() {
        let src = "package main\nfunc sink(v string) {}\nfunc main() {\n\tx := source()\n\tsink(x)\n}\n";
        let mut fir = FileIR::new("main.go".into(), "go".into());
        parse_go(src, &mut fir);
        let dfg = fir.dfg.as_ref().expect("dfg");
        assert!(dfg.nodes.iter().any(|n| n.name == "x" && matches!(n.kind, ir::DFNodeKind::Use)),
            "Use node for x in sink() should exist");
    }

    #[test]
    fn go_dfg_nodes_have_line_numbers() {
        let src = "package main\nfunc f() {\n\tx := 1\n}\n";
        let mut fir = FileIR::new("main.go".into(), "go".into());
        parse_go(src, &mut fir);
        let dfg = fir.dfg.as_ref().expect("dfg");
        assert!(dfg.nodes.iter().any(|n| n.line > 0), "DFNodes should have line numbers");
    }
}
