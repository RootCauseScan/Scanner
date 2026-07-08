use ir::{AstNode, DFNode, DFNodeKind, DataFlowGraph, FileAst, FileIR, IRNode, Meta, Symbol};
use std::collections::HashMap;

pub fn parse_typescript(content: &str, fir: &mut FileIR) {
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
                            kind: "typescript".to_string(),
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
            "variable_declarator" => {
                if let Some(name) = node.child_by_field_name("name") {
                    if let Ok(id) = name.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "typescript".to_string(),
                            path: format!("var.{id}"),
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
            "for_statement" => {
                let pos = node.start_position();
                fir.push(IRNode {
                    id: 0,
                    kind: "typescript".to_string(),
                    path: "for".to_string(),
                    value: serde_json::Value::Null,
                    meta: Meta {
                        file: fir.file_path.clone(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                    },
                });
            }
            "new_expression" => {
                if let Some(cons) = node.child_by_field_name("constructor") {
                    if let Ok(id) = cons.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "typescript".to_string(),
                            path: format!("new.{id}"),
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
                            kind: "typescript".to_string(),
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
        if kind == "CallExpression" {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(id) = func.utf8_text(src.as_bytes()) {
                    value = serde_json::json!(id);
                }
            }
        } else if kind == "AssignmentExpression" {
            if let Some(left) = node.child_by_field_name("left") {
                if left.kind() == "member_expression" {
                    if let Some(prop) = left.child_by_field_name("property") {
                        if let Ok(id) = prop.utf8_text(src.as_bytes()) {
                            value = serde_json::json!(id);
                        }
                    }
                }
            }
        } else if kind == "VariableDeclarator" {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(id) = name.utf8_text(src.as_bytes()) {
                    value = serde_json::json!(id);
                }
            }
        } else if kind == "ForStatement" {
            if let Some(init) = node.child_by_field_name("initializer") {
                if let Ok(init_txt) = init.utf8_text(src.as_bytes()) {
                    value = serde_json::json!(init_txt);
                }
            }
        } else if kind == "NewExpression" {
            if let Some(cons) = node.child_by_field_name("constructor") {
                if let Ok(id) = cons.utf8_text(src.as_bytes()) {
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

    /// Extracts the simple name of a TS expression, unwrapping TS-specific wrappers.
    fn expression_name_ts(node: tree_sitter::Node, src: &str) -> Option<String> {
        match node.kind() {
            "identifier" | "property_identifier" => {
                node.utf8_text(src.as_bytes()).ok().map(|s| s.trim().to_string())
            }
            "as_expression" | "non_null_expression" | "parenthesized_expression" => {
                // Unwrap to the inner expression (first named child that isn't a type)
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.is_named() && child.kind() != "type_annotation" && child.kind() != "predefined_type" {
                        if let Some(name) = expression_name_ts(child, src) {
                            return Some(name);
                        }
                    }
                }
                None
            }
            "member_expression" => {
                let object = node.child_by_field_name("object")
                    .and_then(|c| expression_name_ts(c, src));
                let property = node.child_by_field_name("property")
                    .and_then(|c| expression_name_ts(c, src));
                match (object, property) {
                    (Some(o), Some(p)) => Some(format!("{o}.{p}")),
                    (Some(o), None) => Some(o),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn push_ts_node(fir: &mut FileIR, name: String, kind: DFNodeKind, line: usize) -> usize {
        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
        let id = dfg.nodes.len();
        dfg.nodes.push(DFNode {
            id,
            name,
            kind,
            line,
            ..Default::default()
        });
        id
    }

    fn mark_ts_def(scopes: &mut [HashMap<String, Symbol>], var: String, def_id: usize) {
        if let Some(scope) = scopes.last_mut() {
            scope.insert(var.clone(), Symbol { name: var, sanitized: false, def: Some(def_id), alias_of: None });
        }
    }

    fn resolve_ts<'a>(scopes: &'a [HashMap<String, Symbol>], var: &str) -> Option<&'a Symbol> {
        scopes.iter().rev().find_map(|s| s.get(var))
    }

    fn sanitize_ts(scopes: &mut [HashMap<String, Symbol>], var: &str) {
        for scope in scopes.iter_mut().rev() {
            if let Some(sym) = scope.get_mut(var) { sym.sanitized = true; return; }
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
        // Skip pure TS type nodes — they carry no data flow information
        match node.kind() {
            "type_annotation" | "type_parameters" | "type_predicate" | "predefined_type" => return,
            _ => {}
        }

        let line = node.start_position().row + 1;

        // Register function declarations for call tracking
        if matches!(node.kind(), "function_declaration" | "method_definition") {
            if let Some(name) = node.child_by_field_name("name")
                .and_then(|c| expression_name_ts(c, src))
            {
                let fn_node_id = push_ts_node(fir, name.clone(), DFNodeKind::Def, line);
                fn_ids.insert(name, fn_node_id);
            }
        }

        match node.kind() {
            "statement_block" | "class_body" => scopes.push(HashMap::new()),
            _ => {}
        }

        match node.kind() {
            "variable_declarator" => {
                if let Some(var) = node.child_by_field_name("name")
                    .and_then(|c| expression_name_ts(c, src))
                {
                    let def_id = push_ts_node(fir, var.clone(), DFNodeKind::Def, line);
                    mark_ts_def(scopes, var.clone(), def_id);
                    // If RHS is a call to a known function, record call_return
                    if let Some(rhs) = node.child_by_field_name("value") {
                        let rhs_inner = if rhs.kind() == "as_expression" {
                            rhs.child(0).unwrap_or(rhs)
                        } else { rhs };
                        if rhs_inner.kind() == "call_expression" {
                            let callee = rhs_inner.child_by_field_name("function")
                                .and_then(|c| expression_name_ts(c, src));
                            if let Some(&callee_fn_id) = callee.as_deref().and_then(|n| fn_ids.get(n)) {
                                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                dfg.call_returns.push((def_id, callee_fn_id));
                            }
                        } else if matches!(rhs_inner.kind(), "string" | "number" | "true" | "false") {
                            // String/number/boolean literals are safe values — mark the variable sanitized.
                            sanitize_ts(scopes, &var);
                        }
                    }
                }
            }
            "assignment_expression" => {
                if let Some(target) = node.child_by_field_name("left")
                    .and_then(|c| expression_name_ts(c, src))
                {
                    let assign_id = push_ts_node(fir, target.clone(), DFNodeKind::Assign, line);
                    if let Some(def_id) = resolve_ts(scopes, &target).and_then(|s| s.def) {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        dfg.edges.push((def_id, assign_id));
                    }
                    mark_ts_def(scopes, target, assign_id);
                }
            }
            "call_expression" => {
                let callee_name = node.child_by_field_name("function")
                    .and_then(|c| expression_name_ts(c, src));

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
                        let Some(var) = arg.utf8_text(src.as_bytes()).ok() else { continue };
                        let var = var.trim().to_string();
                        let use_id = push_ts_node(fir, var.clone(), DFNodeKind::Use, line);
                        if let Some(def_id) = resolve_ts(scopes, &var).and_then(|s| s.def) {
                            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                            dfg.edges.push((def_id, use_id));
                        }
                        if callee_name.as_deref() == Some("sanitize") {
                            sanitize_ts(scopes, &var);
                        }
                    }
                }
            }
            _ => {}
        }

        let child_fn_id = if matches!(node.kind(), "function_declaration" | "method_definition") {
            node.child_by_field_name("name")
                .and_then(|c| expression_name_ts(c, src))
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
            "statement_block" | "class_body" => { let _ = scopes.pop(); }
            _ => {}
        }
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_typescript::language_tsx())
        .expect("load typescript grammar");
    if let Some(tree) = parser.parse(content, None) {
        let root = tree.root_node();
        walk_ir(root, content, fir);
        let mut scopes: Vec<HashMap<String, Symbol>> = vec![HashMap::new()];
        let mut fn_ids: HashMap<String, usize> = HashMap::new();
        build_dfg(root, content, fir, &mut scopes, &mut fn_ids, None);
        fir.symbols = scopes.remove(0);
        let mut file_ast = FileAst::new(fir.file_path.clone(), "typescript".into());
        let mut cursor = root.walk();
        let mut counter = 0usize;
        for child in root.children(&mut cursor) {
            file_ast.push(walk_ast(child, content, &fir.file_path, &mut counter, None));
        }
        fir.ast = Some(file_ast);
    }
}
