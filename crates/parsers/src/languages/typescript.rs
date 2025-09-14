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

    fn build_dfg(
        node: tree_sitter::Node,
        src: &str,
        fir: &mut FileIR,
        scopes: &mut Vec<HashMap<String, Symbol>>,
    ) {
        let mut cursor = node.walk();
        match node.kind() {
            "function_declaration" => {
                scopes.push(HashMap::new());
                for child in node.children(&mut cursor) {
                    build_dfg(child, src, fir, scopes);
                }
                scopes.pop();
                return;
            }
            "variable_declarator" => {
                if let (Some(name_node), Some(value)) = (
                    node.child_by_field_name("name"),
                    node.child_by_field_name("value"),
                ) {
                    if let Ok(var) = name_node.utf8_text(src.as_bytes()) {
                        if value.kind() == "call_expression" {
                            if let Some(func) = value.child_by_field_name("function") {
                                if let Ok(fname) = func.utf8_text(src.as_bytes()) {
                                    match fname {
                                        "source" => {
                                            let dfg =
                                                fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                            let id = dfg.nodes.len();
                                            dfg.nodes.push(DFNode {
                                                id,
                                                name: var.to_string(),
                                                kind: DFNodeKind::Def,
                                                sanitized: false,
                                                branch: None,
                                            });
                                            scopes.last_mut().expect("scope").insert(
                                                var.to_string(),
                                                Symbol {
                                                    name: var.to_string(),
                                                    sanitized: false,
                                                    def: Some(id),
                                                    alias_of: None,
                                                },
                                            );
                                        }
                                        "sanitize" => {
                                            scopes
                                                .last_mut()
                                                .expect("scope")
                                                .entry(var.to_string())
                                                .or_insert_with(|| Symbol {
                                                    name: var.to_string(),
                                                    ..Default::default()
                                                })
                                                .sanitized = true;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "call_expression" => {
                if let Some(func) = node.child_by_field_name("function") {
                    if let Ok(fname) = func.utf8_text(src.as_bytes()) {
                        if fname == "sink" {
                            if let Some(args) = node.child_by_field_name("arguments") {
                                let mut c = args.walk();
                                for arg in args.children(&mut c) {
                                    if arg.kind() == "identifier" {
                                        if let Ok(var) = arg.utf8_text(src.as_bytes()) {
                                            let dfg =
                                                fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                            let id = dfg.nodes.len();
                                            dfg.nodes.push(DFNode {
                                                id,
                                                name: var.to_string(),
                                                kind: DFNodeKind::Use,
                                                sanitized: false,
                                                branch: None,
                                            });
                                            for scope in scopes.iter().rev() {
                                                if let Some(sym) = scope.get(var) {
                                                    if let Some(def_id) = sym.def {
                                                        dfg.edges.push((def_id, id));
                                                    }
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else if fname == "sanitize" {
                            if let Some(args) = node.child_by_field_name("arguments") {
                                let mut c = args.walk();
                                for arg in args.children(&mut c) {
                                    if arg.kind() == "identifier" {
                                        if let Ok(var) = arg.utf8_text(src.as_bytes()) {
                                            for scope in scopes.iter_mut().rev() {
                                                if let Some(sym) = scope.get_mut(var) {
                                                    sym.sanitized = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        for child in node.children(&mut cursor) {
            build_dfg(child, src, fir, scopes);
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
        build_dfg(root, content, fir, &mut scopes);
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
