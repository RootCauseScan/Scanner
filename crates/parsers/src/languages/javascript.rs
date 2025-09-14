use ir::{AstNode, FileAst, FileIR, IRNode, Meta};

pub fn parse_javascript(content: &str, fir: &mut FileIR) {
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
                            kind: "javascript".to_string(),
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
                            kind: "javascript".to_string(),
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
                    kind: "javascript".to_string(),
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
                            kind: "javascript".to_string(),
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
                            kind: "javascript".to_string(),
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

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_javascript::language())
        .expect("load javascript grammar");
    if let Some(tree) = parser.parse(content, None) {
        let root = tree.root_node();
        walk_ir(root, content, fir);
        let mut file_ast = FileAst::new(fir.file_path.clone(), "javascript".into());
        let mut cursor = root.walk();
        let mut counter = 0usize;
        for child in root.children(&mut cursor) {
            file_ast.push(walk_ast(child, content, &fir.file_path, &mut counter, None));
        }
        fir.ast = Some(file_ast);
    }
}
