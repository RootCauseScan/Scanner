use ir::{AstNode, FileAst, FileIR, IRNode, Meta};

pub fn parse_ruby(content: &str, fir: &mut FileIR) {
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
            "method" => {
                if let Some(name) = node.child_by_field_name("name") {
                    if let Ok(id) = name.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "ruby".to_string(),
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
            "call" => {
                if let Some(method) = node.child_by_field_name("method") {
                    if let Ok(id) = method.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "ruby".to_string(),
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
        if kind == "Method" {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(id) = name.utf8_text(src.as_bytes()) {
                    value = serde_json::json!(id);
                }
            }
        } else if kind == "Call" {
            if let Some(method) = node.child_by_field_name("method") {
                if let Ok(id) = method.utf8_text(src.as_bytes()) {
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
        .set_language(tree_sitter_ruby::language())
        .expect("load ruby grammar");
    if let Some(tree) = parser.parse(content, None) {
        let root = tree.root_node();
        walk_ir(root, content, fir);
        let mut file_ast = FileAst::new(fir.file_path.clone(), "ruby".into());
        let mut cursor = root.walk();
        let mut counter = 0usize;
        for child in root.children(&mut cursor) {
            file_ast.push(walk_ast(child, content, &fir.file_path, &mut counter, None));
        }
        fir.ast = Some(file_ast);
    }
}
