use hcl_edit::{expr::Expression, structure::Body, Span};
use ir::{FileIR, IRNode, Meta};

pub fn parse_hcl(content: &str, fir: &mut FileIR) {
    fn offset(src: &str, byte_idx: usize) -> (usize, usize) {
        let mut line = 1;
        let mut col = 1;
        for (i, ch) in src.char_indices() {
            if i >= byte_idx {
                break;
            }
            if ch == '\n' {
                line += 1;
                col = 1;
            } else {
                col += 1;
            }
        }
        (line, col)
    }

    fn push_node(
        path: String,
        value: serde_json::Value,
        span: Option<std::ops::Range<usize>>,
        nodes: &mut Vec<IRNode>,
        src: &str,
        file: &str,
    ) {
        if let Some(r) = span {
            let (line, column) = offset(src, r.start);
            nodes.push(IRNode {
                id: 0,
                kind: "terraform".to_string(),
                path,
                value,
                meta: Meta {
                    file: file.to_string(),
                    line,
                    column,
                },
            });
        }
    }

    fn walk_expr(expr: &Expression, path: String, nodes: &mut Vec<IRNode>, src: &str, file: &str) {
        use hcl_edit::expr::Expression::*;
        match expr {
            Null(_) => push_node(path, serde_json::Value::Null, expr.span(), nodes, src, file),
            Bool(b) => push_node(
                path,
                serde_json::json!(*b.value()),
                b.span(),
                nodes,
                src,
                file,
            ),
            Number(n) => {
                let num = n.value();
                let val = if let Some(i) = num.as_i64() {
                    serde_json::json!(i)
                } else if let Some(u) = num.as_u64() {
                    serde_json::json!(u)
                } else if let Some(f) = num.as_f64() {
                    serde_json::json!(f)
                } else {
                    serde_json::Value::Null
                };
                push_node(path, val, n.span(), nodes, src, file);
            }
            String(s) => push_node(
                path,
                serde_json::json!(s.as_str()),
                s.span(),
                nodes,
                src,
                file,
            ),
            Array(arr) => {
                for (i, item) in arr.iter().enumerate() {
                    let new_path = format!("{path}[{i}]");
                    walk_expr(item, new_path, nodes, src, file);
                }
            }
            Object(obj) => {
                for (k, v) in obj.iter() {
                    if let Some(id) = k.as_ident() {
                        let key = id.as_str();
                        let new_path = if path.is_empty() {
                            key.to_string()
                        } else {
                            format!("{path}.{key}")
                        };
                        walk_expr(v.expr(), new_path, nodes, src, file);
                    }
                }
            }
            _ => {}
        }
    }

    fn walk_body(body: &Body, prefix: String, nodes: &mut Vec<IRNode>, src: &str, file: &str) {
        for attr in body.attributes() {
            let key = attr.key.as_str();
            let path = if prefix.is_empty() {
                key.to_string()
            } else {
                format!("{prefix}.{key}")
            };
            walk_expr(&attr.value, path, nodes, src, file);
        }
        for block in body.blocks() {
            let ident = block.ident.as_str();
            let mut new_prefix = if prefix.is_empty() {
                ident.to_string()
            } else {
                format!("{prefix}.{ident}")
            };
            for label in block.labels.iter().map(|l| l.as_str()) {
                new_prefix.push('.');
                new_prefix.push_str(label);
            }
            walk_body(&block.body, new_prefix, nodes, src, file);
        }
    }

    if let Ok(body) = content.parse::<Body>() {
        walk_body(
            &body,
            String::new(),
            &mut fir.nodes,
            content,
            &fir.file_path,
        );
    }
}
