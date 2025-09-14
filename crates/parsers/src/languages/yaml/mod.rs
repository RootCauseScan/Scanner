use anyhow::Error;
use ir::{FileIR, IRNode, Meta};
use marked_yaml::Node;
use std::collections::HashMap;

#[cfg(test)]
mod tests;

fn merge_into<'a>(target: &mut HashMap<String, &'a Node>, node: &'a Node) {
    match node {
        Node::Mapping(map) => {
            for (k, v) in map.iter() {
                if k.as_str() == "<<" {
                    merge_into(target, v);
                } else {
                    target.entry(k.as_str().to_string()).or_insert(v);
                }
            }
        }
        Node::Sequence(seq) => {
            for item in seq.iter() {
                merge_into(target, item);
            }
        }
        #[cfg(any())]
        Node::Alias(alias) => merge_into(target, alias),
        _ => {}
    }
}

fn yaml_to_nodes(
    node: &Node,
    path_prefix: String,
    nodes: &mut Vec<IRNode>,
    file: &str,
    kind: &str,
) {
    match node {
        Node::Mapping(map) => {
            let mut merged: HashMap<String, &Node> = HashMap::new();

            for (k, v) in map.iter() {
                if k.as_str() == "<<" {
                    merge_into(&mut merged, v);
                }
            }

            for (k, v) in map.iter() {
                if k.as_str() == "<<" {
                    continue;
                }
                merged.insert(k.as_str().to_string(), v);
            }

            for (key, v) in merged {
                let new_path = if path_prefix.is_empty() {
                    key
                } else {
                    format!("{path_prefix}.{key}")
                };
                yaml_to_nodes(v, new_path, nodes, file, kind);
            }
        }
        Node::Sequence(seq) => {
            for (i, v) in seq.iter().enumerate() {
                let new_path = format!("{path_prefix}[{i}]");
                yaml_to_nodes(v, new_path, nodes, file, kind);
            }
        }
        #[cfg(any())]
        Node::Alias(alias) => {
            yaml_to_nodes(alias, path_prefix, nodes, file, kind);
        }
        Node::Scalar(s) => {
            let raw = s.as_str();
            let value = serde_yaml::from_str(raw)
                .unwrap_or_else(|_| serde_json::Value::String(raw.to_string()));
            let (line, column) = s
                .span()
                .start()
                .map(|m| (m.line(), m.column()))
                .unwrap_or((1, 1));
            let node = IRNode {
                id: 0,
                kind: kind.to_string(),
                path: path_prefix,
                value,
                meta: Meta {
                    file: file.to_string(),
                    line,
                    column,
                },
            };
            nodes.push(node);
        }
    }
}

pub fn parse_yaml(content: &str, fir: &mut FileIR) -> Result<(), Error> {
    let resolved = serde_yaml::from_str::<serde_yaml::Value>(content)
        .ok()
        .and_then(|v| serde_yaml::to_string(&v).ok())
        .unwrap_or_else(|| content.to_string());
    let doc = marked_yaml::parse_yaml(0, &resolved)?;
    yaml_to_nodes(
        &doc,
        String::new(),
        &mut fir.nodes,
        &fir.file_path,
        &fir.file_type,
    );
    Ok(())
}
