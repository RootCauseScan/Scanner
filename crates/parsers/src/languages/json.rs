use anyhow::Error;
use ir::{FileIR, IRNode, Meta};

fn json_to_nodes(
    value: &serde_json::Value,
    path_prefix: String,
    nodes: &mut Vec<IRNode>,
    file: &str,
    kind: &str,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let new_path = if path_prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{path_prefix}.{k}")
                };
                json_to_nodes(v, new_path, nodes, file, kind);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let new_path = format!("{path_prefix}[{i}]");
                json_to_nodes(v, new_path, nodes, file, kind);
            }
        }
        _ => {
            nodes.push(IRNode {
                id: 0,
                kind: kind.to_string(),
                path: path_prefix,
                value: value.clone(),
                meta: Meta {
                    file: file.to_string(),
                    line: 1,
                    column: 1,
                },
            });
        }
    }
}

pub fn parse_json(content: &str, fir: &mut FileIR) -> Result<(), Error> {
    let value: serde_json::Value = serde_json::from_str(content)?;
    json_to_nodes(
        &value,
        String::new(),
        &mut fir.nodes,
        &fir.file_path,
        &fir.file_type,
    );
    Ok(())
}
