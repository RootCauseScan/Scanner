use ir::{FileIR, IRNode, Meta};
use tracing::debug;

pub fn parse_dockerfile(content: &str, fir: &mut FileIR) {
    debug!(file = %fir.file_path, "Parsing Dockerfile");
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let instr = trimmed.split_whitespace().next().unwrap_or("");
        let col = line.find(instr).map(|i| i + 1).unwrap_or(1);
        let node = IRNode {
            id: 0,
            kind: "dockerfile".to_string(),
            path: instr.to_string(),
            value: serde_json::Value::String(trimmed.to_string()),
            meta: Meta {
                file: fir.file_path.clone(),
                line: idx + 1,
                column: col,
            },
        };
        fir.push(node);
    }
    debug!(file = %fir.file_path, "Parsed Dockerfile");
}
