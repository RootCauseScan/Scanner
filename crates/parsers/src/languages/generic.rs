use anyhow::Error;
use ir::{FileIR, IRNode, Meta};

/// Parse generic text-based files (e.g., HTML, XML, CSS)
/// by splitting content into line-based nodes.
pub fn parse_generic(content: &str, fir: &mut FileIR) -> Result<(), Error> {
    for (idx, line) in content.lines().enumerate() {
        fir.nodes.push(IRNode {
            id: 0,
            kind: fir.file_type.clone(),
            path: (idx + 1).to_string(),
            value: serde_json::Value::String(line.to_string()),
            meta: Meta {
                file: fir.file_path.clone(),
                line: idx + 1,
                column: 1,
            },
        });
    }
    Ok(())
}
