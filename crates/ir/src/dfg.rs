use serde::{Deserialize, Serialize};

/// Generates a stable identifier by combining path, name, and position.
///
/// It uses a simple FNV mix and a bitwise combination of line and column to
/// avoid external dependencies.
pub fn stable_id(path: &str, line: usize, column: usize, name: &str) -> usize {
    let mut h: u64 = 0xcbf29ce484222325; // offset basis
    for b in path.as_bytes().iter().chain(name.as_bytes()) {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3); // FNV prime
    }
    h ^= ((line as u64) << 32) | column as u64;
    h as usize
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DFNodeKind {
    Def,
    Param,
    Use,
    Assign,
    Return,
    Branch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DFNode {
    pub id: usize,
    pub name: String,
    pub kind: DFNodeKind,
    #[serde(default)]
    pub sanitized: bool,
    #[serde(default)]
    pub branch: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DataFlowGraph {
    pub nodes: Vec<DFNode>,
    pub edges: Vec<(usize, usize)>,
    #[serde(default)]
    pub calls: Vec<(usize, usize)>,
    #[serde(default)]
    pub call_returns: Vec<(usize, usize)>,
    #[serde(default)]
    pub merges: Vec<(usize, Vec<usize>)>,
}

impl DataFlowGraph {
    /// Exports the graph to DOT format.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph DFG {\n");
        for node in &self.nodes {
            out.push_str(&format!(
                "    {} [label=\"{}:{:?}\"];\n",
                node.id, node.name, node.kind
            ));
        }
        for (a, b) in &self.edges {
            out.push_str(&format!("    {a} -> {b};\n"));
        }
        out.push('}');
        out
    }

    /// Exports the graph to Mermaid format.
    pub fn to_mermaid(&self) -> String {
        let mut out = String::from("graph TD\n");
        for node in &self.nodes {
            out.push_str(&format!(
                "    {}[\"{}:{:?}\"]\n",
                node.id, node.name, node.kind
            ));
        }
        for (a, b) in &self.edges {
            out.push_str(&format!("    {a} --> {b}\n"));
        }
        out
    }

    /// Exports the graph to JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Symbol {
    pub name: String,
    pub sanitized: bool,
    pub def: Option<usize>,
    #[serde(default)]
    pub alias_of: Option<String>,
}
