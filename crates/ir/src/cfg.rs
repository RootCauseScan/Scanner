use serde::{Deserialize, Serialize};

/// Basic CFG node that represents a call in the source code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CFGNode {
    pub id: usize,
    pub line: usize,
    pub code: String,
}

/// Minimalist control flow graph composed of nodes and edges.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CFG {
    pub nodes: Vec<CFGNode>,
    pub edges: Vec<(usize, usize)>,
}

impl CFG {
    /// Exports the graph to DOT format.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph CFG {\n");
        for node in &self.nodes {
            out.push_str(&format!(
                "    {} [label=\"{}:{}\"];\n",
                node.id, node.line, node.code
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
                "    {}[\"{}:{}\"]\n",
                node.id, node.line, node.code
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
