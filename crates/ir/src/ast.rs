//! IR-AST representation for source code.
//!
//! Unlike **IR-Doc** (see [`IRNode`](crate::IRNode)), which flattens documents
//! into independent nodes identified by a `path`, **IR-AST** preserves the
//! syntax tree hierarchy. Both share the [`Meta`] structure to locate
//! fragments within the file.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstNode {
    /// Incremental unique identifier of the node within the file.
    pub id: usize,
    /// Reference to the parent node, if any.
    pub parent: Option<usize>,
    /// Logical identifier of the node: "Function", "LetStmt", etc.
    pub kind: String,
    /// Value associated with the node (identifier, literal, etc.).
    pub value: JsonValue,
    /// Node children to preserve structural context.
    pub children: Vec<AstNode>,
    /// Location metadata.
    pub meta: Meta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAst {
    pub file_path: String,
    pub file_type: String, // rust|python|...
    /// Root nodes of the AST.
    pub nodes: Vec<AstNode>,
    /// Flat node index ordered by `id`.
    pub index: Vec<AstNode>,
}

impl FileAst {
    pub fn new(file_path: String, file_type: String) -> Self {
        Self {
            file_path,
            file_type,
            nodes: Vec::new(),
            index: Vec::new(),
        }
    }

    pub fn push(&mut self, node: AstNode) {
        self.collect(&node);
        self.nodes.push(node);
    }

    fn collect(&mut self, node: &AstNode) {
        if node.id == self.index.len() {
            self.index.push(node.clone());
        } else if node.id < self.index.len() {
            self.index[node.id] = node.clone();
        } else {
            self.index.push(node.clone());
        }
        for child in &node.children {
            self.collect(child);
        }
    }

    /// Gets the parent node of `id`, if any.
    pub fn parent(&self, id: usize) -> Option<&AstNode> {
        self.index
            .get(id)
            .and_then(|n| n.parent.and_then(|p| self.index.get(p)))
    }

    /// Returns the direct children of node `id`.
    pub fn children(&self, id: usize) -> Vec<&AstNode> {
        self.index
            .get(id)
            .map(|n| {
                n.children
                    .iter()
                    .filter_map(|c| self.index.get(c.id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Exports the AST to DOT format.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph AST {\n");
        for node in &self.index {
            let label = match &node.value {
                JsonValue::String(s) => format!("{}:{}", node.kind, s),
                _ => node.kind.clone(),
            };
            out.push_str(&format!("    {} [label=\"{}\"];\n", node.id, label));
            for child in &node.children {
                out.push_str(&format!("    {} -> {};\n", node.id, child.id));
            }
        }
        out.push('}');
        out
    }

    /// Exports the AST to Mermaid format.
    pub fn to_mermaid(&self) -> String {
        let mut out = String::from("graph TD\n");
        for node in &self.index {
            let label = match &node.value {
                JsonValue::String(s) => format!("{}:{}", node.kind, s),
                _ => node.kind.clone(),
            };
            out.push_str(&format!("    {}[\"{}\"]\n", node.id, label));
            for child in &node.children {
                out.push_str(&format!("    {} --> {}\n", node.id, child.id));
            }
        }
        out
    }

    /// Exports the AST to JSON.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}
