//! Main types for **IR-Doc** and re-export of **IR-AST**.
//!
//! `IR-Doc` flattens configuration documents into independent nodes
//! identified by a `path`. In contrast, `IR-AST` (module [`ast`])
//! preserves the syntax tree hierarchy. Both share the
//! [`Meta`] structure for location data.

pub mod ast;
pub mod cfg;
pub mod dfg;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};

pub use ast::{AstNode, FileAst, Meta};
pub use cfg::{CFGNode, CFG};
pub use dfg::{stable_id, DFNode, DFNodeKind, DataFlowGraph, Symbol};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Classification of a symbol for data flow analysis.
pub enum SymbolKind {
    Source,
    Sink,
    Sanitizer,
    Special,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Individual node within the flattened intermediate representation.
pub struct IRNode {
    /// Stable identifier of the node.
    #[serde(default)]
    pub id: usize,
    /// Logical document type: "dockerfile", "k8s", etc.
    pub kind: String,
    /// Logical path within the document (for YAML/JSON): a.b.c[0]
    pub path: String,
    /// Value of the node (for Dockerfile it can be a string)
    pub value: JsonValue,
    /// Location metadata
    pub meta: Meta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Set of nodes belonging to a processed file.
pub struct FileIR {
    pub file_path: String,
    pub file_type: String, // dockerfile|k8s|yaml
    pub nodes: Vec<IRNode>,
    /// Optional AST representation of the file for structural queries.
    pub ast: Option<FileAst>,
    /// Full file content when textual queries are required.
    pub source: Option<String>,
    /// Lines with suppression comments.
    pub suppressed: HashSet<usize>,
    pub dfg: Option<DataFlowGraph>,
    pub symbols: HashMap<String, Symbol>,
    /// Logical type associated with each symbol.
    #[serde(default)]
    pub symbol_types: HashMap<String, SymbolKind>,
    /// Scope of each symbol.
    #[serde(default)]
    pub symbol_scopes: HashMap<String, String>,
    /// Module to which the symbol belongs for cross-file references.
    #[serde(default)]
    pub symbol_modules: HashMap<String, String>,
}

impl FileIR {
    /// Creates a new empty instance for the specified file.
    ///
    /// # Example
    /// ```
    /// use ir::{FileIR, IRNode, Meta};
    /// let mut fir = FileIR::new("a.yaml".into(), "yaml".into());
    /// fir.push(IRNode {
    ///     id: 0,
    ///     kind: "yaml".into(),
    ///     path: "a".into(),
    ///     value: serde_json::json!(1),
    ///     meta: Meta { file: "a.yaml".into(), line: 1, column: 1 },
    /// });
    /// assert_eq!(fir.nodes.len(), 1);
    /// ```
    pub fn new(file_path: String, file_type: String) -> Self {
        Self {
            file_path,
            file_type,
            nodes: Vec::new(),
            ast: None,
            source: None,
            suppressed: HashSet::new(),
            dfg: None,
            symbols: HashMap::new(),
            symbol_types: HashMap::new(),
            symbol_scopes: HashMap::new(),
            symbol_modules: HashMap::new(),
        }
    }
    /// Adds a node to the collection.
    pub fn push(&mut self, mut node: IRNode) {
        if node.id == 0 {
            node.id = stable_id(
                &self.file_path,
                node.meta.line,
                node.meta.column,
                &node.path,
            );
        }
        self.nodes.push(node);
    }
}

#[cfg(test)]
mod tests;
