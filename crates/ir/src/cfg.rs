use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

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

// ── Real basic-block CFG ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CfgEdgeKind {
    Sequential,
    ConditionalTrue,
    ConditionalFalse,
    LoopBack,
    Exception,
    ExceptionFinally,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub from: usize,
    pub to: usize,
    pub kind: CfgEdgeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BasicBlock {
    pub id: usize,
    pub label: String,
    /// AstNode ids that belong to this block.
    pub stmts: Vec<usize>,
    pub line_start: usize,
    pub line_end: usize,
    pub function: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileCFG {
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
    /// Maps function name to (entry_block_id, exit_block_id).
    pub functions: HashMap<String, (usize, usize)>,
}

impl FileCFG {
    /// Returns true if `to` is reachable from `from` following directed edges.
    pub fn is_reachable(&self, from: usize, to: usize) -> bool {
        if from == to {
            return true;
        }
        let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
        for e in &self.edges {
            adj.entry(e.from).or_default().push(e.to);
        }
        let mut visited = HashSet::new();
        let mut q = VecDeque::new();
        q.push_back(from);
        while let Some(cur) = q.pop_front() {
            if !visited.insert(cur) {
                continue;
            }
            if cur == to {
                return true;
            }
            if let Some(nexts) = adj.get(&cur) {
                for &n in nexts {
                    if !visited.contains(&n) {
                        q.push_back(n);
                    }
                }
            }
        }
        false
    }

    /// Exports blocks and edges to DOT format.
    pub fn to_dot(&self) -> String {
        let mut out = String::from("digraph FileCFG {\n");
        for b in &self.blocks {
            let fn_label = b
                .function
                .as_deref()
                .map(|f| format!(" [{f}]"))
                .unwrap_or_default();
            out.push_str(&format!(
                "    {} [label=\"{}{}\\nL{}-{}\"];\n",
                b.id, b.label, fn_label, b.line_start, b.line_end
            ));
        }
        for e in &self.edges {
            let style = match e.kind {
                CfgEdgeKind::ConditionalTrue => " [label=\"T\"]",
                CfgEdgeKind::ConditionalFalse => " [label=\"F\"]",
                CfgEdgeKind::LoopBack => " [style=dashed label=\"loop\"]",
                CfgEdgeKind::Exception => " [style=dotted label=\"ex\"]",
                CfgEdgeKind::ExceptionFinally => " [style=dotted label=\"finally\"]",
                CfgEdgeKind::Sequential => "",
            };
            out.push_str(&format!("    {} -> {}{style};\n", e.from, e.to));
        }
        out.push('}');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(id: usize, line_start: usize, line_end: usize) -> BasicBlock {
        BasicBlock {
            id,
            label: format!("B{id}"),
            stmts: vec![],
            line_start,
            line_end,
            function: None,
        }
    }

    #[test]
    fn reachability_direct() {
        let cfg = FileCFG {
            blocks: vec![make_block(0, 1, 1), make_block(1, 2, 2)],
            edges: vec![CfgEdge { from: 0, to: 1, kind: CfgEdgeKind::Sequential }],
            functions: HashMap::new(),
        };
        assert!(cfg.is_reachable(0, 1));
        assert!(!cfg.is_reachable(1, 0));
    }

    #[test]
    fn reachability_transitive() {
        let cfg = FileCFG {
            blocks: vec![make_block(0, 1, 1), make_block(1, 2, 2), make_block(2, 3, 3)],
            edges: vec![
                CfgEdge { from: 0, to: 1, kind: CfgEdgeKind::Sequential },
                CfgEdge { from: 1, to: 2, kind: CfgEdgeKind::Sequential },
            ],
            functions: HashMap::new(),
        };
        assert!(cfg.is_reachable(0, 2));
        assert!(!cfg.is_reachable(2, 0));
    }

    #[test]
    fn serde_round_trip() {
        let cfg = FileCFG {
            blocks: vec![make_block(0, 1, 5)],
            edges: vec![CfgEdge { from: 0, to: 0, kind: CfgEdgeKind::LoopBack }],
            functions: [("main".to_string(), (0, 0))].into(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: FileCFG = serde_json::from_str(&json).unwrap();
        assert_eq!(back.blocks[0].id, 0);
        assert_eq!(back.edges[0].kind, CfgEdgeKind::LoopBack);
    }
}
