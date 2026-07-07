use ir::{AstNode, FileIR};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, OnceLock, RwLock};

/// Graph of function calls (directed: caller → callee).
#[derive(Debug, Clone, Default)]
pub struct CallGraph {
    pub edges: HashMap<String, HashSet<String>>, // directed: caller → callee
}

impl CallGraph {
    /// Build a call graph from the AST of all files.
    pub fn build(files: &[FileIR]) -> Self {
        let mut edges: HashMap<String, HashSet<String>> = HashMap::new();
        for f in files {
            let Some(ast) = &f.ast else { continue };
            let src = f.source.as_deref().unwrap_or("");
            let lines: Vec<&str> = src.lines().collect();
            let mut id_to_name = HashMap::new();
            for n in &ast.nodes {
                collect_names(n, &mut id_to_name, None);
            }
            for n in &ast.nodes {
                walk(n, &lines, None, &id_to_name, &mut edges);
            }
        }
        Self { edges }
    }

    fn neighbors(&self, func: &str) -> Option<&HashSet<String>> {
        self.edges.get(func)
    }
}

fn collect_names(node: &AstNode, map: &mut HashMap<usize, String>, class_ctx: Option<&str>) {
    let mut cur_class = class_ctx;
    if node.kind == "ClassDeclaration" {
        if let Some(name) = node.value.as_str() {
            cur_class = Some(name);
        }
    }
    if node.kind.contains("Function") || node.kind == "MethodDeclaration" {
        if let Some(name) = node.value.as_str() {
            let qualified = match cur_class {
                Some(cls) => format!("{cls}.{name}"),
                None => name.to_string(),
            };
            map.insert(node.id, qualified);
        }
    }
    for c in &node.children {
        collect_names(c, map, cur_class);
    }
}

fn walk(
    node: &AstNode,
    lines: &[&str],
    current: Option<usize>,
    id_to_name: &HashMap<usize, String>,
    edges: &mut HashMap<String, HashSet<String>>,
) {
    let mut cur = current;
    if node.kind.contains("Function") || node.kind == "MethodDeclaration" {
        cur = Some(node.id);
    }
    if node.kind == "CallExpression" || node.kind == "Call" {
        if let Some(caller_id) = cur {
            let line = node.meta.line;
            let code = lines.get(line.saturating_sub(1)).copied().unwrap_or("").trim();
            let call_part = if let Some(eq) = code.find('=') {
                code[eq + 1..].trim()
            } else {
                code
            };
            if let Some((callee, _)) = parse_call(call_part) {
                if let Some(caller) = id_to_name.get(&caller_id) {
                    edges
                        .entry(caller.clone())
                        .or_default()
                        .insert(callee.clone());
                }
            }
        }
    }
    for c in &node.children {
        walk(c, lines, cur, id_to_name, edges);
    }
}

pub fn parse_call(code: &str) -> Option<(String, Vec<String>)> {
    let call = code.trim();
    let mut open = None;
    let mut paren = 0usize;
    let mut angle = 0usize;
    for (i, ch) in call.char_indices() {
        match ch {
            '<' => angle += 1,
            '>' => angle = angle.saturating_sub(1),
            '(' if angle == 0 => {
                if paren == 0 {
                    open = Some(i);
                }
                paren += 1;
            }
            ')' if angle == 0 => {
                paren = paren.saturating_sub(1);
                if paren == 0 {
                    let open = open?;
                    let name = call[..open].trim().to_string();
                    let args_str = &call[open + 1..i];
                    let args = split_args(args_str);
                    return Some((name, args));
                }
            }
            _ => {}
        }
    }
    None
}

fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut paren = 0usize;
    let mut angle = 0usize;
    for (i, ch) in s.char_indices() {
        match ch {
            '(' => paren += 1,
            ')' => paren = paren.saturating_sub(1),
            '<' => angle += 1,
            '>' => angle = angle.saturating_sub(1),
            ',' if paren == 0 && angle == 0 => {
                out.push(s[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < s.len() {
        let arg = s[start..].trim();
        if !arg.is_empty() {
            out.push(arg.to_string());
        }
    }
    out
}

static CG: OnceLock<RwLock<Arc<CallGraph>>> = OnceLock::new();

fn cg_lock() -> &'static RwLock<Arc<CallGraph>> {
    CG.get_or_init(|| RwLock::new(Arc::new(CallGraph::default())))
}

/// Replace the global call graph.
pub fn set_call_graph(g: CallGraph) {
    if let Ok(mut cg) = cg_lock().write() {
        *cg = Arc::new(g);
    }
}

/// Access the global call graph as a cheap Arc clone.
pub fn get_call_graph() -> Arc<CallGraph> {
    cg_lock().read().expect("call graph lock poisoned").clone()
}

/// Tracks taint propagation between functions using the call graph.
pub struct TaintTracker {
    graph: Arc<CallGraph>,
    sources: HashSet<String>,
    sinks: HashSet<String>,
}

impl TaintTracker {
    pub fn new(graph: Arc<CallGraph>) -> Self {
        Self {
            graph,
            sources: HashSet::new(),
            sinks: HashSet::new(),
        }
    }

    pub fn mark_source(&mut self, name: &str) {
        self.sources.insert(name.to_string());
    }

    pub fn mark_sink(&mut self, name: &str) {
        self.sinks.insert(name.to_string());
    }

    /// Returns true if a sink is reachable from any source via the directed call graph.
    pub fn has_flow(&self) -> bool {
        let mut visited = HashSet::new();
        let mut q: VecDeque<String> = self.sources.iter().cloned().collect();
        while let Some(cur) = q.pop_front() {
            if !visited.insert(cur.clone()) {
                continue;
            }
            if self.sinks.contains(&cur) {
                return true;
            }
            if let Some(neigh) = self.graph.neighbors(&cur) {
                for n in neigh {
                    if !visited.contains(n) {
                        q.push_back(n.clone());
                    }
                }
            }
        }
        false
    }
}
