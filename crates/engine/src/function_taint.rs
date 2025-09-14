use anyhow::{anyhow, Result};
use ir::{AstNode, FileIR};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{OnceLock, RwLock};

/// Taint data for a function: which arguments are tainted and whether the
/// return value is tainted. Stored globally by function name.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FunctionTaint {
    pub name: String,
    pub tainted_args: HashSet<usize>,
    pub tainted_return: bool,
}

static FN_TAINTS: OnceLock<RwLock<HashMap<String, FunctionTaint>>> = OnceLock::new();
static FN_IDS: OnceLock<RwLock<HashMap<usize, String>>> = OnceLock::new();
static CALL_GRAPH: OnceLock<RwLock<HashMap<usize, HashSet<usize>>>> = OnceLock::new();

fn map() -> &'static RwLock<HashMap<String, FunctionTaint>> {
    FN_TAINTS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn id_map() -> &'static RwLock<HashMap<usize, String>> {
    FN_IDS.get_or_init(|| RwLock::new(HashMap::new()))
}

fn graph() -> &'static RwLock<HashMap<usize, HashSet<usize>>> {
    CALL_GRAPH.get_or_init(|| RwLock::new(HashMap::new()))
}

fn register_function(id: usize, name: &str) {
    if let Ok(mut m) = id_map().write() {
        m.insert(id, name.to_string());
    }
}

fn function_name(id: usize) -> Option<String> {
    id_map().read().ok()?.get(&id).cloned()
}

fn register_edge(caller: Option<usize>, callee: usize) {
    if let Some(cid) = caller {
        if let Ok(mut g) = graph().write() {
            g.entry(cid).or_default().insert(callee);
        }
    }
}

fn propagate_returns() -> Result<()> {
    let mut changed = true;
    while changed {
        changed = false;
        let graph = graph().read().map_err(|_| anyhow!("lock poisoned"))?;
        let names = id_map().read().map_err(|_| anyhow!("lock poisoned"))?;
        let mut taints = map().read().map_err(|_| anyhow!("lock poisoned"))?;
        for (caller, callees) in graph.iter() {
            let Some(caller_name) = names.get(caller).cloned() else {
                continue;
            };
            for callee in callees {
                let Some(callee_name) = names.get(callee) else {
                    continue;
                };
                if taints.get(callee_name).is_some_and(|t| t.tainted_return) {
                    drop(taints);
                    let mut m = map().write().map_err(|_| anyhow!("lock poisoned"))?;
                    let entry = m
                        .entry(caller_name.clone())
                        .or_insert_with(|| FunctionTaint {
                            name: caller_name.clone(),
                            tainted_args: HashSet::new(),
                            tainted_return: false,
                        });
                    if !entry.tainted_return {
                        entry.tainted_return = true;
                        changed = true;
                    }
                    taints = map().read().map_err(|_| anyhow!("lock poisoned"))?;
                }
            }
        }
    }
    Ok(())
}

/// Registers taint information for a single function call.
fn register_call(name: &str, args: &[usize], ret_tainted: bool) -> Result<()> {
    if args.is_empty() && !ret_tainted {
        return Ok(());
    }
    let mut map = map().write().map_err(|_| anyhow!("lock poisoned"))?;
    let entry = map
        .entry(name.to_string())
        .or_insert_with(|| FunctionTaint {
            name: name.to_string(),
            tainted_args: HashSet::new(),
            tainted_return: false,
        });
    for &a in args {
        entry.tainted_args.insert(a);
    }
    if ret_tainted {
        entry.tainted_return = true;
    }
    Ok(())
}

/// Computes which variables in a file are tainted using its DFG.
fn tainted_vars(file: &FileIR) -> HashSet<String> {
    let Some(dfg) = &file.dfg else {
        return HashSet::new();
    };
    let mut id_to_index = HashMap::with_capacity(dfg.nodes.len());
    for (i, node) in dfg.nodes.iter().enumerate() {
        id_to_index.insert(node.id, i);
    }

    let mut adj: HashMap<usize, Vec<usize>> = HashMap::with_capacity(dfg.edges.len());
    let mut indeg: HashMap<usize, usize> = HashMap::with_capacity(dfg.nodes.len());
    for &(from, to) in &dfg.edges {
        adj.entry(from).or_default().push(to);
        *indeg.entry(to).or_default() += 1;
    }
    let mut q = VecDeque::with_capacity(dfg.nodes.len());
    let mut seen = HashSet::new();
    let mut out = HashSet::new();
    for node in &dfg.nodes {
        if matches!(node.kind, ir::DFNodeKind::Def)
            && indeg.get(&node.id).copied().unwrap_or(0) == 0
            && file.symbols.get(&node.name).is_none_or(|s| !s.sanitized)
        {
            q.push_back(node.id);
            seen.insert(node.id);
            out.insert(node.name.clone());
        }
    }
    while let Some(id) = q.pop_front() {
        if let Some(neigh) = adj.get(&id) {
            for &n in neigh {
                if seen.contains(&n) {
                    continue;
                }
                let Some(&idx) = id_to_index.get(&n) else {
                    continue;
                };
                let name = &dfg.nodes[idx].name;
                if file.symbols.get(name).is_some_and(|s| s.sanitized) {
                    continue;
                }
                seen.insert(n);
                out.insert(name.clone());
                q.push_back(n);
            }
        }
    }
    for &(node, func_id) in &dfg.call_returns {
        if let Some(name) = function_name(func_id) {
            if get_function_taint(&name).is_some_and(|t| t.tainted_return) && seen.insert(node) {
                if let Some(&idx) = id_to_index.get(&node) {
                    out.insert(dfg.nodes[idx].name.clone());
                    q.push_back(node);
                }
            }
        }
    }
    out
}

pub(crate) fn parse_call(code: &str) -> Option<(String, Vec<String>)> {
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

fn walk(
    node: &AstNode,
    src: &str,
    tainted: &HashSet<String>,
    current_fn: Option<usize>,
    fn_ids: &HashMap<String, usize>,
) -> Result<()> {
    let mut cur_fn = current_fn;
    if node.kind.contains("Function") {
        cur_fn = Some(node.id);
    }
    if node.kind == "CallExpression" || node.kind == "Call" {
        let line = node.meta.line;
        let code = src.lines().nth(line - 1).unwrap_or("").trim();
        let (lhs, call_part) = if let Some(eq) = code.find('=') {
            (code[..eq].trim(), code[eq + 1..].trim())
        } else {
            ("", code)
        };
        if let Some((name, args)) = parse_call(call_part) {
            let mut tainted_args = Vec::new();
            for (i, a) in args.iter().enumerate() {
                if tainted.contains(a) {
                    tainted_args.push(i);
                }
            }
            let ret_tainted = !lhs.is_empty() && tainted.contains(lhs);
            register_call(&name, &tainted_args, ret_tainted)?;
            if let Some(&callee_id) = fn_ids.get(&name) {
                register_edge(cur_fn, callee_id);
            }
        }
    }
    for c in &node.children {
        walk(c, src, tainted, cur_fn, fn_ids)?;
    }
    Ok(())
}

fn collect_ids(node: &AstNode, map: &mut HashMap<String, usize>) {
    if node.kind.contains("Function") {
        if let Some(name) = node.value.as_str() {
            map.insert(name.to_string(), node.id);
            register_function(node.id, name);
        }
    }
    for c in &node.children {
        collect_ids(c, map);
    }
}

/// Scan a file and update the global map with taint information for each call.
pub fn record_function_taints(file: &FileIR) -> Result<()> {
    let Some(ast) = &file.ast else {
        return Ok(());
    }; // no AST available
    let src = file.source.as_deref().unwrap_or("");

    let mut fn_ids = HashMap::new();
    for n in &ast.nodes {
        collect_ids(n, &mut fn_ids);
    }

    let tainted = tainted_vars(file);
    for n in &ast.nodes {
        walk(n, src, &tainted, None, &fn_ids)?;
    }
    propagate_returns()?;
    Ok(())
}

/// Retrieve taint data for a function by name.
pub fn get_function_taint(name: &str) -> Option<FunctionTaint> {
    map().read().ok()?.get(name).cloned()
}

/// Return all recorded taints.
pub fn all_function_taints() -> Vec<FunctionTaint> {
    map()
        .read()
        .map(|m| m.values().cloned().collect())
        .unwrap_or_default()
}

/// Clear all recorded taint info. Useful in tests.
pub fn reset_function_taints() {
    if let Ok(mut m) = map().write() {
        m.clear();
    }
    if let Ok(mut m) = id_map().write() {
        m.clear();
    }
    if let Ok(mut g) = graph().write() {
        g.clear();
    }
}
