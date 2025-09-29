use anyhow::Result;
use ir::FileIR;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Serialize)]
pub struct CallGraphAnalysis {
    pub nodes: Vec<CallNode>,
    pub edges: Vec<CallEdge>,
    pub functions: Vec<String>,
    pub call_depth: HashMap<String, usize>,
    pub complexity: CallComplexity,
}

#[derive(Debug, Serialize)]
pub struct CallNode {
    pub id: String,
    pub name: String,
    pub calls: Vec<String>,
    pub called_by: Vec<String>,
    pub is_entry: bool,
    pub is_exit: bool,
}

#[derive(Debug, Serialize)]
pub struct CallEdge {
    pub from: String,
    pub to: String,
    pub weight: usize,
}

#[derive(Debug, Serialize)]
pub struct CallComplexity {
    pub total_functions: usize,
    pub max_depth: usize,
    pub avg_calls_per_function: f64,
    pub cycles: Vec<Vec<String>>,
}

pub fn analyze_callgraph(files: &[FileIR], direct_only: bool) -> Result<CallGraphAnalysis> {
    let mut analysis = CallGraphAnalysis {
        nodes: Vec::new(),
        edges: Vec::new(),
        functions: Vec::new(),
        call_depth: HashMap::new(),
        complexity: CallComplexity {
            total_functions: 0,
            max_depth: 0,
            avg_calls_per_function: 0.0,
            cycles: Vec::new(),
        },
    };

    // Build the call graph from the parsed files
    let call_graph = build_callgraph_from_files(files)?;

    // Extract function names for reporting
    analysis.functions = extract_functions(&call_graph);
    analysis.complexity.total_functions = analysis.functions.len();

    // Build the node set from function definitions
    for (func, calls) in &call_graph {
        let called_by = find_called_by(func, &call_graph);
        let is_entry = called_by.is_empty();
        let is_exit = calls.is_empty();

        analysis.nodes.push(CallNode {
            id: func.clone(),
            name: func.clone(),
            calls: if direct_only {
                calls.clone()
            } else {
                calls.clone()
            },
            called_by,
            is_entry,
            is_exit,
        });
    }

    // Add directed edges for each call site
    for (from, calls) in &call_graph {
        for to in calls {
            analysis.edges.push(CallEdge {
                from: from.clone(),
                to: to.clone(),
                weight: 1,
            });
        }
    }

    // Capture call-depth metrics and averages
    analysis.call_depth = calculate_call_depths(&call_graph);
    analysis.complexity.max_depth = analysis.call_depth.values().max().copied().unwrap_or(0);
    analysis.complexity.avg_calls_per_function =
        analysis.edges.len() as f64 / analysis.functions.len().max(1) as f64;

    // Detect recursion cycles so the UI can highlight them
    analysis.complexity.cycles = detect_cycles(&call_graph);

    Ok(analysis)
}

fn build_callgraph_from_files(files: &[FileIR]) -> Result<HashMap<String, Vec<String>>> {
    let mut call_graph = HashMap::new();

    for file in files {
        if let Some(ast) = &file.ast {
            extract_calls_from_ast(ast, &mut call_graph);
        }
    }

    Ok(call_graph)
}

fn extract_calls_from_ast(ast: &ir::FileAst, call_graph: &mut HashMap<String, Vec<String>>) {
    for node in &ast.nodes {
        if node.kind.contains("Function") {
            if let Some(func_name) = node.value.as_str() {
                let mut calls = Vec::new();
                extract_calls_from_node(node, &mut calls);
                call_graph.insert(func_name.to_string(), calls);
            }
        }
    }
}

fn extract_calls_from_node(node: &ir::AstNode, calls: &mut Vec<String>) {
    if node.kind == "Call" || node.kind == "CallExpression" {
        if let Some(name) = node.value.as_str() {
            calls.push(name.to_string());
        }
    }

    for child in &node.children {
        extract_calls_from_node(child, calls);
    }
}

fn extract_functions(call_graph: &HashMap<String, Vec<String>>) -> Vec<String> {
    let mut functions = call_graph.keys().cloned().collect::<Vec<_>>();
    functions.sort();
    functions
}

fn find_called_by(func: &str, call_graph: &HashMap<String, Vec<String>>) -> Vec<String> {
    let mut called_by = Vec::new();

    for (caller, calls) in call_graph {
        if calls.contains(&func.to_string()) {
            called_by.push(caller.clone());
        }
    }

    called_by
}

fn calculate_call_depths(call_graph: &HashMap<String, Vec<String>>) -> HashMap<String, usize> {
    let mut depths = HashMap::new();
    let mut visited = HashSet::new();

    for func in call_graph.keys() {
        if !visited.contains(func) {
            calculate_depth_recursive(func, call_graph, &mut depths, &mut visited, 0);
        }
    }

    depths
}

fn calculate_depth_recursive(
    func: &str,
    call_graph: &HashMap<String, Vec<String>>,
    depths: &mut HashMap<String, usize>,
    visited: &mut HashSet<String>,
    current_depth: usize,
) {
    if visited.contains(func) {
        return;
    }

    visited.insert(func.to_string());
    depths.insert(func.to_string(), current_depth);

    if let Some(calls) = call_graph.get(func) {
        for callee in calls {
            calculate_depth_recursive(callee, call_graph, depths, visited, current_depth + 1);
        }
    }
}

fn detect_cycles(call_graph: &HashMap<String, Vec<String>>) -> Vec<Vec<String>> {
    let mut cycles = Vec::new();
    let mut visited = HashSet::new();
    let mut rec_stack = HashSet::new();
    let mut path = Vec::new();

    for func in call_graph.keys() {
        if !visited.contains(func) {
            detect_cycle_dfs(
                func,
                call_graph,
                &mut visited,
                &mut rec_stack,
                &mut path,
                &mut cycles,
            );
        }
    }

    cycles
}

fn detect_cycle_dfs(
    func: &str,
    call_graph: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    rec_stack: &mut HashSet<String>,
    path: &mut Vec<String>,
    cycles: &mut Vec<Vec<String>>,
) {
    if rec_stack.contains(func) {
        // Cycle detected starting at the first repeated node
        if let Some(start) = path.iter().position(|f| f == func) {
            cycles.push(path[start..].to_vec());
        }
        return;
    }

    if visited.contains(func) {
        return;
    }

    visited.insert(func.to_string());
    rec_stack.insert(func.to_string());
    path.push(func.to_string());

    if let Some(calls) = call_graph.get(func) {
        for callee in calls {
            detect_cycle_dfs(callee, call_graph, visited, rec_stack, path, cycles);
        }
    }

    rec_stack.remove(func);
    path.pop();
}

pub fn format_callgraph_analysis(analysis: &CallGraphAnalysis, format: crate::Format) -> String {
    match format {
        crate::Format::Json => {
            serde_json::to_string_pretty(analysis).unwrap_or_else(|_| "{}".to_string())
        }
        crate::Format::Dot => callgraph_to_dot(analysis),
        crate::Format::Mermaid => callgraph_to_mermaid(analysis),
        _ => callgraph_to_text(analysis),
    }
}

fn callgraph_to_text(analysis: &CallGraphAnalysis) -> String {
    let mut output = String::new();

    output.push_str("=== CALL GRAPH ANALYSIS ===\n\n");

    output.push_str(&format!("📊 COMPLEXITY METRICS:\n"));
    output.push_str(&format!(
        "  • Total Functions: {}\n",
        analysis.complexity.total_functions
    ));
    output.push_str(&format!(
        "  • Max Call Depth: {}\n",
        analysis.complexity.max_depth
    ));
    output.push_str(&format!(
        "  • Avg Calls per Function: {:.2}\n",
        analysis.complexity.avg_calls_per_function
    ));
    output.push_str(&format!(
        "  • Cycles Detected: {}\n",
        analysis.complexity.cycles.len()
    ));
    output.push('\n');

    if !analysis.complexity.cycles.is_empty() {
        output.push_str("🔄 CYCLES DETECTED:\n");
        for (i, cycle) in analysis.complexity.cycles.iter().enumerate() {
            output.push_str(&format!(
                "  {}. {} -> {}\n",
                i + 1,
                cycle.join(" -> "),
                cycle[0]
            ));
        }
        output.push('\n');
    }

    output.push_str("🔧 FUNCTIONS:\n");
    for node in &analysis.nodes {
        let depth = analysis.call_depth.get(&node.name).copied().unwrap_or(0);
        let status = if node.is_entry {
            "ENTRY"
        } else if node.is_exit {
            "EXIT"
        } else {
            "INTERNAL"
        };
        output.push_str(&format!(
            "  • {} (depth: {}, status: {})\n",
            node.name, depth, status
        ));
        if !node.calls.is_empty() {
            output.push_str(&format!("    calls: {}\n", node.calls.join(", ")));
        }
    }
    output.push('\n');

    output.push_str("🔗 CALL RELATIONSHIPS:\n");
    for edge in &analysis.edges {
        output.push_str(&format!("  • {} -> {}\n", edge.from, edge.to));
    }

    output
}

fn callgraph_to_dot(analysis: &CallGraphAnalysis) -> String {
    let mut dot = String::from("digraph CallGraph {\n");
    dot.push_str("    rankdir=TB;\n");
    dot.push_str("    node [style=filled, shape=box, fontname=\"Arial\"];\n");
    dot.push_str("    edge [color=gray, fontname=\"Arial\"];\n\n");

    // Colour nodes according to their role in the graph
    for node in &analysis.nodes {
        let color = if node.is_entry {
            "#2ECC71" // entry point
        } else if node.is_exit {
            "#E74C3C" // exit point
        } else {
            "#3498DB" // internal function
        };

        let depth = analysis.call_depth.get(&node.name).copied().unwrap_or(0);
        dot.push_str(&format!(
            "    {} [label=\"{}\\n(depth: {})\", fillcolor=\"{}\"];\n",
            node.name.replace('-', "_"),
            node.name,
            depth,
            color
        ));
    }

    // Edges
    for edge in &analysis.edges {
        dot.push_str(&format!(
            "    {} -> {};\n",
            edge.from.replace('-', "_"),
            edge.to.replace('-', "_")
        ));
    }

    // Highlight cycles so they stand out in the diagram
    for cycle in &analysis.complexity.cycles {
        for i in 0..cycle.len() {
            let from = cycle[i].replace('-', "_");
            let to = cycle[(i + 1) % cycle.len()].replace('-', "_");
            dot.push_str(&format!(
                "    {} -> {} [color=red, penwidth=3];\n",
                from, to
            ));
        }
    }

    dot.push('}');
    dot
}

fn callgraph_to_mermaid(analysis: &CallGraphAnalysis) -> String {
    let mut mermaid = String::from("graph TD\n");

    // Nodes
    for node in &analysis.nodes {
        let shape = if node.is_entry {
            "(({}))"
        } else if node.is_exit {
            "[{}]"
        } else {
            "({})"
        };
        mermaid.push_str(&format!(
            "    {}\n",
            shape.replace("{}", &node.name.replace('-', "_"))
        ));
    }

    // Edges
    for edge in &analysis.edges {
        mermaid.push_str(&format!(
            "    {} --> {}\n",
            edge.from.replace('-', "_"),
            edge.to.replace('-', "_")
        ));
    }

    mermaid
}
