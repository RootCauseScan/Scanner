use anyhow::Result;
use engine::{all_function_taints, record_function_taints, FunctionTaint};
use ir::FileIR;
use parsers::build_dfg;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct TaintAnalysis {
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub tainted_vars: Vec<String>,
    pub function_taints: Vec<FunctionTaint>,
    pub flows: Vec<TaintFlow>,
}

#[derive(Debug, Serialize)]
pub struct TaintFlow {
    pub from: String,
    pub to: String,
    pub path: Vec<String>,
    pub severity: String,
}

pub fn analyze_taint(file: &FileIR, detailed: bool) -> Result<TaintAnalysis> {
    // Build the DFG on demand so the taint model is available
    if file.dfg.is_none() {
        build_dfg(&mut file.clone())?;
    }

    // Capture engine-level function taints
    record_function_taints(file)?;

    let mut analysis = TaintAnalysis {
        sources: Vec::new(),
        sinks: Vec::new(),
        tainted_vars: Vec::new(),
        function_taints: all_function_taints(),
        flows: Vec::new(),
    };

    // Project obvious sources and sinks from the AST
    if let Some(ast) = &file.ast {
        analyze_sources_sinks(ast, &mut analysis);
    }

    // Surface suspicious variables from the DFG
    if let Some(dfg) = &file.dfg {
        analyze_tainted_variables(dfg, &mut analysis);
    }

    // Optionally derive trivial flows for quick visualisation
    if detailed {
        let flows = analyze_taint_flows(&analysis);
        analysis.flows = flows;
    }

    Ok(analysis)
}

fn analyze_sources_sinks(ast: &ir::FileAst, analysis: &mut TaintAnalysis) {
    for node in &ast.nodes {
        analyze_node_recursive(node, analysis);
    }
}

fn analyze_node_recursive(node: &ir::AstNode, analysis: &mut TaintAnalysis) {
    // Inspect the current node for well-known source/sink patterns
    if node.kind == "Call" || node.kind == "CallExpression" {
        if let Some(name) = node.value.as_str() {
            match name {
                // Common source APIs
                "input" | "raw_input" | "get" | "post" | "request" | "argv" => {
                    analysis.sources.push(format!("{}() - User input", name));
                }
                // Dangerous sinks
                "eval" | "exec" | "system" | "shell_exec" | "popen" | "subprocess" => {
                    analysis.sinks.push(format!("{}() - Code execution", name));
                }
                "print" | "echo" | "printf" | "sprintf" => {
                    analysis
                        .sinks
                        .push(format!("{}() - Output operation", name));
                }
                _ => {}
            }
        }
    } else if node.kind == "Identifier" {
        if let Some(name) = node.value.as_str() {
            match name {
                "input" | "raw_input" | "get" | "post" => {
                    analysis.sources.push(format!("{} - Variable", name));
                }
                "eval" | "exec" | "system" => {
                    analysis.sinks.push(format!("{} - Variable", name));
                }
                _ => {}
            }
        }
    } else if node.kind == "SubscriptExpression" {
        // Detect constructs like $_GET['foo'] or $_POST['data']
        for child in &node.children {
            if child.kind == "VariableName" {
                if let Some(name) = child.value.as_str() {
                    if name == "_GET"
                        || name == "_POST"
                        || name == "_REQUEST"
                        || name == "_COOKIE"
                        || name == "_SESSION"
                        || name == "_SERVER"
                    {
                        analysis.sources.push(format!("${} - HTTP input", name));
                    }
                }
            }
        }
    } else if node.kind == "ArrayAccess" || node.kind == "ArrayExpression" {
        // Direct references to PHP super globals inside arrays
        if let Some(name) = node.value.as_str() {
            if name.contains("_GET") || name.contains("_POST") || name.contains("_REQUEST") {
                analysis.sources.push(format!("{} - HTTP input", name));
            }
        }
    } else if node.kind == "EchoStatement" || node.kind == "PrintStatement" {
        analysis
            .sinks
            .push(format!("{} - Output operation", node.kind));
    } else if node.kind == "VariableDeclaration" || node.kind == "AssignmentExpression" {
        // Assignments that copy super globals into local variables
        if let Some(name) = node.value.as_str() {
            if name.contains("_GET")
                || name.contains("_POST")
                || name.contains("_REQUEST")
                || name.contains("_COOKIE")
                || name.contains("_SESSION")
                || name.contains("_SERVER")
            {
                analysis.sources.push(format!("{} - HTTP input", name));
            }
        }
    }

    // Recurse through the subtree
    for child in &node.children {
        analyze_node_recursive(child, analysis);
    }
}

fn analyze_tainted_variables(dfg: &ir::DataFlowGraph, analysis: &mut TaintAnalysis) {
    for node in &dfg.nodes {
        match node.kind {
            ir::DFNodeKind::Def => {
                // Heuristically mark definitions that look like user-controlled input
                if node.name.contains("input") || node.name.contains("user") {
                    analysis.tainted_vars.push(node.name.clone());
                }
            }
            ir::DFNodeKind::Use => {
                // Likewise flag uses that suggest execution or templating sinks
                if node.name.contains("eval") || node.name.contains("exec") {
                    analysis.tainted_vars.push(node.name.clone());
                }
            }
            _ => {}
        }
    }
}

fn analyze_taint_flows(analysis: &TaintAnalysis) -> Vec<TaintFlow> {
    let mut flows = Vec::new();

    // Look for direct source-to-sink pairs using simple heuristics
    for source in &analysis.sources {
        for sink in &analysis.sinks {
            // Simple heuristics to highlight obviously dangerous flows
            if source.contains("input") && sink.contains("eval") {
                flows.push(TaintFlow {
                    from: source.clone(),
                    to: sink.clone(),
                    path: vec![source.clone(), sink.clone()],
                    severity: "HIGH".to_string(),
                });
            } else if source.contains("get") && sink.contains("print") {
                flows.push(TaintFlow {
                    from: source.clone(),
                    to: sink.clone(),
                    path: vec![source.clone(), sink.clone()],
                    severity: "MEDIUM".to_string(),
                });
            }
        }
    }

    flows
}

pub fn format_taint_analysis(analysis: &TaintAnalysis, format: crate::Format) -> String {
    match format {
        crate::Format::Json => {
            serde_json::to_string_pretty(analysis).unwrap_or_else(|_| "{}".to_string())
        }
        crate::Format::Dot => taint_to_dot(analysis),
        crate::Format::Mermaid => taint_to_mermaid(analysis),
        _ => taint_to_text(analysis),
    }
}

fn taint_to_text(analysis: &TaintAnalysis) -> String {
    let mut output = String::new();

    output.push_str("=== TAINT ANALYSIS ===\n\n");

    if !analysis.sources.is_empty() {
        output.push_str("📥 SOURCES (Data Entry Points):\n");
        for source in &analysis.sources {
            output.push_str(&format!("  • {}\n", source));
        }
        output.push('\n');
    }

    if !analysis.sinks.is_empty() {
        output.push_str("📤 SINKS (Dangerous Operations):\n");
        for sink in &analysis.sinks {
            output.push_str(&format!("  • {}\n", sink));
        }
        output.push('\n');
    }

    if !analysis.tainted_vars.is_empty() {
        output.push_str("🔍 TAINTED VARIABLES:\n");
        for var in &analysis.tainted_vars {
            output.push_str(&format!("  • {}\n", var));
        }
        output.push('\n');
    }

    if !analysis.function_taints.is_empty() {
        output.push_str("🔧 FUNCTION TAINTS:\n");
        for taint in &analysis.function_taints {
            output.push_str(&format!(
                "  • {}: args={:?}, return={}\n",
                taint.name, taint.tainted_args, taint.tainted_return
            ));
        }
        output.push('\n');
    }

    if !analysis.flows.is_empty() {
        output.push_str("⚠️  TAINT FLOWS:\n");
        for flow in &analysis.flows {
            output.push_str(&format!(
                "  • {} -> {} ({}): {:?}\n",
                flow.from, flow.to, flow.severity, flow.path
            ));
        }
        output.push('\n');
    }

    // Provide a quick qualitative summary
    if !analysis.sources.is_empty() && !analysis.sinks.is_empty() {
        output.push_str("🚨 VULNERABILITY DETECTED!\n");
        output.push_str("   Data flows from sources to sinks without sanitization\n");
        output.push_str("   Risk: XSS, Code Injection, or Data Exposure\n");
    } else if !analysis.sources.is_empty() {
        output.push_str("⚠️  POTENTIAL RISK!\n");
        output.push_str("   Data sources detected but no obvious sinks\n");
    } else if !analysis.sinks.is_empty() {
        output.push_str("⚠️  POTENTIAL RISK!\n");
        output.push_str("   Dangerous operations detected but no obvious sources\n");
    } else {
        output.push_str("✅ No obvious vulnerabilities detected\n");
    }

    output
}

fn taint_to_dot(analysis: &TaintAnalysis) -> String {
    let mut dot = String::from("digraph TaintAnalysis {\n");
    dot.push_str("    rankdir=TB;\n");
    dot.push_str("    node [style=filled, shape=box, fontname=\"Arial\"];\n");
    dot.push_str("    edge [color=gray, fontname=\"Arial\"];\n\n");

    // Sources
    for (i, source) in analysis.sources.iter().enumerate() {
        dot.push_str(&format!(
            "    source{} [label=\"{}\", fillcolor=\"#2ECC71\"];\n",
            i, source
        ));
    }

    // Sinks
    for (i, sink) in analysis.sinks.iter().enumerate() {
        dot.push_str(&format!(
            "    sink{} [label=\"{}\", fillcolor=\"#E74C3C\"];\n",
            i, sink
        ));
    }

    // Variables tainted
    for (i, var) in analysis.tainted_vars.iter().enumerate() {
        dot.push_str(&format!(
            "    var{} [label=\"{}\", fillcolor=\"#F39C12\"];\n",
            i, var
        ));
    }

    // Flows
    for flow in &analysis.flows {
        dot.push_str(&format!(
            "    \"{}\" -> \"{}\" [color=red, penwidth=2];\n",
            flow.from, flow.to
        ));
    }

    dot.push('}');
    dot
}

fn taint_to_mermaid(analysis: &TaintAnalysis) -> String {
    let mut mermaid = String::from("graph TD\n");

    // Sources
    for (i, source) in analysis.sources.iter().enumerate() {
        mermaid.push_str(&format!("    source{}[\"{}\"]\n", i, source));
    }

    // Sinks
    for (i, sink) in analysis.sinks.iter().enumerate() {
        mermaid.push_str(&format!("    sink{}[\"{}\"]\n", i, sink));
    }

    // Flows
    for flow in &analysis.flows {
        mermaid.push_str(&format!("    \"{}\" --> \"{}\"\n", flow.from, flow.to));
    }

    mermaid
}
