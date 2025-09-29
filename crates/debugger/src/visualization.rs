use ir::{AstNode, FileAst};

/// Render the AST to DOT escaping label quotes that would otherwise break Graphviz
pub fn ast_to_dot_escaped(ast: &FileAst) -> String {
    let dot = ast.to_dot();
    // Replace problematic quotes only inside label contents
    dot.lines()
        .map(|line| {
            if line.contains("label=") {
                // Look for label="..." patterns and replace inner quotes
                if let Some(start) = line.find("label=\"") {
                    let end = line.rfind('"').unwrap_or(line.len());
                    let before = &line[..start + 7]; // "label=\""
                    let content = &line[start + 7..end];
                    let after = &line[end..];

                    let escaped_content = content.replace('"', " ");
                    format!("{}{}{}", before, escaped_content, after)
                } else {
                    line.to_string()
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Generate a simplified DOT graph suited for presentations
pub fn ast_to_simplified_dot(ast: &FileAst) -> String {
    let mut out = String::from("digraph AST {\n");
    out.push_str("    rankdir=TB;\n");
    out.push_str("    node [style=filled, shape=box, fontname=\"Arial\"];\n");
    out.push_str("    edge [color=gray, fontname=\"Arial\"];\n");

    for node in &ast.nodes {
        if is_important_node(node) {
            let label = format_node_label(node);
            let color = get_node_color(node);
            let shape = get_node_shape(node);
            out.push_str(&format!(
                "    {} [label=\"{}\", fillcolor=\"{}\", shape={}];\n",
                node.id, label, color, shape
            ));
        }
    }

    // Only connect nodes that we kept in the simplified view
    for node in &ast.nodes {
        if is_important_node(node) {
            for child in &node.children {
                if is_important_node(child) {
                    out.push_str(&format!("    {} -> {};\n", node.id, child.id));
                }
            }
        }
    }

    out.push('}');
    out
}

/// Generate a simplified text tree for presentations
pub fn ast_to_simplified_tree(ast: &FileAst) -> String {
    let mut out = String::new();
    for node in &ast.nodes {
        if node.parent.is_none() {
            out.push_str(&format_simplified_tree_node(node, 0));
        }
    }
    out
}

fn format_simplified_tree_node(node: &AstNode, depth: usize) -> String {
    let mut out = String::new();
    let indent = "  ".repeat(depth);

    // Only show nodes considered relevant
    if is_important_node(node) {
        let label = format_node_label(node);
        out.push_str(&format!("{}{}\n", indent, label));

        // Recursively process relevant children
        for child in &node.children {
            if is_important_node(child) {
                out.push_str(&format_simplified_tree_node(child, depth + 1));
            }
        }
    }

    out
}

/// Render the full AST in a text tree layout
pub fn ast_to_tree(ast: &FileAst) -> String {
    let mut out = String::new();
    for node in &ast.nodes {
        if node.parent.is_none() {
            out.push_str(&format_tree_node(node, 0, ast));
        }
    }
    out
}

fn format_tree_node(node: &AstNode, depth: usize, ast: &FileAst) -> String {
    let mut out = String::new();
    let indent = "  ".repeat(depth);
    let label = format_node_label(node);
    out.push_str(&format!("{}{}\n", indent, label));

    for child in &node.children {
        out.push_str(&format_tree_node(child, depth + 1, ast));
    }

    out
}

/// Decide if a node should be surfaced in the simplified visualisations
pub fn is_important_node(node: &AstNode) -> bool {
    match node.kind.as_str() {
        // Nodes we always keep
        "FunctionDefinition"
        | "Call"
        | "Parameter"
        | "Identifier"
        | "Block"
        | "ExpressionStatement"
        | "UseDeclaration"
        | "ScopedIdentifier"
        | "VariableDeclaration"
        | "AssignmentExpression"
        | "LetDeclaration"
        | "IfStatement"
        | "ForStatement"
        | "WhileStatement"
        | "ReturnStatement" => true,

        // Pure punctuation nodes are noise
        ";" | "::" | "(" | ")" | "[" | "]" | "{" | "}" | "," | "." | ":" | "=" | "+" | "-"
        | "*" | "/" => false,

        // Comments are usually noise for presentations
        "LineComment" | "BlockComment" => false,

        _ => {
            // Keep string literals or identifiers with meaningful text
            if let Some(value) = node.value.as_str() {
                !value.is_empty() && value.len() > 1
            } else {
                // Otherwise, keep it if it has interesting children
                !node.children.is_empty()
            }
        }
    }
}

/// Prepare a human friendly label for a node in the visualisations
pub fn format_node_label(node: &AstNode) -> String {
    let escape_quotes = |s: &str| s.replace('"', "\\\"");

    match node.kind.as_str() {
        "FunctionDefinition" => {
            if let Some(name) = node.value.as_str() {
                format!("Function:{}", escape_quotes(name))
            } else {
                "Function".to_string()
            }
        }
        "Call" => {
            if let Some(name) = node.value.as_str() {
                format!("Call:{}", escape_quotes(name))
            } else {
                "Call".to_string()
            }
        }
        "Parameter" => {
            if let Some(name) = node.value.as_str() {
                format!("Parameter:{}", escape_quotes(name))
            } else {
                "Parameter".to_string()
            }
        }
        "Identifier" => {
            if let Some(name) = node.value.as_str() {
                format!("Identifier:{}", escape_quotes(name))
            } else {
                "Identifier".to_string()
            }
        }
        "LetDeclaration" => {
            if let Some(name) = node.value.as_str() {
                format!("Let:{}", escape_quotes(name))
            } else {
                "LetDeclaration".to_string()
            }
        }
        "UseDeclaration" => {
            if let Some(name) = node.value.as_str() {
                format!("Use:{}", escape_quotes(name))
            } else {
                "UseDeclaration".to_string()
            }
        }
        "ScopedIdentifier" => {
            if let Some(name) = node.value.as_str() {
                format!("Scoped:{}", escape_quotes(name))
            } else {
                "ScopedIdentifier".to_string()
            }
        }
        _ => {
            if let Some(value) = node.value.as_str() {
                if !value.is_empty() {
                    format!("{}:{}", node.kind, escape_quotes(value))
                } else {
                    node.kind.clone()
                }
            } else {
                node.kind.clone()
            }
        }
    }
}

/// Apply a colour palette to ease reading the visual output
pub fn get_node_color(node: &AstNode) -> &'static str {
    match node.kind.as_str() {
        "FunctionDefinition" => "#4A90E2",  // cool blue for functions
        "Call" => "#E74C3C",                // alert red for calls
        "Parameter" => "#2ECC71",           // green for parameters
        "Identifier" => "#F39C12",          // orange for identifiers
        "Block" => "#9B59B6",               // purple for blocks
        "ExpressionStatement" => "#34495E", // dark grey for statements
        _ => "#BDC3C7",                     // light grey fallback
    }
}

/// Assign shapes so different constructs stand out in the graph
pub fn get_node_shape(node: &AstNode) -> &'static str {
    match node.kind.as_str() {
        "FunctionDefinition" => "ellipse",
        "Call" => "diamond",
        "Parameter" => "box",
        "Identifier" => "oval",
        "Block" => "rectangle",
        _ => "box",
    }
}

/// Render the CFG as a simple tree-like textual structure
pub fn cfg_to_tree(cfg: &ir::CFG) -> String {
    let mut out = String::new();
    out.push_str("Control Flow Graph:\n");
    for node in &cfg.nodes {
        out.push_str(&format!("  {}: {}\n", node.id, node.code));
    }
    for (from, to) in &cfg.edges {
        out.push_str(&format!("  {} -> {}\n", from, to));
    }
    out
}

/// Render the DFG as a simple tree-like textual structure
pub fn dfg_to_tree(dfg: &ir::DataFlowGraph) -> String {
    let mut out = String::new();
    out.push_str("Data Flow Graph:\n");
    for node in &dfg.nodes {
        out.push_str(&format!("  {}: {} ({:?})\n", node.id, node.name, node.kind));
    }
    for (from, to) in &dfg.edges {
        out.push_str(&format!("  {} -> {}\n", from, to));
    }
    out
}
