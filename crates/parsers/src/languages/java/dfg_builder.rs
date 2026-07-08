use crate::catalog as catalog_module;
use ir::{stable_id, DFNode, DFNodeKind, DataFlowGraph, FileIR, Symbol, SymbolKind};
use std::collections::{HashMap, HashSet};
use tree_sitter::Node;

fn resolve_alias<'a>(mut name: &'a str, symbols: &'a HashMap<String, Symbol>) -> String {
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(name.to_string());
    while let Some(next) = symbols.get(name).and_then(|s| s.alias_of.as_deref()) {
        if !visited.insert(next.to_string()) {
            break;
        }
        name = next;
    }
    name.to_string()
}

fn base_of(name: &str) -> Option<&str> {
    if let Some(pos) = name.rfind('.') {
        Some(&name[..pos])
    } else if let Some(pos) = name.rfind('[') {
        Some(&name[..pos])
    } else {
        None
    }
}

fn find_symbol<'a>(name: &str, symbols: &'a HashMap<String, Symbol>) -> Option<&'a Symbol> {
    if let Some(sym) = symbols.get(name) {
        return Some(sym);
    }
    if let Some(base) = base_of(name) {
        return find_symbol(base, symbols);
    }
    // Static/instance fields are stored with a "this." prefix. When code references
    // a field by its bare name (e.g. TABLE instead of this.TABLE), fall back to the
    // prefixed form so taint/sanitization is resolved correctly.
    if !name.starts_with("this.") {
        if let Some(sym) = symbols.get(&format!("this.{name}")) {
            return Some(sym);
        }
    }
    None
}

fn node_text_trimmed(node: Node, src: &str) -> Option<String> {
    node.utf8_text(src.as_bytes())
        .ok()
        .map(|s| s.trim().to_string())
}

/// Returns true for names that look like qualified class/type references rather than variable
/// names. When `gather_ids` follows a field-access chain (e.g. `java.util.Optional`), the
/// gathered identifier contains a dot-separated path where the terminal segment is PascalCase.
/// Such names are never user-defined variables, so "not found in symbols" means "safe".
fn looks_like_class_ref(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    last.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
}

/// Returns true when the expression is made entirely of compile-time constants
/// (literals and operators) with no variable references or method calls.
/// For ternary/switch expressions only the value branches are checked, not the condition.
fn is_constant_expression(node: Node) -> bool {
    let k = node.kind();
    if k.ends_with("_literal") || k == "true" || k == "false" || k == "null_literal"
        || k == "text_block"
    {
        return true;
    }
    if k == "identifier" || k == "method_invocation" || k == "object_creation_expression" {
        return false;
    }
    if k == "ternary_expression" {
        let cons_ok = node
            .child_by_field_name("consequence")
            .map(|c| is_constant_expression(c))
            .unwrap_or(true);
        let alt_ok = node
            .child_by_field_name("alternative")
            .map(|c| is_constant_expression(c))
            .unwrap_or(true);
        return cons_ok && alt_ok;
    }
    // Switch expressions: only check arm consequences, not the switch value (condition).
    if k == "switch_expression" {
        if let Some(body) = node.child_by_field_name("body") {
            let mut bc = body.walk();
            for group in body.children(&mut bc) {
                match group.kind() {
                    "switch_rule" => {
                        let mut gc = group.walk();
                        for child in group.children(&mut gc) {
                            if child.kind() == "switch_label" || child.kind() == "->" {
                                continue;
                            }
                            if child.is_named() && !is_constant_expression(child) {
                                return false;
                            }
                        }
                    }
                    "switch_block_statement_group" => {
                        // Traditional-form blocks are too complex to evaluate statically.
                        return false;
                    }
                    _ => {}
                }
            }
            return true;
        }
        return false;
    }
    let mut cursor = node.walk();
    let result = node
        .children(&mut cursor)
        .filter(|c| c.is_named())
        .all(|c| is_constant_expression(c));
    result
}

fn gather_ids(node: Node, src: &str, out: &mut Vec<String>) {
    match node.kind() {
        "identifier" => {
            if let Ok(id) = node.utf8_text(src.as_bytes()) {
                out.push(id.to_string());
            }
        }
        "field_access" => {
            let mut bases = Vec::new();
            if let Some(obj) = node.child_by_field_name("object") {
                if obj.kind() == "this" {
                    bases.push("this".to_string());
                } else {
                    gather_ids(obj, src, &mut bases);
                }
            }
            if let Some(field) = node.child_by_field_name("field") {
                if let Ok(name) = field.utf8_text(src.as_bytes()) {
                    if bases.is_empty() {
                        out.push(name.to_string());
                    } else {
                        for base in bases {
                            out.push(format!("{base}.{name}"));
                        }
                    }
                } else {
                    out.extend(bases);
                }
            } else {
                out.extend(bases);
            }
            return;
        }
        "array_access" => {
            let mut bases = Vec::new();
            if let Some(arr) = node.child_by_field_name("array") {
                gather_ids(arr, src, &mut bases);
            }
            if let Some(index) = node.child_by_field_name("index") {
                if let Ok(idx) = index.utf8_text(src.as_bytes()) {
                    if bases.is_empty() {
                        out.push(format!("[{idx}]"));
                    } else {
                        for base in bases {
                            out.push(format!("{base}[{idx}]"));
                        }
                    }
                } else {
                    out.extend(bases);
                }
            } else {
                out.extend(bases);
            }
            return;
        }
        "method_invocation" => {
            let receiver_text = node
                .child_by_field_name("object")
                .and_then(|obj| node_text_trimmed(obj, src));
            if let Some(obj) = node.child_by_field_name("object") {
                if obj.kind() == "identifier" {
                    if let Ok(id) = obj.utf8_text(src.as_bytes()) {
                        // Skip class-name receivers (Java convention: uppercase-first).
                        // `String.format(...)` → `String` is a type, not a variable.
                        let is_type = id.chars().next().map(|c| c.is_uppercase()).unwrap_or(false);
                        if !is_type {
                            out.push(id.to_string());
                        }
                    }
                } else {
                    gather_ids(obj, src, out);
                }
            }
            let mut arg_nodes: Vec<Node> = Vec::new();
            if let Some(args) = node
                .child_by_field_name("arguments")
                .or_else(|| node.child_by_field_name("argument_list"))
            {
                let mut cursor = args.walk();
                for arg in args.children(&mut cursor).filter(|n| n.is_named()) {
                    arg_nodes.push(arg);
                    gather_ids(arg, src, out);
                }
            }
            if let (Some(obj), Some(method)) = (
                receiver_text,
                node.child_by_field_name("name")
                    .and_then(|n| node_text_trimmed(n, src)),
            ) {
                let is_keyed = matches!(method.as_str(), "put" | "get" | "add" | "set" | "remove");
                if is_keyed {
                    if let Some(first) = arg_nodes.first() {
                        if let Some(key) = node_text_trimmed(*first, src) {
                            out.push(format!("{obj}[{key}]"));
                        }
                    }
                }
            }
            return;
        }
        "object_creation_expression" => {
            if let Some(args) = node.child_by_field_name("arguments") {
                gather_ids(args, src, out);
            }
            return;
        }
        "instanceof_expression" => {
            // `left instanceof Type name` — only the tested expression (left) is a use;
            // `name` is a newly BOUND variable (a declaration), not a reference to read.
            if let Some(left) = node.child_by_field_name("left") {
                gather_ids(left, src, out);
            }
            return;
        }
        "ternary_expression" => {
            // The condition determines WHICH branch is taken but doesn't flow into the value;
            // collect identifiers only from the two value branches.
            if let Some(cons) = node.child_by_field_name("consequence") {
                gather_ids(cons, src, out);
            }
            if let Some(alt) = node.child_by_field_name("alternative") {
                gather_ids(alt, src, out);
            }
            return;
        }
        "switch_expression" => {
            // Like ternary, the switched value (condition) decides which arm runs but does
            // not itself flow into the result — only the arm consequences carry data.
            if let Some(body) = node.child_by_field_name("body") {
                let mut bc = body.walk();
                for group in body.children(&mut bc) {
                    match group.kind() {
                        "switch_rule" => {
                            let mut gc = group.walk();
                            for child in group.children(&mut gc) {
                                if child.kind() == "switch_label" || child.kind() == "->" {
                                    continue;
                                }
                                if child.is_named() {
                                    gather_ids(child, src, out);
                                }
                            }
                        }
                        "switch_block_statement_group" => {
                            let mut gc = group.walk();
                            for stmt in group.children(&mut gc) {
                                if stmt.kind() == "switch_label" {
                                    continue;
                                }
                                gather_ids(stmt, src, out);
                            }
                        }
                        _ => {}
                    }
                }
            }
            return;
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        gather_ids(child, src, out);
    }
}

fn extract_call_path(node: Node, src: &str) -> Option<String> {
    if node.kind() != "method_invocation" {
        return None;
    }
    let mut name = String::new();
    if let Some(obj) = node.child_by_field_name("object") {
        if let Ok(t) = obj.utf8_text(src.as_bytes()) {
            name.push_str(t);
            name.push('.');
        }
    }
    if let Some(id) = node.child_by_field_name("name") {
        if let Ok(t) = id.utf8_text(src.as_bytes()) {
            name.push_str(t);
        }
    }
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn resolve_import(
    path: &str,
    imports: &HashMap<String, String>,
    wildcards: &[String],
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some((first, rest)) = path.split_once('.') {
        if let Some(full) = imports.get(first) {
            out.push(format!("{full}.{rest}"));
        } else if !wildcards.iter().any(|w| w == first) {
            for pkg in wildcards {
                out.push(format!("{pkg}.{path}"));
            }
        }
    } else if let Some(full) = imports.get(path) {
        out.push(full.clone());
    }
    out
}

fn stable_node_id(fir: &FileIR, node: Option<Node>, key: &str) -> usize {
    if let Some(n) = node {
        let pos = n.start_position();
        stable_id(&fir.file_path, pos.row + 1, pos.column + 1, key)
    } else {
        stable_id(&fir.file_path, 0, 0, key)
    }
}

fn stable_node_id2(fir: &FileIR, node: Option<Node>, key: &str) -> (usize, usize) {
    if let Some(n) = node {
        let pos = n.start_position();
        let line = pos.row + 1;
        (stable_id(&fir.file_path, line, pos.column + 1, key), line)
    } else {
        (stable_id(&fir.file_path, 0, 0, key), 0)
    }
}

fn find_node_mut(dfg: &mut DataFlowGraph, id: usize) -> Option<&mut DFNode> {
    dfg.nodes.iter_mut().find(|n| n.id == id)
}

fn push_node(fir: &mut FileIR, node: DFNode) {
    fir.dfg
        .get_or_insert_with(DataFlowGraph::default)
        .nodes
        .push(node);
}

fn push_edge(fir: &mut FileIR, edge: (usize, usize)) {
    fir.dfg
        .get_or_insert_with(DataFlowGraph::default)
        .edges
        .push(edge);
}

fn push_call_return(fir: &mut FileIR, entry: (usize, usize)) {
    fir.dfg
        .get_or_insert_with(DataFlowGraph::default)
        .call_returns
        .push(entry);
}

fn push_merge(fir: &mut FileIR, merge: (usize, Vec<usize>)) {
    fir.dfg
        .get_or_insert_with(DataFlowGraph::default)
        .merges
        .push(merge);
}

fn merge_states(fir: &mut FileIR, states: Vec<HashMap<String, Symbol>>, merge_counter: &mut usize) {
    let mut names = HashSet::new();
    for state in &states {
        for name in state.keys() {
            names.insert(name.clone());
        }
    }
    let mut merged = HashMap::new();
    for name in names {
        // Count states that actually define this variable.
        // A variable that only exists in one branch (e.g. declared inside a try or if block)
        // is never accessible from other branches, so there is no competing definition to
        // merge against; simply inherit that branch's state instead of forcing sanitized=false.
        let defining_count = states.iter().filter(|s| s.contains_key(&name)).count();
        if defining_count <= 1 {
            if let Some(sym) = states.iter().find_map(|s| s.get(&name)) {
                merged.insert(name.clone(), sym.clone());
            }
            continue;
        }
        let mut sanitized_all = true;
        let mut defs = Vec::new();
        let mut alias = None;
        for state in &states {
            if let Some(sym) = state.get(&name) {
                sanitized_all &= sym.sanitized;
                if let Some(d) = sym.def {
                    defs.push(d);
                }
                if alias.is_none() {
                    alias = sym.alias_of.clone();
                }
            } else {
                sanitized_all = false;
            }
        }
        let def = match defs.len() {
            0 => None,
            1 => Some(defs[0]),
            _ => {
                let merge_idx = *merge_counter;
                *merge_counter += 1;
                let id = stable_node_id(fir, None, &format!("merge:{name}:{merge_idx}"));
                push_node(
                    fir,
                    DFNode {
                        id,
                        name: name.clone(),
                        kind: DFNodeKind::Assign,
                        sanitized: sanitized_all,
                        branch: None,
                        ..Default::default()
                    },
                );
                for d in &defs {
                    push_edge(fir, (*d, id));
                }
                push_merge(fir, (id, defs.clone()));
                Some(id)
            }
        };
        merged.insert(
            name.clone(),
            Symbol {
                name: name.clone(),
                sanitized: sanitized_all,
                def,
                alias_of: alias,
            },
        );
    }
    fir.symbols = merged;
}

fn propagate_sanitized(fir: &mut FileIR) {
    if let Some(dfg) = &mut fir.dfg {
        // Build a reverse-edge map so we can check ALL incoming edges to a node.
        let edges = dfg.edges.clone();
        let mut incoming: HashMap<usize, Vec<usize>> = HashMap::new();
        for &(src, dst) in &edges {
            incoming.entry(dst).or_default().push(src);
        }

        // Seed the queue with nodes that are already marked sanitized.
        let mut queue: Vec<usize> = dfg
            .nodes
            .iter()
            .filter(|n| n.sanitized)
            .map(|n| n.id)
            .collect();
        let mut visited = HashSet::new();

        while let Some(id) = queue.pop() {
            if !visited.insert(id) {
                continue;
            }
            // Collect candidate destination ids first (immutable pass).
            let candidates: Vec<usize> = edges
                .iter()
                .filter(|&&(src, _)| src == id)
                .filter_map(|&(_, dst)| {
                    let node = dfg.nodes.iter().find(|n| n.id == dst)?;
                    if node.sanitized {
                        return None;
                    }
                    if matches!(node.kind, DFNodeKind::Assign) && node.branch.is_none() {
                        return None;
                    }
                    // Only propagate when EVERY incoming edge comes from a sanitized node.
                    // A node with both sanitized and unsanitized sources (e.g. `result = CONST + raw`)
                    // must remain tainted.
                    let all_sanitized = incoming
                        .get(&dst)
                        .map(|srcs| {
                            srcs.iter().all(|&s| {
                                dfg.nodes
                                    .iter()
                                    .find(|n| n.id == s)
                                    .map(|n| n.sanitized)
                                    .unwrap_or(false)
                            })
                        })
                        .unwrap_or(true);
                    if all_sanitized { Some(dst) } else { None }
                })
                .collect();

            // Mutable update pass.
            for dst in candidates {
                if let Some(node) = find_node_mut(dfg, dst) {
                    node.sanitized = true;
                    let (name, canonical) = {
                        let n = dfg.nodes.iter().find(|n| n.id == dst).unwrap();
                        let c = resolve_alias(&n.name, &fir.symbols);
                        (n.name.clone(), c)
                    };
                    if let Some(sym) = fir.symbols.get_mut(&canonical) {
                        sym.sanitized = true;
                    } else if let Some(sym) = fir.symbols.get_mut(&name) {
                        sym.sanitized = true;
                    }
                    queue.push(dst);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_dfg(
    node: Node,
    src: &str,
    fir: &mut FileIR,
    imports: &HashMap<String, String>,
    wildcards: &[String],
    current_fn: Option<usize>,
    fn_ids: &mut HashMap<String, usize>,
    fn_params: &mut HashMap<usize, Vec<usize>>,
    fn_returns: &mut HashMap<usize, Vec<usize>>,
    call_args: &mut Vec<(usize, usize, usize)>,
    branch_stack: &mut Vec<usize>,
    branch_counter: &mut usize,
    merge_counter: &mut usize,
) {
    match node.kind() {
        "method_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                    let (id, fn_line) = stable_node_id2(fir, Some(name_node), &format!("function:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: name.to_string(),
                            kind: DFNodeKind::Def,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                            line: fn_line,
                        ..Default::default()
                        },
                    );
                    fn_ids.insert(name.to_string(), id);
                    if let Some(params) = node.child_by_field_name("parameters") {
                        let mut pc = params.walk();
                        for p in params.children(&mut pc) {
                            let pn_opt = if p.kind() == "formal_parameter" {
                                p.child_by_field_name("name")
                            } else if p.kind() == "spread_parameter" {
                                // spread_parameter (varargs): named children are
                                // [type_identifier, variable_declarator]; no "name" field.
                                (0..p.named_child_count())
                                    .filter_map(|i| p.named_child(i))
                                    .find(|c| c.kind() == "variable_declarator")
                            } else {
                                None
                            };
                            if let Some(pn) = pn_opt {
                                if let Ok(pname) = pn.utf8_text(src.as_bytes()) {
                                    let (pid, param_line) = stable_node_id2(
                                        fir,
                                        Some(pn),
                                        &format!("param:{name}:{pname}"),
                                    );
                                    push_node(
                                        fir,
                                        DFNode {
                                            id: pid,
                                            name: pname.to_string(),
                                            kind: DFNodeKind::Param,
                                            sanitized: false,
                                            branch: branch_stack.last().copied(),
                                            line: param_line,
                                            ..Default::default()
                                        },
                                    );
                                    fn_params.entry(id).or_default().push(pid);
                                    fir.symbols.insert(
                                        pname.to_string(),
                                        Symbol {
                                            name: pname.to_string(),
                                            sanitized: false,
                                            def: Some(pid),
                                            alias_of: None,
                                        },
                                    );
                                }
                            }
                        }
                    }
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        build_dfg(
                            child,
                            src,
                            fir,
                            imports,
                            wildcards,
                            Some(id),
                            fn_ids,
                            fn_params,
                            fn_returns,
                            call_args,
                            branch_stack,
                            branch_counter,
                            merge_counter,
                        );
                    }
                    return;
                }
            }
        }
        "constructor_declaration" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                    let (id, fn_line) = stable_node_id2(fir, Some(name_node), &format!("constructor:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: name.to_string(),
                            kind: DFNodeKind::Def,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                            line: fn_line,
                            ..Default::default()
                        },
                    );
                    fn_ids.insert(name.to_string(), id);
                    if let Some(params) = node.child_by_field_name("parameters") {
                        let mut pc = params.walk();
                        for p in params.children(&mut pc) {
                            let pn_opt = if p.kind() == "formal_parameter" {
                                p.child_by_field_name("name")
                            } else if p.kind() == "spread_parameter" {
                                // spread_parameter (varargs): named children are
                                // [type_identifier, variable_declarator]; no "name" field.
                                (0..p.named_child_count())
                                    .filter_map(|i| p.named_child(i))
                                    .find(|c| c.kind() == "variable_declarator")
                            } else {
                                None
                            };
                            if let Some(pn) = pn_opt {
                                if let Ok(pname) = pn.utf8_text(src.as_bytes()) {
                                    let (pid, param_line) = stable_node_id2(
                                        fir,
                                        Some(pn),
                                        &format!("param:{name}:{pname}"),
                                    );
                                    push_node(
                                        fir,
                                        DFNode {
                                            id: pid,
                                            name: pname.to_string(),
                                            kind: DFNodeKind::Param,
                                            sanitized: false,
                                            branch: branch_stack.last().copied(),
                                            line: param_line,
                                            ..Default::default()
                                        },
                                    );
                                    fn_params.entry(id).or_default().push(pid);
                                    fir.symbols.insert(
                                        pname.to_string(),
                                        Symbol {
                                            name: pname.to_string(),
                                            sanitized: false,
                                            def: Some(pid),
                                            alias_of: None,
                                        },
                                    );
                                }
                            }
                        }
                    }
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        build_dfg(
                            child,
                            src,
                            fir,
                            imports,
                            wildcards,
                            Some(id),
                            fn_ids,
                            fn_params,
                            fn_returns,
                            call_args,
                            branch_stack,
                            branch_counter,
                            merge_counter,
                        );
                    }
                    return;
                }
            }
        }
        "field_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    // Only track initialized field declarations; uninitialized fields carry no
                    // taint and would conflict with the assignment_expression Def created when
                    // the field is later written (e.g. `this.f = param`).
                    if let Some(val) = child.child_by_field_name("value") {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(var) = name_node.utf8_text(src.as_bytes()) {
                                let mut ids: Vec<String> = Vec::new();
                                let mut sanitized = false;
                                if val.kind() != "lambda_expression"
                                    && val.kind() != "method_reference"
                                {
                                    let vk = val.kind();
                                    if vk.ends_with("_literal")
                                        || vk == "true"
                                        || vk == "false"
                                        || vk == "null_literal"
                                        || vk == "text_block"
                                        || is_constant_expression(val)
                                    {
                                        sanitized = true;
                                    } else {
                                        let mut call_sanitizer = false;
                                        if let Some(call) = extract_call_path(val, src) {
                                            if resolve_import(&call, imports, wildcards)
                                                .into_iter()
                                                .chain(std::iter::once(call.clone()))
                                                .any(|f| {
                                                    catalog_module::is_sanitizer("java", &f)
                                                        || matches!(
                                                            fir.symbol_types.get(&f),
                                                            Some(SymbolKind::Sanitizer)
                                                        )
                                                })
                                            {
                                                call_sanitizer = true;
                                            }
                                        }
                                        if !call_sanitizer {
                                            gather_ids(val, src, &mut ids);
                                            if vk == "object_creation_expression"
                                                && ids.is_empty()
                                            {
                                                sanitized = true;
                                            }
                                        }
                                        sanitized = call_sanitizer || sanitized;
                                    }
                                }
                                let field_key = format!("this.{var}");
                                let (id, field_line) = stable_node_id2(fir, Some(name_node), &format!("field:{var}"));
                                push_node(
                                    fir,
                                    DFNode {
                                        id,
                                        name: field_key.clone(),
                                        kind: DFNodeKind::Def,
                                        sanitized,
                                        branch: branch_stack.last().copied(),
                                        line: field_line,
                                        ..Default::default()
                                    },
                                );
                                let san = sanitized
                                    || ids.iter().any(|src_var| {
                                        let canonical = resolve_alias(src_var, &fir.symbols);
                                        find_symbol(&canonical, &fir.symbols)
                                            .map(|s| s.sanitized)
                                            .unwrap_or(false)
                                    });
                                fir.symbols.insert(
                                    field_key.clone(),
                                    Symbol {
                                        name: field_key,
                                        sanitized: san,
                                        def: Some(id),
                                        alias_of: None,
                                    },
                                );
                                for src_var in &ids {
                                    let canonical = resolve_alias(src_var, &fir.symbols);
                                    if let Some(def_id) =
                                        find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                                    {
                                        push_edge(fir, (def_id, id));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return;
        }
        "catch_formal_parameter" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(pname) = name_node.utf8_text(src.as_bytes()) {
                    let (pid, param_line) = stable_node_id2(
                        fir,
                        Some(name_node),
                        &format!("catch_param:{pname}"),
                    );
                    push_node(
                        fir,
                        DFNode {
                            id: pid,
                            name: pname.to_string(),
                            kind: DFNodeKind::Param,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                            line: param_line,
                            ..Default::default()
                        },
                    );
                    fir.symbols.insert(
                        pname.to_string(),
                        Symbol {
                            name: pname.to_string(),
                            sanitized: false,
                            def: Some(pid),
                            alias_of: None,
                        },
                    );
                }
            }
            return;
        }
        // try-with-resources: `try (InputStream in = req.getInputStream()) { ... }`
        // The `resource` node has `type`, `name`, and `value` fields — track it like a local var.
        "resource" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(var) = name_node.utf8_text(src.as_bytes()) {
                    let mut ids = Vec::new();
                    let mut sanitized = false;
                    if let Some(val) = node.child_by_field_name("value") {
                        let vkind = val.kind();
                        if vkind != "lambda_expression" && vkind != "method_reference" {
                            if vkind.ends_with("_literal")
                                || vkind == "true"
                                || vkind == "false"
                                || vkind == "null_literal"
                                || vkind == "text_block"
                                || is_constant_expression(val)
                            {
                                sanitized = true;
                            } else {
                                let mut call_sanitizer = false;
                                if let Some(call) = extract_call_path(val, src) {
                                    let resolved: Vec<String> = resolve_import(&call, imports, wildcards)
                                        .into_iter()
                                        .chain(std::iter::once(call.clone()))
                                        .collect();
                                    if resolved.iter().any(|f| {
                                        catalog_module::is_sanitizer("java", f)
                                            || matches!(
                                                fir.symbol_types.get(f.as_str()),
                                                Some(SymbolKind::Sanitizer)
                                            )
                                    }) {
                                        sanitized = true;
                                        call_sanitizer = true;
                                    }
                                    let is_known_source = resolved.iter().any(|f| {
                                        catalog_module::is_source("java", f)
                                            || matches!(
                                                fir.symbol_types.get(f.as_str()),
                                                Some(SymbolKind::Source)
                                            )
                                    });
                                    if let Some(args) = val.child_by_field_name("arguments") {
                                        gather_ids(args, src, &mut ids);
                                    }
                                    if !call_sanitizer {
                                        gather_ids(val, src, &mut ids);
                                    }
                                    let has_receiver = val.child_by_field_name("object").is_some();
                                    if !call_sanitizer && !is_known_source && ids.is_empty() && has_receiver {
                                        sanitized = true;
                                    }
                                } else {
                                    gather_ids(val, src, &mut ids);
                                    if vkind == "object_creation_expression" && ids.is_empty() {
                                        sanitized = true;
                                    }
                                }
                            }
                        }
                    }
                    let (id, res_line) =
                        stable_node_id2(fir, Some(name_node), &format!("resource:{var}"));
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: var.to_string(),
                            kind: DFNodeKind::Def,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: res_line,
                            ..Default::default()
                        },
                    );
                    let sym = fir.symbols.entry(var.to_string()).or_insert_with(|| Symbol {
                        name: var.to_string(),
                        sanitized: false,
                        def: None,
                        alias_of: None,
                    });
                    sym.sanitized = sanitized;
                    sym.def = Some(id);
                    sym.alias_of = None;
                    for src_name in &ids {
                        let canonical = resolve_alias(src_name, &fir.symbols);
                        if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            push_edge(fir, (def_id, id));
                        }
                    }
                    if let Some(val) = node.child_by_field_name("value") {
                        if val.kind() != "lambda_expression" && val.kind() != "method_reference" {
                            if let Some(call) = extract_call_path(val, src) {
                                if let Some(&callee_id) =
                                    fn_ids.get(call.rsplit('.').next().unwrap_or(&call))
                                {
                                    push_call_return(fir, (id, callee_id));
                                }
                            }
                        }
                    }
                }
            }
            return;
        }
        "local_variable_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(var) = name_node.utf8_text(src.as_bytes()) {
                            let mut ids = Vec::new();
                            let mut sanitized = false;
                            if let Some(val) = child.child_by_field_name("value") {
                                let vkind = val.kind();
                                if vkind != "lambda_expression" && vkind != "method_reference" {
                                    // Constant/literal initializers (including pure literal
                                    // concatenations and ternaries of literals) cannot carry taint.
                                    if vkind.ends_with("_literal")
                                        || vkind == "true"
                                        || vkind == "false"
                                        || vkind == "null_literal"
                                        || vkind == "text_block"
                                        || is_constant_expression(val)
                                    {
                                        sanitized = true;
                                    } else {
                                        let mut call_sanitizer = false;
                                        if let Some(call) = extract_call_path(val, src) {
                                            let resolved: Vec<String> = resolve_import(&call, imports, wildcards)
                                                .into_iter()
                                                .chain(std::iter::once(call.clone()))
                                                .collect();
                                            if resolved.iter().any(|f| {
                                                catalog_module::is_sanitizer("java", f)
                                                    || matches!(
                                                        fir.symbol_types.get(f.as_str()),
                                                        Some(SymbolKind::Sanitizer)
                                                    )
                                            }) {
                                                sanitized = true;
                                                call_sanitizer = true;
                                            }
                                            let is_known_source = resolved.iter().any(|f| {
                                                catalog_module::is_source("java", f)
                                                    || matches!(
                                                        fir.symbol_types.get(f.as_str()),
                                                        Some(SymbolKind::Source)
                                                    )
                                            });
                                            if let Some(args) = val.child_by_field_name("arguments") {
                                                gather_ids(args, src, &mut ids);
                                            }
                                            if !call_sanitizer {
                                                gather_ids(val, src, &mut ids);
                                            }
                                            // If gather_ids found no variable references in the call
                                            // AND the call has a receiver (e.g. String.format("lit"),
                                            // "safe".trim().toLowerCase()), the result has no way to
                                            // carry user-controlled data and can be treated as clean.
                                            // Bare function calls (no receiver, like `source()`) are
                                            // excluded because they may be unrecognised taint sources.
                                            let has_receiver = val.child_by_field_name("object").is_some();
                                            if !call_sanitizer && !is_known_source && ids.is_empty() && has_receiver {
                                                sanitized = true;
                                            }
                                        } else {
                                            gather_ids(val, src, &mut ids);
                                            // A freshly constructed object (e.g. new StringBuilder())
                                            // carries no taint unless its constructor args do.
                                            if vkind == "object_creation_expression"
                                                && ids.is_empty()
                                            {
                                                sanitized = true;
                                            }
                                        }
                                    }
                                }
                            }
                            // If all referenced variables are sanitized, the result is sanitized
                            // too (e.g. `"prefix" + cleanVar` or `a + b` where both are clean).
                            // Qualified class references (e.g. java.util.Optional) that are not in
                            // symbols are treated as sanitized because they are type names, not vars.
                            if !sanitized && !ids.is_empty() {
                                let all_clean = ids.iter().all(|name| {
                                    let canonical = resolve_alias(name, &fir.symbols);
                                    find_symbol(&canonical, &fir.symbols)
                                        .map(|s| s.sanitized)
                                        .unwrap_or_else(|| looks_like_class_ref(&canonical))
                                });
                                if all_clean {
                                    sanitized = true;
                                }
                            }
                            let (id, local_line) = stable_node_id2(fir, Some(name_node), &format!("local:{var}"));
                            fir.dfg
                                .get_or_insert_with(DataFlowGraph::default)
                                .nodes
                                .push(DFNode {
                                    id,
                                    name: var.to_string(),
                                    kind: DFNodeKind::Def,
                                    sanitized,
                                    branch: branch_stack.last().copied(),
                                    line: local_line,
                        ..Default::default()
                                });
                            let mut sym = Symbol {
                                name: var.to_string(),
                                sanitized,
                                def: Some(id),
                                alias_of: None,
                            };
                            if ids.len() == 1
                                && child
                                    .child_by_field_name("value")
                                    .map(|v| v.kind() == "identifier")
                                    .unwrap_or(false)
                            {
                                let canonical = resolve_alias(&ids[0], &fir.symbols);
                                sym.alias_of = Some(canonical.clone());
                                if let Some(src_sym) = find_symbol(&canonical, &fir.symbols) {
                                    if src_sym.sanitized {
                                        sym.sanitized = true;
                                        if let Some(dfg) = fir.dfg.as_mut() {
                                            if let Some(n) = find_node_mut(dfg, id) {
                                                n.sanitized = true;
                                            }
                                        }
                                    }
                                }
                            }
                            for src_name in ids {
                                let canonical = resolve_alias(&src_name, &fir.symbols);
                                if let Some(def_id) =
                                    find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                                {
                                    push_edge(fir, (def_id, id));
                                }
                            }
                            if let Some(val) = child.child_by_field_name("value") {
                                if val.kind() != "lambda_expression"
                                    && val.kind() != "method_reference"
                                {
                                    if let Some(call) = extract_call_path(val, src) {
                                        if let Some(&callee_id) =
                                            fn_ids.get(call.rsplit('.').next().unwrap_or(&call))
                                        {
                                            push_call_return(fir, (id, callee_id));
                                        }
                                    }
                                }
                            }
                            fir.symbols.insert(var.to_string(), sym);
                        }
                    }
                }
            }
        }
        "assignment_expression" => {
            if let Some(left) = node.child_by_field_name("left") {
                if let Ok(var) = left.utf8_text(src.as_bytes()) {
                    let mut ids = Vec::new();
                    let mut sanitized = false;
                    if let Some(right) = node.child_by_field_name("right") {
                        let rkind = right.kind();
                        if rkind != "lambda_expression" && rkind != "method_reference" {
                            if rkind.ends_with("_literal")
                                || rkind == "true"
                                || rkind == "false"
                                || rkind == "null_literal"
                                || rkind == "text_block"
                                || is_constant_expression(right)
                            {
                                sanitized = true;
                            } else {
                                let mut call_sanitizer = false;
                                if let Some(call) = extract_call_path(right, src) {
                                    let resolved: Vec<String> = resolve_import(&call, imports, wildcards)
                                        .into_iter()
                                        .chain(std::iter::once(call.clone()))
                                        .collect();
                                    if resolved.iter().any(|f| {
                                        catalog_module::is_sanitizer("java", f)
                                            || matches!(
                                                fir.symbol_types.get(f.as_str()),
                                                Some(SymbolKind::Sanitizer)
                                            )
                                    }) {
                                        sanitized = true;
                                        call_sanitizer = true;
                                    }
                                    let is_known_source = resolved.iter().any(|f| {
                                        catalog_module::is_source("java", f)
                                            || matches!(
                                                fir.symbol_types.get(f.as_str()),
                                                Some(SymbolKind::Source)
                                            )
                                    });
                                    if let Some(args) = right.child_by_field_name("arguments") {
                                        gather_ids(args, src, &mut ids);
                                    }
                                    if !call_sanitizer {
                                        gather_ids(right, src, &mut ids);
                                    }
                                    let has_receiver = right.child_by_field_name("object").is_some();
                                    if !call_sanitizer && !is_known_source && ids.is_empty() && has_receiver {
                                        sanitized = true;
                                    }
                                } else {
                                    gather_ids(right, src, &mut ids);
                                    if rkind == "object_creation_expression"
                                        && ids.is_empty()
                                    {
                                        sanitized = true;
                                    }
                                }
                            }
                        }
                    }
                    // If all referenced variables are sanitized, the result is sanitized.
                    if !sanitized && !ids.is_empty() {
                        let all_clean = ids.iter().all(|name| {
                            let canonical = resolve_alias(name, &fir.symbols);
                            find_symbol(&canonical, &fir.symbols)
                                .map(|s| s.sanitized)
                                .unwrap_or_else(|| looks_like_class_ref(&canonical))
                        });
                        if all_clean {
                            sanitized = true;
                        }
                    }
                    // Detect compound assignment (+=, -=, etc.): tree-sitter-java uses
                    // assignment_expression for both simple (=) and compound (+=, etc.) ops.
                    let is_compound = node
                        .child_by_field_name("operator")
                        .and_then(|op| op.utf8_text(src.as_bytes()).ok())
                        .map(|op| op != "=")
                        .unwrap_or(false);

                    // For compound assignments the old lhs value contributes taint, so only
                    // treat result as sanitized if BOTH old value and rhs are sanitized.
                    let old_sanitized = if is_compound {
                        find_symbol(var, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or(false)
                    } else {
                        true // simple assignment: old value is completely replaced
                    };

                    // Pure-alias detection: only for simple assignments where rhs is a bare id.
                    let alias_cand = if !is_compound
                        && ids.len() == 1
                        && node
                            .child_by_field_name("right")
                            .map(|v| v.kind() == "identifier")
                            .unwrap_or(false)
                    {
                        Some(resolve_alias(&ids[0], &fir.symbols))
                    } else {
                        None
                    };
                    let alias_sanitized = alias_cand
                        .as_ref()
                        .and_then(|c| find_symbol(c, &fir.symbols))
                        .map(|s| s.sanitized)
                        .unwrap_or(false);

                    let base_def_id = if let Some(base) = base_of(var) {
                        find_symbol(base, &fir.symbols).and_then(|s| s.def)
                    } else {
                        None
                    };
                    let base_sanitized = if let Some(base) = base_of(var) {
                        find_symbol(base, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or(false)
                    } else {
                        false
                    };

                    // Compute final sanitization state EXPLICITLY (never inherit stale state).
                    let rhs_sanitized = sanitized || alias_sanitized || base_sanitized;
                    let new_sanitized = rhs_sanitized && old_sanitized;

                    let (id, assign_line) = stable_node_id2(fir, Some(left), &format!("local:{var}"));
                    fir.dfg
                        .get_or_insert_with(DataFlowGraph::default)
                        .nodes
                        .push(DFNode {
                            id,
                            name: var.to_string(),
                            kind: DFNodeKind::Def,
                            sanitized: new_sanitized,
                            branch: branch_stack.last().copied(),
                            line: assign_line,
                        ..Default::default()
                        });
                    let canonical_names: Vec<String> = ids
                        .iter()
                        .map(|src_name| resolve_alias(src_name, &fir.symbols))
                        .collect();

                    let sym = fir
                        .symbols
                        .entry(var.to_string())
                        .or_insert_with(|| Symbol {
                            name: var.to_string(),
                            sanitized: false,
                            def: None,
                            alias_of: None,
                        });
                    sym.def = Some(id);
                    // Always set sanitized to the freshly computed value (never inherit stale state).
                    sym.sanitized = new_sanitized;
                    if let Some(c) = alias_cand {
                        sym.alias_of = Some(c);
                    } else {
                        sym.alias_of = None;
                    }

                    for canonical in canonical_names {
                        if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            fir.dfg
                                .get_or_insert_with(DataFlowGraph::default)
                                .edges
                                .push((def_id, id));
                        }
                    }
                    if let Some(bid) = base_def_id {
                        fir.dfg
                            .get_or_insert_with(DataFlowGraph::default)
                            .edges
                            .push((bid, id));
                    }
                    if let Some(right) = node.child_by_field_name("right") {
                        if right.kind() != "lambda_expression" && right.kind() != "method_reference"
                        {
                            if let Some(call) = extract_call_path(right, src) {
                                if let Some(&callee_id) =
                                    fn_ids.get(call.rsplit('.').next().unwrap_or(&call))
                                {
                                    fir.dfg
                                        .get_or_insert_with(DataFlowGraph::default)
                                        .call_returns
                                        .push((id, callee_id));
                                }
                            }
                        }
                    }
                }
            }
        }
        "lambda_expression" => {
            let (func_id, lambda_line) = stable_node_id2(fir, Some(node), "lambda");
            let lname = format!("lambda_{func_id}");
            push_node(
                fir,
                DFNode {
                    id: func_id,
                    name: lname,
                    kind: DFNodeKind::Def,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                    line: lambda_line,
                        ..Default::default()
                },
            );
            if let Some(params) = node.child_by_field_name("parameters") {
                let mut pnames = Vec::new();
                gather_ids(params, src, &mut pnames);
                for pname in pnames {
                    let pid = stable_node_id(fir, None, &format!("lambda_param:{func_id}:{pname}"));
                    push_node(
                        fir,
                        DFNode {
                            id: pid,
                            name: pname.clone(),
                            kind: DFNodeKind::Param,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        ..Default::default()
                        },
                    );
                    fn_params.entry(func_id).or_default().push(pid);
                    fir.symbols.insert(
                        pname.clone(),
                        Symbol {
                            name: pname,
                            sanitized: false,
                            def: Some(pid),
                            alias_of: None,
                        },
                    );
                }
            }
            if let Some(body) = node.child_by_field_name("body") {
                if body.kind() == "block" {
                    build_dfg(
                        body,
                        src,
                        fir,
                        imports,
                        wildcards,
                        Some(func_id),
                        fn_ids,
                        fn_params,
                        fn_returns,
                        call_args,
                        branch_stack,
                        branch_counter,
                        merge_counter,
                    );
                } else {
                    let mut ids = Vec::new();
                    gather_ids(body, src, &mut ids);
                    for name in ids {
                        let canonical = resolve_alias(&name, &fir.symbols);
                        let sanitized = find_symbol(&canonical, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or(false);
                        let (rid, ret_line) = stable_node_id2(
                            fir,
                            Some(body),
                            &format!("lambda_ret:{func_id}:{name}"),
                        );
                        fir.dfg
                            .get_or_insert_with(DataFlowGraph::default)
                            .nodes
                            .push(DFNode {
                                id: rid,
                                name: name.clone(),
                                kind: DFNodeKind::Return,
                                sanitized,
                                branch: branch_stack.last().copied(),
                                line: ret_line,
                        ..Default::default()
                            });
                        fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                            name: name.clone(),
                            sanitized: false,
                            def: None,
                            alias_of: None,
                        });
                        if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            fir.dfg
                                .get_or_insert_with(DataFlowGraph::default)
                                .edges
                                .push((def_id, rid));
                        }
                        fn_returns.entry(func_id).or_default().push(rid);
                    }
                }
            }
            return;
        }
        "if_statement" => {
            if let Some(cond) = node.child_by_field_name("condition") {
                let mut ids = Vec::new();
                gather_ids(cond, src, &mut ids);
                for name in ids {
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (uid, if_cond_line) = stable_node_id2(fir, Some(cond), &format!("if_cond_use:{name}"));
                    fir.dfg
                        .get_or_insert_with(DataFlowGraph::default)
                        .nodes
                        .push(DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: if_cond_line,
                        ..Default::default()
                        });
                    fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                        name: name.clone(),
                        sanitized: false,
                        def: None,
                        alias_of: None,
                    });
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        fir.dfg
                            .get_or_insert_with(DataFlowGraph::default)
                            .edges
                            .push((def_id, uid));
                    }
                }
            }
            let (bid, if_line) = stable_node_id2(fir, Some(node), "branch:if");
            fir.dfg
                .get_or_insert_with(DataFlowGraph::default)
                .nodes
                .push(DFNode {
                    id: bid,
                    name: "if".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                    line: if_line,
                        ..Default::default()
                });
            // Java 16+ instanceof pattern binding: `if (obj instanceof String s)` — bind `s`
            // to the tested expression's taint state so it's available in the consequence block.
            // The `condition` field is a parenthesized wrapper; search for instanceof inside.
            if let Some(cond) = node.child_by_field_name("condition") {
                // Unwrap the parenthesized condition wrapper to get the inner expression.
                // The `condition` field is `seq('(', expr, ')')` so the expression is
                // accessible as the first named child.
                let instanceof_expr = if cond.kind() == "instanceof_expression" {
                    Some(cond)
                } else {
                    (0..cond.named_child_count())
                        .filter_map(|i| cond.named_child(i))
                        .find(|c| c.kind() == "instanceof_expression")
                };
                if let Some(iof) = instanceof_expr {
                    if let Some(name_node) = iof.child_by_field_name("name") {
                        if let Ok(pname) = name_node.utf8_text(src.as_bytes()) {
                            let lhs_sanitized = iof
                                .child_by_field_name("left")
                                .map(|left| {
                                    let mut lids = Vec::new();
                                    gather_ids(left, src, &mut lids);
                                    !lids.is_empty()
                                        && lids.iter().all(|n| {
                                            let c = resolve_alias(n, &fir.symbols);
                                            find_symbol(&c, &fir.symbols)
                                                .map(|s| s.sanitized)
                                                .unwrap_or(false)
                                        })
                                })
                                .unwrap_or(false);
                            let (pid, pline) = stable_node_id2(
                                fir,
                                Some(name_node),
                                &format!("instanceof_bind:{pname}"),
                            );
                            push_node(
                                fir,
                                DFNode {
                                    id: pid,
                                    name: pname.to_string(),
                                    kind: DFNodeKind::Param,
                                    sanitized: lhs_sanitized,
                                    branch: branch_stack.last().copied(),
                                    line: pline,
                                    ..Default::default()
                                },
                            );
                            fir.symbols.insert(
                                pname.to_string(),
                                Symbol {
                                    name: pname.to_string(),
                                    sanitized: lhs_sanitized,
                                    def: Some(pid),
                                    alias_of: None,
                                },
                            );
                            if let Some(left) = iof.child_by_field_name("left") {
                                let mut lids = Vec::new();
                                gather_ids(left, src, &mut lids);
                                for lname in lids {
                                    let canonical = resolve_alias(&lname, &fir.symbols);
                                    if let Some(def_id) =
                                        find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                                    {
                                        push_edge(fir, (def_id, pid));
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(cons) = node.child_by_field_name("consequence") {
                let id = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(id);
                build_dfg(
                    cons,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
                branch_states.push(fir.symbols.clone());
                branch_stack.pop();
            }
            if let Some(alt) = node.child_by_field_name("alternative") {
                let id = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(id);
                build_dfg(
                    alt,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
                branch_states.push(fir.symbols.clone());
                branch_stack.pop();
            } else {
                branch_states.push(before.clone());
            }
            merge_states(fir, branch_states, merge_counter);
            return;
        }
        "try_statement" => {
            // Model try/catch/finally blocks as branches so taint merges conservatively.
            if let Some(resources) = node
                .child_by_field_name("resource_specification")
                .or_else(|| node.child_by_field_name("resources"))
            {
                build_dfg(
                    resources,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
            } else {
                let mut res_cursor = node.walk();
                for child in node.children(&mut res_cursor) {
                    if child.kind() == "resource_specification" {
                        build_dfg(
                            child,
                            src,
                            fir,
                            imports,
                            wildcards,
                            current_fn,
                            fn_ids,
                            fn_params,
                            fn_returns,
                            call_args,
                            branch_stack,
                            branch_counter,
                            merge_counter,
                        );
                    }
                }
            }

            let (bid, try_line) = stable_node_id2(fir, Some(node), "branch:try");
            push_node(
                fir,
                DFNode {
                    id: bid,
                    name: "try".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                    line: try_line,
                        ..Default::default()
                },
            );

            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();

            if let Some(body) = node.child_by_field_name("body") {
                let id = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(id);
                build_dfg(
                    body,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
                branch_states.push(fir.symbols.clone());
                branch_stack.pop();
            }

            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                match child.kind() {
                    "catch_clause" => {
                        let id = *branch_counter;
                        *branch_counter += 1;
                        fir.symbols = before.clone();
                        branch_stack.push(id);
                        // tree-sitter-java does not expose the catch parameter as a named
                        // field; find it by kind instead.
                        let mut cc = child.walk();
                        for part in child.children(&mut cc) {
                            if part.kind() == "catch_formal_parameter" {
                                build_dfg(
                                    part,
                                    src,
                                    fir,
                                    imports,
                                    wildcards,
                                    current_fn,
                                    fn_ids,
                                    fn_params,
                                    fn_returns,
                                    call_args,
                                    branch_stack,
                                    branch_counter,
                                    merge_counter,
                                );
                                break;
                            }
                        }
                        let mut body = child.child_by_field_name("body");
                        if body.is_none() {
                            let mut inner = child.walk();
                            for part in child.children(&mut inner) {
                                if part.kind() == "block" {
                                    body = Some(part);
                                    break;
                                }
                            }
                        }
                        if let Some(block) = body {
                            build_dfg(
                                block,
                                src,
                                fir,
                                imports,
                                wildcards,
                                current_fn,
                                fn_ids,
                                fn_params,
                                fn_returns,
                                call_args,
                                branch_stack,
                                branch_counter,
                                merge_counter,
                            );
                        }
                        branch_states.push(fir.symbols.clone());
                        branch_stack.pop();
                    }
                    "finally_clause" => {
                        let id = *branch_counter;
                        *branch_counter += 1;
                        fir.symbols = before.clone();
                        branch_stack.push(id);
                        let mut body = child.child_by_field_name("body");
                        if body.is_none() {
                            let mut inner = child.walk();
                            for part in child.children(&mut inner) {
                                if part.kind() == "block" {
                                    body = Some(part);
                                    break;
                                }
                            }
                        }
                        if let Some(block) = body {
                            build_dfg(
                                block,
                                src,
                                fir,
                                imports,
                                wildcards,
                                current_fn,
                                fn_ids,
                                fn_params,
                                fn_returns,
                                call_args,
                                branch_stack,
                                branch_counter,
                                merge_counter,
                            );
                        }
                        branch_states.push(fir.symbols.clone());
                        branch_stack.pop();
                    }
                    _ => {}
                }
            }

            if branch_states.is_empty() {
                branch_states.push(before);
            }

            merge_states(fir, branch_states, merge_counter);
            return;
        }
        "while_statement" => {
            let (nid, while_line) = stable_node_id2(fir, Some(node), "branch:while");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "while".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                    line: while_line,
                        ..Default::default()
                },
            );
            if let Some(cond) = node.child_by_field_name("condition") {
                let mut ids = Vec::new();
                gather_ids(cond, src, &mut ids);
                for name in ids {
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (uid, while_cond_line) = stable_node_id2(fir, Some(cond), &format!("while_cond_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: while_cond_line,
                        ..Default::default()
                        },
                    );
                    fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                        name: name.clone(),
                        sanitized: false,
                        def: None,
                        alias_of: None,
                    });
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        push_edge(fir, (def_id, uid));
                    }
                }
            }
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let id = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(id);
                build_dfg(
                    body,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
                branch_states.push(fir.symbols.clone());
                branch_stack.pop();
            }
            branch_states.push(before.clone());
            merge_states(fir, branch_states, merge_counter);
            return;
        }
        "for_statement" => {
            if let Some(init) = node.child_by_field_name("init") {
                build_dfg(
                    init,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
            }
            let (nid, for_line) = stable_node_id2(fir, Some(node), "branch:for");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "for".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                    line: for_line,
                        ..Default::default()
                },
            );
            if let Some(cond) = node.child_by_field_name("condition") {
                let mut ids = Vec::new();
                gather_ids(cond, src, &mut ids);
                for name in ids {
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (uid, for_cond_line) = stable_node_id2(fir, Some(cond), &format!("for_cond_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: for_cond_line,
                        ..Default::default()
                        },
                    );
                    fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                        name: name.clone(),
                        sanitized: false,
                        def: None,
                        alias_of: None,
                    });
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        push_edge(fir, (def_id, uid));
                    }
                }
            }
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let id = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(id);
                build_dfg(
                    body,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
                if let Some(update) = node.child_by_field_name("update") {
                    build_dfg(
                        update,
                        src,
                        fir,
                        imports,
                        wildcards,
                        current_fn,
                        fn_ids,
                        fn_params,
                        fn_returns,
                        call_args,
                        branch_stack,
                        branch_counter,
                        merge_counter,
                    );
                }
                branch_states.push(fir.symbols.clone());
                branch_stack.pop();
            }
            branch_states.push(before.clone());
            merge_states(fir, branch_states, merge_counter);
            return;
        }
        "enhanced_for_statement" => {
            let (nid, efor_line) = stable_node_id2(fir, Some(node), "branch:enhanced_for");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "for".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                    line: efor_line,
                        ..Default::default()
                },
            );
            // Track iterable's taint and create Use nodes for referenced variables.
            let iterable_sanitized = if let Some(val) = node.child_by_field_name("value") {
                let mut ids = Vec::new();
                gather_ids(val, src, &mut ids);
                let all_clean = !ids.is_empty()
                    && ids.iter().all(|name| {
                        let canonical = resolve_alias(name, &fir.symbols);
                        find_symbol(&canonical, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or_else(|| looks_like_class_ref(&canonical))
                    });
                for name in ids {
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (uid, efor_use_line) = stable_node_id2(fir, Some(val), &format!("enhanced_for_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: efor_use_line,
                        ..Default::default()
                        },
                    );
                    fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                        name: name.clone(),
                        sanitized: false,
                        def: None,
                        alias_of: None,
                    });
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        push_edge(fir, (def_id, uid));
                    }
                }
                all_clean
            } else {
                false
            };
            // Create a Param node for the loop variable, carrying the iterable's taint.
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(item_name) = name_node.utf8_text(src.as_bytes()) {
                    let item_name = item_name.trim().to_string();
                    let (iid, item_line) =
                        stable_node_id2(fir, Some(name_node), &format!("for_item:{item_name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: iid,
                            name: item_name.clone(),
                            kind: DFNodeKind::Param,
                            sanitized: iterable_sanitized,
                            branch: branch_stack.last().copied(),
                            line: item_line,
                            ..Default::default()
                        },
                    );
                    fir.symbols.insert(
                        item_name.clone(),
                        Symbol {
                            name: item_name,
                            sanitized: iterable_sanitized,
                            def: Some(iid),
                            alias_of: None,
                        },
                    );
                }
            }
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let id = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(id);
                build_dfg(
                    body,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
                branch_states.push(fir.symbols.clone());
                branch_stack.pop();
            }
            branch_states.push(before.clone());
            merge_states(fir, branch_states, merge_counter);
            return;
        }
        "do_statement" => {
            // do { body } while (cond): body always executes once, then condition checked.
            // Model conservatively: run body as a branch and merge with pre-loop state.
            let (nid, do_line) = stable_node_id2(fir, Some(node), "branch:do");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "do".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                    line: do_line,
                    ..Default::default()
                },
            );
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let id = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(id);
                build_dfg(
                    body,
                    src,
                    fir,
                    imports,
                    wildcards,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                    merge_counter,
                );
                branch_states.push(fir.symbols.clone());
                branch_stack.pop();
            }
            if let Some(cond) = node.child_by_field_name("condition") {
                let mut ids = Vec::new();
                gather_ids(cond, src, &mut ids);
                for name in ids {
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (uid, do_cond_line) = stable_node_id2(fir, Some(cond), &format!("do_cond_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: do_cond_line,
                            ..Default::default()
                        },
                    );
                    fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                        name: name.clone(),
                        sanitized: false,
                        def: None,
                        alias_of: None,
                    });
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def) {
                        push_edge(fir, (def_id, uid));
                    }
                }
            }
            branch_states.push(before.clone());
            merge_states(fir, branch_states, merge_counter);
            return;
        }
        "switch_statement" | "switch_expression" => {
            let (nid, switch_line) = stable_node_id2(fir, Some(node), "branch:switch");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "switch".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                    line: switch_line,
                        ..Default::default()
                },
            );
            if let Some(cond) = node
                .child_by_field_name("value")
                .or_else(|| node.child_by_field_name("condition"))
            {
                let mut ids = Vec::new();
                gather_ids(cond, src, &mut ids);
                for name in ids {
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (uid, switch_cond_line) = stable_node_id2(fir, Some(cond), &format!("switch_cond_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: switch_cond_line,
                        ..Default::default()
                        },
                    );
                    fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                        name: name.clone(),
                        sanitized: false,
                        def: None,
                        alias_of: None,
                    });
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        push_edge(fir, (def_id, uid));
                    }
                }
            }
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            let mut has_default = false;
            if let Some(body) = node.child_by_field_name("body") {
                let mut cursor = body.walk();
                for group in body.children(&mut cursor) {
                    if group.kind() == "switch_block_statement_group"
                        || group.kind() == "switch_rule"
                    {
                        let mut gc = group.walk();
                        for label in group.children(&mut gc) {
                            if label.kind() != "switch_label" {
                                break;
                            }
                            if let Ok(t) = label.utf8_text(src.as_bytes()) {
                                if t.contains("default") {
                                    has_default = true;
                                }
                            }
                        }
                        let id = *branch_counter;
                        *branch_counter += 1;
                        fir.symbols = before.clone();
                        branch_stack.push(id);
                        let mut gc2 = group.walk();
                        for stmt in group.children(&mut gc2) {
                            if stmt.kind() == "switch_label"
                                || stmt.kind() == ":"
                                || stmt.kind() == "->"
                            {
                                continue;
                            }
                            build_dfg(
                                stmt,
                                src,
                                fir,
                                imports,
                                wildcards,
                                current_fn,
                                fn_ids,
                                fn_params,
                                fn_returns,
                                call_args,
                                branch_stack,
                                branch_counter,
                                merge_counter,
                            );
                        }
                        branch_states.push(fir.symbols.clone());
                        branch_stack.pop();
                    } else if group.kind() == "switch_label" {
                        if let Ok(t) = group.utf8_text(src.as_bytes()) {
                            if t.contains("default") {
                                has_default = true;
                            }
                        }
                    }
                }
            }
            if !has_default {
                branch_states.push(before.clone());
            }
            merge_states(fir, branch_states, merge_counter);
            return;
        }
        "method_reference" => {
            if let Ok(text) = node.utf8_text(src.as_bytes()) {
                let name = text.replace("::", ".");
                let (id, mref_line) = stable_node_id2(fir, Some(node), &format!("method_ref:{name}"));
                push_node(
                    fir,
                    DFNode {
                        id,
                        name,
                        kind: DFNodeKind::Use,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                        line: mref_line,
                        ..Default::default()
                    },
                );
            }
            return;
        }
        "return_statement" => {
            // Find the actual return value (skip the "return" keyword node).
            let ret_val = (0..node.named_child_count()).filter_map(|i| node.named_child(i)).next();
            let mut ids = Vec::new();
            gather_ids(node, src, &mut ids);
            if ids.is_empty() {
                // The return value is a constant/literal expression with no variable references.
                // Still create a sanitized Return node so call-site analysis can detect that this
                // path is clean and contribute to the all-returns-sanitized check.
                if let Some(func_id) = current_fn {
                    let is_void = ret_val.is_none();
                    if !is_void {
                        let (id, ret_line) = stable_node_id2(fir, Some(node), "return:__literal__");
                        push_node(
                            fir,
                            DFNode {
                                id,
                                name: "__return__".to_string(),
                                kind: DFNodeKind::Return,
                                sanitized: true,
                                branch: branch_stack.last().copied(),
                                line: ret_line,
                                ..Default::default()
                            },
                        );
                        fn_returns.entry(func_id).or_default().push(id);
                    }
                }
            } else {
                for name in ids {
                    let (id, ret_line) = stable_node_id2(fir, Some(node), &format!("return:{name}"));
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: name.clone(),
                            kind: DFNodeKind::Return,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: ret_line,
                            ..Default::default()
                        },
                    );
                    fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                        name: name.clone(),
                        sanitized: false,
                        def: None,
                        alias_of: None,
                    });
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def) {
                        push_edge(fir, (def_id, id));
                    }
                    if let Some(func_id) = current_fn {
                        fn_returns.entry(func_id).or_default().push(id);
                    }
                }
            }
        }
        "method_invocation" => {
            let mut callee = None;
            if let Some(path) = extract_call_path(node, src) {
                if let Some(&cid) = fn_ids.get(path.rsplit('.').next().unwrap_or(&path)) {
                    callee = Some(cid);
                    if let Some(caller_id) = current_fn {
                        fir.dfg
                            .get_or_insert_with(DataFlowGraph::default)
                            .calls
                            .push((caller_id, cid));
                    }
                }
            }

            let receiver_name = node
                .child_by_field_name("object")
                .and_then(|obj| node_text_trimmed(obj, src));
            let method_name = node
                .child_by_field_name("name")
                .and_then(|n| node_text_trimmed(n, src));

            let mut arg_nodes: Vec<Node> = Vec::new();
            if let Some(args) = node.child_by_field_name("arguments") {
                let mut cursor = args.walk();
                for arg in args.children(&mut cursor).filter(|n| n.is_named()) {
                    arg_nodes.push(arg);
                }
            }

            if let Some(obj_node) = node.child_by_field_name("object") {
                let mut vars = Vec::new();
                gather_ids(obj_node, src, &mut vars);
                for var in vars {
                    let canonical = resolve_alias(&var, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (id, obj_use_line) =
                        stable_node_id2(fir, Some(obj_node), &format!("method_object_use:{var}"));
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: var.to_string(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: obj_use_line,
                        ..Default::default()
                        },
                    );
                    if let Some(def_id) = find_symbol(&var, &fir.symbols).and_then(|s| s.def) {
                        push_edge(fir, (def_id, id));
                    } else if let Some(def_id) =
                        find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        push_edge(fir, (def_id, id));
                    }
                }
            }

            for (idx, arg) in arg_nodes.iter().enumerate() {
                if arg.kind() == "lambda_expression" || arg.kind() == "method_reference" {
                    continue;
                }
                let mut vars = Vec::new();
                gather_ids(*arg, src, &mut vars);
                for var in vars {
                    let canonical = resolve_alias(&var, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (id, arg_use_line) =
                        stable_node_id2(fir, Some(*arg), &format!("method_arg_use:{idx}:{var}"));
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: var.to_string(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: arg_use_line,
                        ..Default::default()
                        },
                    );
                    if let Some(def_id) = find_symbol(&var, &fir.symbols).and_then(|s| s.def) {
                        push_edge(fir, (def_id, id));
                        if let Some(cid) = callee {
                            call_args.push((def_id, cid, idx));
                        }
                    } else if let Some(def_id) =
                        find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        push_edge(fir, (def_id, id));
                        if let Some(cid) = callee {
                            call_args.push((def_id, cid, idx));
                        }
                    }
                }
            }

            let mut field_name: Option<String> = None;
            let mut value_index: Option<usize> = None;
            if let (Some(receiver), Some(method)) = (receiver_name.as_ref(), method_name.as_ref()) {
                match method.as_str() {
                    "put" | "replace" | "set" => {
                        if let Some(node) = arg_nodes.first() {
                            if let Some(key) = node_text_trimmed(*node, src) {
                                field_name = Some(format!("{receiver}[{key}]"));
                                value_index = Some(1);
                            }
                        }
                    }
                    "add" => {
                        if arg_nodes.len() >= 2 {
                            if let Some(node) = arg_nodes.first() {
                                if let Some(key) = node_text_trimmed(*node, src) {
                                    field_name = Some(format!("{receiver}[{key}]"));
                                    value_index = Some(1);
                                }
                            }
                        }
                    }
                    "get" | "remove" => {
                        if let Some(node) = arg_nodes.first() {
                            if let Some(key) = node_text_trimmed(*node, src) {
                                field_name = Some(format!("{receiver}[{key}]"));
                            }
                        }
                    }
                    _ => {}
                }
            }

            if let (Some(field), Some(val_idx)) = (field_name.clone(), value_index) {
                if let Some(value_node) = arg_nodes.get(val_idx) {
                    if value_node.kind() != "lambda_expression"
                        && value_node.kind() != "method_reference"
                    {
                        let mut value_ids = Vec::new();
                        let mut sanitized_value = false;
                        if let Some(call) = extract_call_path(*value_node, src) {
                            if resolve_import(&call, imports, wildcards)
                                .into_iter()
                                .chain(std::iter::once(call.clone()))
                                .any(|f| {
                                    catalog_module::is_sanitizer("java", &f)
                                        || matches!(
                                            fir.symbol_types.get(&f),
                                            Some(SymbolKind::Sanitizer)
                                        )
                                })
                            {
                                sanitized_value = true;
                            }
                            if let Some(args) = value_node.child_by_field_name("arguments") {
                                gather_ids(args, src, &mut value_ids);
                            }
                        } else {
                            gather_ids(*value_node, src, &mut value_ids);
                        }

                        let canonical_sources: Vec<String> = value_ids
                            .iter()
                            .map(|name| resolve_alias(name, &fir.symbols))
                            .collect();
                        if canonical_sources.is_empty() {
                            // No variable references — value is entirely literal/constant.
                            if is_constant_expression(*value_node) {
                                sanitized_value = true;
                            }
                        } else if canonical_sources.iter().any(|canonical| {
                            find_symbol(canonical, &fir.symbols)
                                .map(|s| s.sanitized)
                                .unwrap_or(false)
                        }) {
                            sanitized_value = true;
                        }

                        let (def_id, field_def_line) = stable_node_id2(
                            fir,
                            Some(*value_node),
                            &format!("method_field_def:{field}"),
                        );
                        push_node(
                            fir,
                            DFNode {
                                id: def_id,
                                name: field.clone(),
                                kind: DFNodeKind::Def,
                                sanitized: sanitized_value,
                                branch: branch_stack.last().copied(),
                                line: field_def_line,
                        ..Default::default()
                            },
                        );

                        {
                            let entry =
                                fir.symbols.entry(field.clone()).or_insert_with(|| Symbol {
                                    name: field.clone(),
                                    sanitized: false,
                                    def: None,
                                    alias_of: None,
                                });
                            entry.def = Some(def_id);
                            entry.alias_of = None;
                            entry.sanitized = sanitized_value;
                        }

                        for canonical in canonical_sources {
                            if let Some(def_src) =
                                find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                            {
                                push_edge(fir, (def_src, def_id));
                            }
                        }
                    }
                }
            }

            if let (Some(field), Some(method)) = (field_name, method_name.clone()) {
                if matches!(method.as_str(), "get" | "remove") {
                    let canonical = resolve_alias(&field, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let (use_id, field_use_line) =
                        stable_node_id2(fir, Some(node), &format!("method_field_use:{field}"));
                    push_node(
                        fir,
                        DFNode {
                            id: use_id,
                            name: field,
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                            line: field_use_line,
                        ..Default::default()
                        },
                    );
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        push_edge(fir, (def_id, use_id));
                    }
                }
            }

            // Mutation tracking: for builder/stream methods that mutate the receiver,
            // propagate taint from arguments to the receiver's symbol.
            if let (Some(receiver), Some(method)) = (receiver_name.as_ref(), method_name.as_ref())
            {
                if matches!(
                    method.as_str(),
                    "append"
                        | "insert"
                        | "prepend"
                        | "write"
                        | "print"
                        | "println"
                        | "printf"
                        | "format"
                        | "setCharAt"
                        | "delete"
                        | "deleteCharAt"
                        | "replace"
                ) {
                    let any_arg_tainted = arg_nodes.iter().any(|arg| {
                        if is_constant_expression(*arg) {
                            return false;
                        }
                        let mut vars = Vec::new();
                        gather_ids(*arg, src, &mut vars);
                        if vars.is_empty() {
                            // Unknown expression: conservative unless it's a literal kind
                            !arg.kind().ends_with("_literal")
                                && arg.kind() != "null_literal"
                                && arg.kind() != "true"
                                && arg.kind() != "false"
                        } else {
                            vars.iter().any(|var| {
                                let canonical = resolve_alias(var, &fir.symbols);
                                !find_symbol(&canonical, &fir.symbols)
                                    .map(|s| s.sanitized)
                                    .unwrap_or(false)
                            })
                        }
                    });
                    if any_arg_tainted {
                        let canonical = resolve_alias(receiver, &fir.symbols);
                        // Update the symbol table so downstream uses pick up the new taint.
                        if let Some(sym) = fir.symbols.get_mut(&canonical) {
                            sym.sanitized = false;
                        } else if let Some(sym) = fir.symbols.get_mut(receiver.as_str()) {
                            sym.sanitized = false;
                        }
                        // Also update the existing Def node in the DFG.
                        let def_id_opt =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def);
                        if let Some(def_id) = def_id_opt {
                            if let Some(dfg) = fir.dfg.as_mut() {
                                if let Some(n) = find_node_mut(dfg, def_id) {
                                    n.sanitized = false;
                                }
                            }
                        }
                    }
                }
            }
        }
        "object_creation_expression" => {
            if let Some(args) = node.child_by_field_name("arguments") {
                let mut cursor = args.walk();
                for arg in args.children(&mut cursor).filter(|n| n.is_named()) {
                    if arg.kind() == "lambda_expression" || arg.kind() == "method_reference" {
                        continue;
                    }
                    let mut vars = Vec::new();
                    gather_ids(arg, src, &mut vars);
                    for var in vars {
                        let canonical = resolve_alias(&var, &fir.symbols);
                        let sanitized = find_symbol(&canonical, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or(false);
                        let (id, oc_use_line) =
                            stable_node_id2(fir, Some(arg), &format!("object_create_use:{var}"));
                        push_node(
                            fir,
                            DFNode {
                                id,
                                name: var.to_string(),
                                kind: DFNodeKind::Use,
                                sanitized,
                                branch: branch_stack.last().copied(),
                                line: oc_use_line,
                        ..Default::default()
                            },
                        );
                        if let Some(def_id) = find_symbol(&var, &fir.symbols).and_then(|s| s.def) {
                            push_edge(fir, (def_id, id));
                        } else if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            push_edge(fir, (def_id, id));
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        build_dfg(
            child,
            src,
            fir,
            imports,
            wildcards,
            current_fn,
            fn_ids,
            fn_params,
            fn_returns,
            call_args,
            branch_stack,
            branch_counter,
            merge_counter,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn build_dfg_tolerant(
    node: Node,
    src: &str,
    fir: &mut FileIR,
    imports: &HashMap<String, String>,
    wildcards: &[String],
    current_fn: Option<usize>,
    fn_ids: &mut HashMap<String, usize>,
    fn_params: &mut HashMap<usize, Vec<usize>>,
    fn_returns: &mut HashMap<usize, Vec<usize>>,
    call_args: &mut Vec<(usize, usize, usize)>,
    branch_stack: &mut Vec<usize>,
    branch_counter: &mut usize,
    merge_counter: &mut usize,
) {
    if node.is_error() {
        return;
    }
    if node.has_error() {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            build_dfg_tolerant(
                child,
                src,
                fir,
                imports,
                wildcards,
                current_fn,
                fn_ids,
                fn_params,
                fn_returns,
                call_args,
                branch_stack,
                branch_counter,
                merge_counter,
            );
        }
    } else {
        build_dfg(
            node,
            src,
            fir,
            imports,
            wildcards,
            current_fn,
            fn_ids,
            fn_params,
            fn_returns,
            call_args,
            branch_stack,
            branch_counter,
            merge_counter,
        );
    }
}

pub fn build(
    root: Node,
    content: &str,
    fir: &mut FileIR,
    imports: &HashMap<String, String>,
    wildcards: &[String],
) {
    let mut fn_ids = HashMap::new();
    let mut fn_params: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut fn_returns: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut call_args: Vec<(usize, usize, usize)> = Vec::new();
    let mut branch_stack: Vec<usize> = Vec::new();
    let mut branch_counter: usize = 0;
    let mut merge_counter: usize = 0;
    let has_errors = root.has_error() || root.is_error();

    if has_errors {
        build_dfg_tolerant(
            root,
            content,
            fir,
            imports,
            wildcards,
            None,
            &mut fn_ids,
            &mut fn_params,
            &mut fn_returns,
            &mut call_args,
            &mut branch_stack,
            &mut branch_counter,
            &mut merge_counter,
        );
    } else {
        build_dfg(
            root,
            content,
            fir,
            imports,
            wildcards,
            None,
            &mut fn_ids,
            &mut fn_params,
            &mut fn_returns,
            &mut call_args,
            &mut branch_stack,
            &mut branch_counter,
            &mut merge_counter,
        );
    }

    if let Some(dfg) = &mut fir.dfg {
        for (src, callee, idx) in call_args {
            if let Some(params) = fn_params.get(&callee) {
                if let Some(&pid) = params.get(idx) {
                    dfg.edges.push((src, pid));
                    let src_san = dfg
                        .nodes
                        .iter()
                        .find(|n| n.id == src)
                        .map(|n| n.sanitized)
                        .unwrap_or(false);
                    if src_san {
                        if let Some(pnode) = dfg.nodes.iter_mut().find(|n| n.id == pid) {
                            pnode.sanitized = true;
                        }
                        if let Some(name) = dfg
                            .nodes
                            .iter()
                            .find(|n| n.id == pid)
                            .map(|n| n.name.clone())
                        {
                            if let Some(sym) = fir.symbols.get_mut(&name) {
                                sym.sanitized = true;
                            }
                        }
                    }
                }
            }
        }
        let edges_snapshot = dfg.edges.clone();
        for (src_id, dst_id) in edges_snapshot {
            let src_san = dfg
                .nodes
                .iter()
                .find(|n| n.id == src_id)
                .map(|n| n.sanitized)
                .unwrap_or(false);
            if src_san {
                if let Some(dst_node) = dfg.nodes.iter_mut().find(|n| n.id == dst_id) {
                    if matches!(dst_node.kind, DFNodeKind::Return) {
                        dst_node.sanitized = true;
                    }
                }
            }
        }
        for (dest, callee) in dfg.call_returns.clone() {
            if let Some(rets) = fn_returns.get(&callee) {
                // A call site is sanitized only when ALL return paths are sanitized.
                let mut all_sanit = !rets.is_empty();
                for &r in rets {
                    dfg.edges.push((r, dest));
                    if !dfg
                        .nodes
                        .iter()
                        .find(|n| n.id == r)
                        .map(|n| n.sanitized)
                        .unwrap_or(false)
                    {
                        all_sanit = false;
                    }
                }
                if all_sanit {
                    if let Some(dnode) = dfg.nodes.iter_mut().find(|n| n.id == dest) {
                        dnode.sanitized = true;
                    }
                    for sym in fir.symbols.values_mut() {
                        if sym.def == Some(dest) {
                            sym.sanitized = true;
                            break;
                        }
                    }
                }
            }
        }
    }
    propagate_sanitized(fir);
}
