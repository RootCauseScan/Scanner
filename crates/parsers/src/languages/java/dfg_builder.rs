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
        Some(sym)
    } else if let Some(base) = base_of(name) {
        find_symbol(base, symbols)
    } else {
        None
    }
}

fn node_text_trimmed(node: Node, src: &str) -> Option<String> {
    node.utf8_text(src.as_bytes())
        .ok()
        .map(|s| s.trim().to_string())
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
                        out.push(id.to_string());
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

fn find_node_mut<'a>(dfg: &'a mut DataFlowGraph, id: usize) -> Option<&'a mut DFNode> {
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
        let mut queue: Vec<usize> = dfg
            .nodes
            .iter()
            .filter(|n| n.sanitized)
            .map(|n| n.id)
            .collect();
        let mut visited = HashSet::new();
        let edges = dfg.edges.clone();
        while let Some(id) = queue.pop() {
            if !visited.insert(id) {
                continue;
            }
            for &(src, dst) in &edges {
                if src == id {
                    if let Some(node) = find_node_mut(dfg, dst) {
                        if matches!(node.kind, DFNodeKind::Assign) && node.branch.is_none() {
                            continue;
                        }
                        if !node.sanitized {
                            node.sanitized = true;
                            let canonical = resolve_alias(&node.name, &fir.symbols);
                            if let Some(sym) = fir.symbols.get_mut(&canonical) {
                                sym.sanitized = true;
                            } else if let Some(sym) = fir.symbols.get_mut(&node.name) {
                                sym.sanitized = true;
                            }
                            queue.push(dst);
                        }
                    }
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
                    let id = stable_node_id(fir, Some(name_node), &format!("function:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: name.to_string(),
                            kind: DFNodeKind::Def,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        },
                    );
                    fn_ids.insert(name.to_string(), id);
                    if let Some(params) = node.child_by_field_name("parameters") {
                        let mut pc = params.walk();
                        for p in params.children(&mut pc) {
                            if p.kind() == "formal_parameter" {
                                if let Some(pn) = p.child_by_field_name("name") {
                                    if let Ok(pname) = pn.utf8_text(src.as_bytes()) {
                                        let pid = stable_node_id(
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
        "local_variable_declaration" => {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "variable_declarator" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(var) = name_node.utf8_text(src.as_bytes()) {
                            let mut ids = Vec::new();
                            let mut sanitized = false;
                            if let Some(val) = child.child_by_field_name("value") {
                                if val.kind() != "lambda_expression"
                                    && val.kind() != "method_reference"
                                {
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
                                            sanitized = true;
                                            call_sanitizer = true;
                                        }
                                        if let Some(args) = val.child_by_field_name("arguments") {
                                            gather_ids(args, src, &mut ids);
                                        }
                                        if !call_sanitizer {
                                            gather_ids(val, src, &mut ids);
                                        }
                                    } else {
                                        gather_ids(val, src, &mut ids);
                                    }
                                }
                            }
                            let id = stable_node_id(fir, Some(name_node), &format!("local:{var}"));
                            fir.dfg
                                .get_or_insert_with(DataFlowGraph::default)
                                .nodes
                                .push(DFNode {
                                    id,
                                    name: var.to_string(),
                                    kind: DFNodeKind::Def,
                                    sanitized,
                                    branch: branch_stack.last().copied(),
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
                        if right.kind() != "lambda_expression" && right.kind() != "method_reference"
                        {
                            let mut call_sanitizer = false;
                            if let Some(call) = extract_call_path(right, src) {
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
                                    sanitized = true;
                                    call_sanitizer = true;
                                }
                                if let Some(args) = right.child_by_field_name("arguments") {
                                    gather_ids(args, src, &mut ids);
                                }
                                if !call_sanitizer {
                                    gather_ids(right, src, &mut ids);
                                }
                            } else {
                                gather_ids(right, src, &mut ids);
                            }
                        }
                    }
                    let alias_cand = if ids.len() == 1
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
                    let id = stable_node_id(fir, Some(left), &format!("local:{var}"));
                    fir.dfg
                        .get_or_insert_with(DataFlowGraph::default)
                        .nodes
                        .push(DFNode {
                            id,
                            name: var.to_string(),
                            kind: DFNodeKind::Def,
                            sanitized: sanitized || alias_sanitized,
                            branch: branch_stack.last().copied(),
                        });
                    let canonical_names: Vec<String> = ids
                        .iter()
                        .map(|src_name| resolve_alias(src_name, &fir.symbols))
                        .collect();

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
                    if let Some(c) = alias_cand {
                        sym.alias_of = Some(c.clone());
                        if alias_sanitized {
                            sym.sanitized = true;
                        }
                    }
                    if sanitized {
                        sym.sanitized = true;
                    }
                    if base_sanitized {
                        sym.sanitized = true;
                    }
                    if sym.sanitized {
                        if let Some(dfg) = fir.dfg.as_mut() {
                            if let Some(n) = find_node_mut(dfg, id) {
                                n.sanitized = true;
                            }
                        }
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
            let func_id = stable_node_id(fir, Some(node), "lambda");
            let lname = format!("lambda_{func_id}");
            push_node(
                fir,
                DFNode {
                    id: func_id,
                    name: lname,
                    kind: DFNodeKind::Def,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
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
                        let rid = stable_node_id(
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
                    let uid = stable_node_id(fir, Some(cond), &format!("if_cond_use:{name}"));
                    fir.dfg
                        .get_or_insert_with(DataFlowGraph::default)
                        .nodes
                        .push(DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
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
            let bid = stable_node_id(fir, Some(node), "branch:if");
            fir.dfg
                .get_or_insert_with(DataFlowGraph::default)
                .nodes
                .push(DFNode {
                    id: bid,
                    name: "if".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                });
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

            let bid = stable_node_id(fir, Some(node), "branch:try");
            push_node(
                fir,
                DFNode {
                    id: bid,
                    name: "try".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
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
                        if let Some(param) = child.child_by_field_name("parameter") {
                            build_dfg(
                                param,
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
            let nid = stable_node_id(fir, Some(node), "branch:while");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "while".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
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
                    let uid = stable_node_id(fir, Some(cond), &format!("while_cond_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
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
            let nid = stable_node_id(fir, Some(node), "branch:for");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "for".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
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
                    let uid = stable_node_id(fir, Some(cond), &format!("for_cond_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
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
            let nid = stable_node_id(fir, Some(node), "branch:enhanced_for");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "for".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                },
            );
            if let Some(val) = node.child_by_field_name("value") {
                let mut ids = Vec::new();
                gather_ids(val, src, &mut ids);
                for name in ids {
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let uid = stable_node_id(fir, Some(val), &format!("enhanced_for_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
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
        "switch_statement" | "switch_expression" => {
            let nid = stable_node_id(fir, Some(node), "branch:switch");
            push_node(
                fir,
                DFNode {
                    id: nid,
                    name: "switch".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
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
                    let uid = stable_node_id(fir, Some(cond), &format!("switch_cond_use:{name}"));
                    push_node(
                        fir,
                        DFNode {
                            id: uid,
                            name: name.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
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
                let id = stable_node_id(fir, Some(node), &format!("method_ref:{name}"));
                push_node(
                    fir,
                    DFNode {
                        id,
                        name,
                        kind: DFNodeKind::Use,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                    },
                );
            }
            return;
        }
        "return_statement" => {
            let mut ids = Vec::new();
            gather_ids(node, src, &mut ids);
            for name in ids {
                let id = stable_node_id(fir, Some(node), &format!("return:{name}"));
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
                    let id =
                        stable_node_id(fir, Some(obj_node), &format!("method_object_use:{var}"));
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: var.to_string(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
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
                    let id =
                        stable_node_id(fir, Some(*arg), &format!("method_arg_use:{idx}:{var}"));
                    push_node(
                        fir,
                        DFNode {
                            id,
                            name: var.to_string(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
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
                        if let Some(node) = arg_nodes.get(0) {
                            if let Some(key) = node_text_trimmed(*node, src) {
                                field_name = Some(format!("{receiver}[{key}]"));
                                value_index = Some(1);
                            }
                        }
                    }
                    "add" => {
                        if arg_nodes.len() >= 2 {
                            if let Some(node) = arg_nodes.get(0) {
                                if let Some(key) = node_text_trimmed(*node, src) {
                                    field_name = Some(format!("{receiver}[{key}]"));
                                    value_index = Some(1);
                                }
                            }
                        }
                    }
                    "get" | "remove" => {
                        if let Some(node) = arg_nodes.get(0) {
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
                        if canonical_sources.iter().any(|canonical| {
                            find_symbol(canonical, &fir.symbols)
                                .map(|s| s.sanitized)
                                .unwrap_or(false)
                        }) {
                            sanitized_value = true;
                        }

                        let def_id = stable_node_id(
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

            if let (Some(field), Some(method)) = (field_name, method_name) {
                if matches!(method.as_str(), "get" | "remove") {
                    let canonical = resolve_alias(&field, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let use_id =
                        stable_node_id(fir, Some(node), &format!("method_field_use:{field}"));
                    push_node(
                        fir,
                        DFNode {
                            id: use_id,
                            name: field,
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                        },
                    );
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        push_edge(fir, (def_id, use_id));
                    }
                }
            }
        }
        "object_creation_expression" => {
            if let Some(args) = node.child_by_field_name("arguments") {
                let mut cursor = args.walk();
                for (_idx, arg) in args
                    .children(&mut cursor)
                    .filter(|n| n.is_named())
                    .enumerate()
                {
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
                        let id =
                            stable_node_id(fir, Some(arg), &format!("object_create_use:{var}"));
                        push_node(
                            fir,
                            DFNode {
                                id,
                                name: var.to_string(),
                                kind: DFNodeKind::Use,
                                sanitized,
                                branch: branch_stack.last().copied(),
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
                let mut sanit = false;
                for &r in rets {
                    dfg.edges.push((r, dest));
                    if dfg
                        .nodes
                        .iter()
                        .find(|n| n.id == r)
                        .map(|n| n.sanitized)
                        .unwrap_or(false)
                    {
                        sanit = true;
                    }
                }
                if sanit {
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
