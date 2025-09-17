use crate::catalog;
use ir::{stable_id, DFNode, DFNodeKind, DataFlowGraph, FileIR, Symbol, SymbolKind};
use std::collections::{HashMap, HashSet};

use super::tokens::canonical_call_path;

pub(crate) fn resolve_alias(name: &str, symbols: &HashMap<String, Symbol>) -> String {
    if let Some((head, tail)) = name.split_once('.') {
        let resolved_head = resolve_alias(head, symbols);
        if tail.is_empty() {
            resolved_head
        } else {
            format!("{resolved_head}.{tail}")
        }
    } else {
        let mut current = name;
        let mut visited: HashSet<String> = HashSet::new();
        visited.insert(current.to_string());
        let mut last_alias = None;
        while let Some(sym) = symbols.get(current) {
            if let Some(next) = sym.alias_of.as_deref() {
                last_alias = Some(next.to_string());
                if !visited.insert(next.to_string()) {
                    break;
                }
                current = next;
            } else {
                break;
            }
        }
        last_alias.unwrap_or_else(|| current.to_string())
    }
}

fn is_sanitizer(name: &str, fir: &FileIR) -> bool {
    catalog::is_sanitizer("python", name)
        || matches!(fir.symbol_types.get(name), Some(SymbolKind::Sanitizer))
}

fn merge_states(fir: &mut FileIR, states: Vec<HashMap<String, Symbol>>) {
    let mut names = HashSet::new();
    for state in &states {
        for name in state.keys() {
            names.insert(name.clone());
        }
    }
    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
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
                let id = dfg.nodes.len();
                dfg.nodes.push(DFNode {
                    id,
                    name: name.clone(),
                    kind: DFNodeKind::Assign,
                    sanitized: sanitized_all,
                    branch: None,
                });
                for d in defs {
                    dfg.edges.push((d, id));
                }
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_dfg(
    node: tree_sitter::Node,
    src: &str,
    fir: &mut FileIR,
    current_fn: Option<usize>,
    fn_ids: &mut HashMap<String, usize>,
    fn_params: &mut HashMap<usize, Vec<usize>>,
    fn_returns: &mut HashMap<usize, Vec<usize>>,
    call_args: &mut Vec<(usize, usize, usize)>,
    branch_stack: &mut Vec<usize>,
    branch_counter: &mut usize,
) {
    fn gather_ids(node: tree_sitter::Node, src: &str, out: &mut Vec<String>) {
        match node.kind() {
            "identifier" => {
                if let Ok(name) = node.utf8_text(src.as_bytes()) {
                    out.push(name.to_string());
                }
            }
            "attribute" => {
                let mut bases = Vec::new();
                if let Some(obj) = node.child_by_field_name("object") {
                    gather_ids(obj, src, &mut bases);
                }
                if let Some(attr) = node.child_by_field_name("attribute") {
                    if let Ok(aname) = attr.utf8_text(src.as_bytes()) {
                        if bases.is_empty() {
                            out.push(aname.to_string());
                        } else {
                            for base in bases {
                                out.push(format!("{base}.{aname}"));
                            }
                        }
                    }
                }
            }
            "subscript" => {
                let mut bases = Vec::new();
                if let Some(value) = node.child_by_field_name("value") {
                    gather_ids(value, src, &mut bases);
                }
                if let Some(index) = node
                    .child_by_field_name("index")
                    .or_else(|| node.child_by_field_name("slice"))
                    .or_else(|| node.child_by_field_name("subscript"))
                {
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
            }
            "call" => {
                if let Some(func) = node.child_by_field_name("function") {
                    if let Ok(name) = func.utf8_text(src.as_bytes()) {
                        if name == "getattr" {
                            if let Some(args) = node.child_by_field_name("arguments") {
                                let mut ac = args.walk();
                                let arg_nodes: Vec<tree_sitter::Node> =
                                    args.named_children(&mut ac).collect();
                                if arg_nodes.len() >= 2 {
                                    let attr_node = arg_nodes[1];
                                    if attr_node.kind() == "string" {
                                        if let Ok(aname) = attr_node.utf8_text(src.as_bytes()) {
                                            let attr_name =
                                                aname.trim_matches(['"', '\'']).to_string();
                                            let mut bases = Vec::new();
                                            gather_ids(arg_nodes[0], src, &mut bases);
                                            for base in bases {
                                                out.push(format!("{base}.{attr_name}"));
                                            }
                                        }
                                    }
                                }
                            }
                            return;
                        }
                    }
                }
                let mut c = node.walk();
                for child in node.children(&mut c) {
                    gather_ids(child, src, out);
                }
            }
            _ => {
                let mut c = node.walk();
                for child in node.children(&mut c) {
                    gather_ids(child, src, out);
                }
            }
        }
    }
    let mut cursor = node.walk();
    match node.kind() {
        "decorated_definition" => {
            fn has_timeit(node: tree_sitter::Node, src: &str) -> bool {
                if node.kind() == "decorator" {
                    if let Ok(text) = node.utf8_text(src.as_bytes()) {
                        let deco = text.trim().trim_start_matches('@');
                        if deco.starts_with("timeit") {
                            return true;
                        }
                    }
                }
                let mut c = node.walk();
                for child in node.children(&mut c) {
                    if has_timeit(child, src) {
                        return true;
                    }
                }
                false
            }
            let mut func_name: Option<String> = None;
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                if child.kind() == "function_definition"
                    || child.kind() == "async_function_definition"
                {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                            func_name = Some(name.to_string());
                        }
                    }
                }
            }
            if has_timeit(node, src) {
                if let Some(name) = func_name {
                    fir.symbol_types.insert(name, SymbolKind::Special);
                }
            }
        }
        "function_definition" | "async_function_definition" => {
            let func_node = if node.kind() == "async_function_definition" {
                node.child_by_field_name("function").unwrap_or(node)
            } else {
                node
            };
            if let Some(name_node) = func_node.child_by_field_name("name") {
                if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                    let id = fn_ids.len();
                    fn_ids.insert(name.to_string(), id);

                    if let Some(params) = func_node.child_by_field_name("parameters") {
                        let mut pc = params.walk();
                        for param in params.children(&mut pc) {
                            let ident = match param.kind() {
                                "identifier" => Some(param),
                                _ => param.child_by_field_name("name").or_else(|| param.child(0)),
                            };
                            if let Some(ident) = ident {
                                if ident.kind() == "identifier" {
                                    if let Ok(pname) = ident.utf8_text(src.as_bytes()) {
                                        let dfg =
                                            fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                        let pos = ident.start_position();
                                        let pid = stable_id(
                                            &fir.file_path,
                                            pos.row + 1,
                                            pos.column + 1,
                                            pname,
                                        );
                                        dfg.nodes.push(DFNode {
                                            id: pid,
                                            name: pname.to_string(),
                                            kind: DFNodeKind::Param,
                                            sanitized: false,
                                            branch: branch_stack.last().copied(),
                                        });
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

                    let mut c = func_node.walk();
                    for child in func_node.children(&mut c) {
                        build_dfg(
                            child,
                            src,
                            fir,
                            Some(id),
                            fn_ids,
                            fn_params,
                            fn_returns,
                            call_args,
                            branch_stack,
                            branch_counter,
                        );
                    }
                    return;
                }
            }
        }
        "if_statement" => {
            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
            let bid = dfg.nodes.len();
            dfg.nodes.push(DFNode {
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
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                );
                branch_states.push(fir.symbols.clone());
                branch_stack.pop();
            }
            let mut alt_found = false;
            let mut c_alt = node.walk();
            for child in node.children(&mut c_alt) {
                if matches!(child.kind(), "elif_clause" | "else_clause") {
                    alt_found = true;
                    let id = *branch_counter;
                    *branch_counter += 1;
                    fir.symbols = before.clone();
                    branch_stack.push(id);
                    build_dfg(
                        child,
                        src,
                        fir,
                        current_fn,
                        fn_ids,
                        fn_params,
                        fn_returns,
                        call_args,
                        branch_stack,
                        branch_counter,
                    );
                    branch_states.push(fir.symbols.clone());
                    branch_stack.pop();
                }
            }
            if !alt_found {
                branch_states.push(before.clone());
            }
            merge_states(fir, branch_states);
            return;
        }
        "match_statement" => {
            if let Some(subject) = node.child_by_field_name("subject") {
                build_dfg(
                    subject,
                    src,
                    fir,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                );
            }
            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
            let id = dfg.nodes.len();
            dfg.nodes.push(DFNode {
                id,
                name: "match".to_string(),
                kind: DFNodeKind::Branch,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let mut bc = body.walk();
                for case in body.children(&mut bc) {
                    if case.kind() == "case_clause" {
                        let bid = *branch_counter;
                        *branch_counter += 1;
                        fir.symbols = before.clone();
                        branch_stack.push(bid);
                        if let Some(b) = case.child_by_field_name("body") {
                            build_dfg(
                                b,
                                src,
                                fir,
                                current_fn,
                                fn_ids,
                                fn_params,
                                fn_returns,
                                call_args,
                                branch_stack,
                                branch_counter,
                            );
                        }
                        branch_states.push(fir.symbols.clone());
                        branch_stack.pop();
                    }
                }
            }
            if branch_states.is_empty() {
                branch_states.push(before.clone());
            }
            let mut names = HashSet::new();
            for state in &branch_states {
                for name in state.keys() {
                    names.insert(name.clone());
                }
            }
            let mut merged: HashMap<String, Symbol> = HashMap::new();
            for name in names {
                let mut sanitized_all = true;
                let mut def = None;
                let mut alias = None;
                for state in &branch_states {
                    if let Some(sym) = state.get(&name) {
                        sanitized_all &= sym.sanitized;
                        if def.is_none() {
                            def = sym.def;
                        }
                        if alias.is_none() {
                            alias = sym.alias_of.clone();
                        }
                    } else {
                        sanitized_all = false;
                    }
                }
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
            return;
        }
        "assignment" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                let mut targets = Vec::new();
                gather_ids(left, src, &mut targets);
                if let Some(var) = targets.first() {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let pos = left.start_position();
                    let id = stable_id(&fir.file_path, pos.row + 1, pos.column + 1, var);
                    dfg.nodes.push(DFNode {
                        id,
                        name: var.to_string(),
                        kind: DFNodeKind::Def,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                    });
                    let alias_of = fir.symbols.get(var).and_then(|s| s.alias_of.clone());
                    fir.symbols.insert(
                        var.to_string(),
                        Symbol {
                            name: var.to_string(),
                            sanitized: false,
                            def: Some(id),
                            alias_of,
                        },
                    );
                    let call_node = if right.kind() == "await" {
                        right
                            .child_by_field_name("expression")
                            .or_else(|| right.child(0))
                    } else if right.kind() == "call" {
                        Some(right)
                    } else {
                        None
                    };
                    if let Some(call) = call_node.filter(|n| n.kind() == "call") {
                        let mut fname = String::new();
                        let mut callee = None;
                        let mut fname_tail_buf = String::new();
                        let mut is_source_call = false;
                        let mut call_receivers: Vec<String> = Vec::new();
                        if let Some(func) = call.child_by_field_name("function") {
                            if let Ok(name) = func.utf8_text(src.as_bytes()) {
                                fname = canonical_call_path(name, &fir.symbols);
                                let fname_tail = fname.rsplit('.').next().unwrap_or(&fname);
                                fname_tail_buf = fname_tail.to_string();
                                is_source_call = catalog::is_source("python", &fname)
                                    || catalog::is_source("python", fname_tail);
                                if let Some(&callee_id) = fn_ids.get(fname_tail) {
                                    dfg.call_returns.push((id, callee_id));
                                    callee = Some(callee_id);
                                }
                                if is_source_call {
                                    let pos = call.start_position();
                                    let id =
                                        stable_id(&fir.file_path, pos.row + 1, pos.column + 1, var);
                                    dfg.nodes.push(DFNode {
                                        id,
                                        name: var.to_string(),
                                        kind: DFNodeKind::Def,
                                        sanitized: false,
                                        branch: branch_stack.last().copied(),
                                    });
                                    fir.symbols.insert(
                                        var.to_string(),
                                        Symbol {
                                            name: var.to_string(),
                                            sanitized: false,
                                            def: Some(id),
                                            alias_of: None,
                                        },
                                    );
                                }
                            }
                            // Capture the receiver of the call (e.g. request.args)
                            match func.kind() {
                                "attribute" => {
                                    if let Some(obj) = func.child_by_field_name("object") {
                                        gather_ids(obj, src, &mut call_receivers);
                                    }
                                }
                                "identifier" => {
                                    if let Ok(name) = func.utf8_text(src.as_bytes()) {
                                        call_receivers.push(name.to_string());
                                    }
                                }
                                "subscript" => {
                                    gather_ids(func, src, &mut call_receivers);
                                }
                                _ => {}
                            }
                        }
                        let fname_tail = if fname_tail_buf.is_empty() {
                            fname.rsplit('.').next().unwrap_or(&fname).to_string()
                        } else {
                            fname_tail_buf
                        };
                        let fname_tail_str = fname_tail.as_str();
                        if fname_tail_str == "getattr" {
                            if let Some(args) = call.child_by_field_name("arguments") {
                                let mut ac = args.walk();
                                let arg_nodes: Vec<tree_sitter::Node> =
                                    args.named_children(&mut ac).collect();
                                if arg_nodes.len() >= 2 {
                                    let attr_node = arg_nodes[1];
                                    if attr_node.kind() == "string" {
                                        if let Ok(aname) = attr_node.utf8_text(src.as_bytes()) {
                                            let attr_name =
                                                aname.trim_matches(['"', '\'']).to_string();
                                            let mut bases = Vec::new();
                                            gather_ids(arg_nodes[0], src, &mut bases);
                                            for base in bases {
                                                let field = format!("{base}.{attr_name}");
                                                if let Some(def_id) =
                                                    fir.symbols.get(&field).and_then(|s| s.def)
                                                {
                                                    dfg.edges.push((def_id, id));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            let mut ids = Vec::new();
                            if let Some(args) = call.child_by_field_name("arguments") {
                                gather_ids(args, src, &mut ids);
                            }
                            for recv in call_receivers {
                                if !ids.contains(&recv) {
                                    ids.push(recv);
                                }
                            }
                            if let Some(callee_id) = callee {
                                for (idx, src_name) in ids.iter().enumerate() {
                                    if src_name.as_str() == var {
                                        continue;
                                    }
                                    let resolved = resolve_alias(src_name, &fir.symbols);
                                    if let Some(def_id) =
                                        fir.symbols.get(&resolved).and_then(|s| s.def)
                                    {
                                        call_args.push((def_id, callee_id, idx));
                                    }
                                }
                            }
                            let sink_call = catalog::is_sink("python", &fname)
                                || catalog::is_sink("python", fname_tail_str);
                            let _ = dfg;
                            if !is_source_call
                                && (is_sanitizer(&fname, fir)
                                    || is_sanitizer(fname_tail_str, fir)
                                    || (ids.is_empty() && !sink_call))
                            {
                                let canonical = resolve_alias(var, &fir.symbols);
                                if let Some(sym) = fir.symbols.get_mut(&canonical) {
                                    sym.sanitized = true;
                                    if let Some(def) = sym.def {
                                        if let Some(dfg) = &mut fir.dfg {
                                            if let Some(n) =
                                                dfg.nodes.iter_mut().find(|n| n.id == def)
                                            {
                                                n.sanitized = true;
                                            }
                                        }
                                    }
                                }
                                if canonical.as_str() != var {
                                    if let Some(sym) = fir.symbols.get_mut(var) {
                                        sym.alias_of = Some(canonical.clone());
                                        sym.sanitized = true;
                                    }
                                }
                                if let Some(dfg) = &mut fir.dfg {
                                    if let Some(n) = dfg.nodes.iter_mut().find(|n| n.id == id) {
                                        n.sanitized = true;
                                    }
                                }
                            }
                        }
                    } else {
                        let mut ids = Vec::new();
                        gather_ids(right, src, &mut ids);
                        if ids.is_empty() {
                            if let Some(sym) = fir.symbols.get_mut(var) {
                                sym.sanitized = true;
                            }
                            if let Some(n) = dfg.nodes.iter_mut().find(|n| n.id == id) {
                                n.sanitized = true;
                            }
                        }
                        for src_name in ids.iter() {
                            if src_name.as_str() == var {
                                continue;
                            }
                            let resolved = resolve_alias(src_name, &fir.symbols);
                            if let Some(def_id) = fir.symbols.get(&resolved).and_then(|s| s.def) {
                                dfg.edges.push((def_id, id));
                            }
                        }
                        if ids.len() == 1 && right.kind() == "identifier" {
                            let resolved = resolve_alias(&ids[0], &fir.symbols);
                            let src_sanitized = fir
                                .symbols
                                .get(&resolved)
                                .map(|s| s.sanitized)
                                .unwrap_or(false);
                            if let Some(dest) = fir.symbols.get_mut(var) {
                                dest.alias_of = Some(resolved);
                                dest.sanitized = src_sanitized;
                                if src_sanitized {
                                    if let Some(n) = dfg.nodes.iter_mut().find(|n| n.id == id) {
                                        n.sanitized = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        "augmented_assignment" => {
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                let mut targets = Vec::new();
                gather_ids(left, src, &mut targets);
                if let Some(var) = targets.first() {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let pos = left.start_position();
                    let id = stable_id(&fir.file_path, pos.row + 1, pos.column + 1, var);
                    dfg.nodes.push(DFNode {
                        id,
                        name: var.to_string(),
                        kind: DFNodeKind::Def,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                    });
                    let alias_of = fir.symbols.get(var).and_then(|s| s.alias_of.clone());
                    fir.symbols.insert(
                        var.to_string(),
                        Symbol {
                            name: var.to_string(),
                            sanitized: false,
                            def: Some(id),
                            alias_of,
                        },
                    );
                    let mut ids = Vec::new();
                    gather_ids(right, src, &mut ids);
                    for src_name in ids {
                        if src_name.as_str() == var {
                            continue;
                        }
                        let resolved = resolve_alias(&src_name, &fir.symbols);
                        if let Some(def_id) = fir.symbols.get(&resolved).and_then(|s| s.def) {
                            dfg.edges.push((def_id, id));
                        }
                    }
                }
            }
        }
        "return_statement" => {
            let mut ids = Vec::new();
            gather_ids(node, src, &mut ids);
            let pos = node.start_position();
            for name in ids {
                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                let id = stable_id(&fir.file_path, pos.row + 1, pos.column + 1, &name);
                let canonical = resolve_alias(&name, &fir.symbols);
                let sanitized = fir.symbols.get(&canonical).is_some_and(|s| s.sanitized);
                dfg.nodes.push(DFNode {
                    id,
                    name: name.clone(),
                    kind: DFNodeKind::Return,
                    sanitized,
                    branch: branch_stack.last().copied(),
                });
                fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                    name: name.clone(),
                    ..Default::default()
                });
                if let Some(def_id) = fir.symbols.get(&canonical).and_then(|s| s.def) {
                    dfg.edges.push((def_id, id));
                }
                if let Some(func_id) = current_fn {
                    fn_returns.entry(func_id).or_default().push(id);
                }
            }
        }
        "while_statement" => {
            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
            let nid = dfg.nodes.len();
            dfg.nodes.push(DFNode {
                id: nid,
                name: "while".to_string(),
                kind: DFNodeKind::Branch,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            if let Some(cond) = node.child_by_field_name("condition") {
                let mut ids = Vec::new();
                gather_ids(cond, src, &mut ids);
                let pos = cond.start_position();
                for name in ids {
                    let id = stable_id(&fir.file_path, pos.row + 1, pos.column + 1, &name);
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = fir.symbols.get(&canonical).is_some_and(|s| s.sanitized);
                    dfg.nodes.push(DFNode {
                        id,
                        name: name.clone(),
                        kind: DFNodeKind::Use,
                        sanitized,
                        branch: branch_stack.last().copied(),
                    });
                    fir.symbols.entry(name.clone()).or_insert_with(|| Symbol {
                        name: name.clone(),
                        ..Default::default()
                    });
                    if let Some(def_id) = fir.symbols.get(&canonical).and_then(|s| s.def) {
                        dfg.edges.push((def_id, id));
                    }
                }
            }
            let before = fir.symbols.clone();
            let bid = *branch_counter;
            *branch_counter += 1;
            branch_stack.push(bid);
            if let Some(body) = node.child_by_field_name("body") {
                build_dfg(
                    body,
                    src,
                    fir,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                );
            }
            let body_state = fir.symbols.clone();
            branch_stack.pop();
            merge_states(fir, vec![body_state, before]);
            return;
        }
        "for_statement" => {
            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
            let nid = dfg.nodes.len();
            dfg.nodes.push(DFNode {
                id: nid,
                name: "for".to_string(),
                kind: DFNodeKind::Branch,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            if let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) {
                if let Ok(var) = left.utf8_text(src.as_bytes()) {
                    let pos = left.start_position();
                    let id = stable_id(&fir.file_path, pos.row + 1, pos.column + 1, var);
                    dfg.nodes.push(DFNode {
                        id,
                        name: var.to_string(),
                        kind: DFNodeKind::Def,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                    });
                    fir.symbols.insert(
                        var.to_string(),
                        Symbol {
                            name: var.to_string(),
                            sanitized: false,
                            def: Some(id),
                            alias_of: None,
                        },
                    );
                    let mut ids = Vec::new();
                    gather_ids(right, src, &mut ids);
                    for src_name in ids {
                        if src_name.as_str() == var {
                            continue;
                        }
                        let resolved = resolve_alias(&src_name, &fir.symbols);
                        if let Some(def_id) = fir.symbols.get(&resolved).and_then(|s| s.def) {
                            dfg.edges.push((def_id, id));
                        }
                    }
                }
            }
            let before = fir.symbols.clone();
            let bid = *branch_counter;
            *branch_counter += 1;
            branch_stack.push(bid);
            if let Some(body) = node.child_by_field_name("body") {
                build_dfg(
                    body,
                    src,
                    fir,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                );
            }
            let body_state = fir.symbols.clone();
            branch_stack.pop();
            merge_states(fir, vec![body_state, before]);
            return;
        }
        "await" => {
            if let Some(expr) = node
                .child_by_field_name("expression")
                .or_else(|| node.child(0))
            {
                build_dfg(
                    expr,
                    src,
                    fir,
                    current_fn,
                    fn_ids,
                    fn_params,
                    fn_returns,
                    call_args,
                    branch_stack,
                    branch_counter,
                );
            }
            return;
        }
        "call" => {
            if let Some(func) = node.child_by_field_name("function") {
                if let Ok(raw) = func.utf8_text(src.as_bytes()) {
                    let full = canonical_call_path(raw, &fir.symbols);
                    let part = full.rsplit('.').next().unwrap_or(&full);
                    if part == "setattr" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut ac = args.walk();
                            let arg_nodes: Vec<tree_sitter::Node> =
                                args.named_children(&mut ac).collect();
                            if arg_nodes.len() >= 3 {
                                let obj_node = arg_nodes[0];
                                let attr_node = arg_nodes[1];
                                let val_node = arg_nodes[2];
                                if attr_node.kind() == "string" {
                                    if let Ok(aname) = attr_node.utf8_text(src.as_bytes()) {
                                        let attr_name = aname.trim_matches(['"', '\'']).to_string();
                                        let mut bases = Vec::new();
                                        gather_ids(obj_node, src, &mut bases);
                                        let mut src_ids = Vec::new();
                                        gather_ids(val_node, src, &mut src_ids);
                                        let dfg =
                                            fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                        let pos = obj_node.start_position();
                                        for base in bases {
                                            let field = format!("{base}.{attr_name}");
                                            let id = stable_id(
                                                &fir.file_path,
                                                pos.row + 1,
                                                pos.column + 1,
                                                &field,
                                            );
                                            dfg.nodes.push(DFNode {
                                                id,
                                                name: field.clone(),
                                                kind: DFNodeKind::Def,
                                                sanitized: false,
                                                branch: branch_stack.last().copied(),
                                            });
                                            let alias_of = fir
                                                .symbols
                                                .get(&field)
                                                .and_then(|s| s.alias_of.clone());
                                            fir.symbols.insert(
                                                field.clone(),
                                                Symbol {
                                                    name: field.clone(),
                                                    sanitized: false,
                                                    def: Some(id),
                                                    alias_of,
                                                },
                                            );
                                            for src_name in &src_ids {
                                                if src_name == &field {
                                                    continue;
                                                }
                                                let resolved =
                                                    resolve_alias(src_name, &fir.symbols);
                                                if let Some(def_id) =
                                                    fir.symbols.get(&resolved).and_then(|s| s.def)
                                                {
                                                    dfg.edges.push((def_id, id));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else if part == "getattr" {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut ac = args.walk();
                            let arg_nodes: Vec<tree_sitter::Node> =
                                args.named_children(&mut ac).collect();
                            if arg_nodes.len() >= 2 {
                                let obj_node = arg_nodes[0];
                                let attr_node = arg_nodes[1];
                                if attr_node.kind() == "string" {
                                    if let Ok(aname) = attr_node.utf8_text(src.as_bytes()) {
                                        let attr_name = aname.trim_matches(['"', '\'']).to_string();
                                        let mut bases = Vec::new();
                                        gather_ids(obj_node, src, &mut bases);
                                        let pos = obj_node.start_position();
                                        for base in bases {
                                            let field = format!("{base}.{attr_name}");
                                            let dfg =
                                                fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                            let id = stable_id(
                                                &fir.file_path,
                                                pos.row + 1,
                                                pos.column + 1,
                                                &field,
                                            );
                                            let sanitized = fir
                                                .symbols
                                                .get(&field)
                                                .map(|s| s.sanitized)
                                                .unwrap_or(false);
                                            dfg.nodes.push(DFNode {
                                                id,
                                                name: field.clone(),
                                                kind: DFNodeKind::Use,
                                                sanitized,
                                                branch: branch_stack.last().copied(),
                                            });
                                            if let Some(def_id) =
                                                fir.symbols.get(&field).and_then(|s| s.def)
                                            {
                                                dfg.edges.push((def_id, id));
                                            }
                                            fir.symbols.entry(field.clone()).or_insert_with(|| {
                                                Symbol {
                                                    name: field.clone(),
                                                    ..Default::default()
                                                }
                                            });
                                        }
                                    }
                                }
                            }
                        }
                    } else if let Some(&callee_id) = fn_ids.get(part) {
                        if let Some(caller_id) = current_fn {
                            fir.dfg
                                .get_or_insert_with(DataFlowGraph::default)
                                .calls
                                .push((caller_id, callee_id));
                        }
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut c = args.walk();
                            for (idx, arg) in args.children(&mut c).enumerate() {
                                let mut ids = Vec::new();
                                gather_ids(arg, src, &mut ids);
                                for var in ids {
                                    let resolved = resolve_alias(&var, &fir.symbols);
                                    if let Some(def_id) =
                                        fir.symbols.get(&resolved).and_then(|s| s.def)
                                    {
                                        call_args.push((def_id, callee_id, idx));
                                    }
                                }
                            }
                        }
                    }
                    let sink_call =
                        catalog::is_sink("python", &full) || catalog::is_sink("python", part);
                    if sink_call {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut c = args.walk();
                            for arg in args.children(&mut c) {
                                let mut ids = Vec::new();
                                gather_ids(arg, src, &mut ids);
                                let pos = arg.start_position();
                                for var in ids {
                                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                    let id = stable_id(
                                        &fir.file_path,
                                        pos.row + 1,
                                        pos.column + 1,
                                        &var,
                                    );
                                    let canonical = resolve_alias(&var, &fir.symbols);
                                    let sanitized =
                                        fir.symbols.get(&canonical).is_some_and(|s| s.sanitized);
                                    dfg.nodes.push(DFNode {
                                        id,
                                        name: var.to_string(),
                                        kind: DFNodeKind::Use,
                                        sanitized,
                                        branch: branch_stack.last().copied(),
                                    });
                                    if let Some(sym) = fir.symbols.get(&canonical) {
                                        if let Some(def_id) = sym.def {
                                            dfg.edges.push((def_id, id));
                                        }
                                    }
                                }
                            }
                        }
                    } else if is_sanitizer(&full, fir) {
                        if let Some(args) = node.child_by_field_name("arguments") {
                            let mut c = args.walk();
                            for arg in args.children(&mut c) {
                                let mut ids = Vec::new();
                                gather_ids(arg, src, &mut ids);
                                for var in ids {
                                    let canonical = resolve_alias(&var, &fir.symbols);
                                    let sym =
                                        fir.symbols.entry(canonical.clone()).or_insert_with(|| {
                                            Symbol {
                                                name: canonical.clone(),
                                                ..Default::default()
                                            }
                                        });
                                    sym.sanitized = true;
                                    if let Some(def) = sym.def {
                                        if let Some(dfg) = &mut fir.dfg {
                                            if let Some(node) = dfg.nodes.get_mut(def) {
                                                node.sanitized = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    for child in node.children(&mut cursor) {
        build_dfg(
            child,
            src,
            fir,
            current_fn,
            fn_ids,
            fn_params,
            fn_returns,
            call_args,
            branch_stack,
            branch_counter,
        );
    }
}

pub(crate) fn link_imports(fir: &mut FileIR, modules: &HashMap<String, FileIR>) {
    let imports: Vec<(String, String)> = fir
        .symbols
        .iter()
        .filter_map(|(alias, sym)| sym.alias_of.as_ref().map(|t| (alias.clone(), t.clone())))
        .collect();
    for (alias, target) in imports {
        if let Some(mod_fir) = modules.get(&target) {
            for (name, sym) in &mod_fir.symbols {
                if let Some(def) = sym.def {
                    let canonical = format!("{target}.{name}");
                    fir.symbols.insert(
                        canonical.clone(),
                        Symbol {
                            name: canonical.clone(),
                            sanitized: sym.sanitized,
                            def: Some(def),
                            alias_of: None,
                        },
                    );
                    let qualified = format!("{alias}.{name}");
                    fir.symbols.insert(
                        qualified.clone(),
                        Symbol {
                            name: qualified.clone(),
                            sanitized: sym.sanitized,
                            def: Some(def),
                            alias_of: Some(canonical.clone()),
                        },
                    );
                    let module_name = mod_fir
                        .symbol_modules
                        .get(name)
                        .cloned()
                        .unwrap_or_else(|| target.clone());
                    fir.symbol_modules
                        .insert(canonical.clone(), module_name.clone());
                    fir.symbol_modules.insert(qualified, module_name);
                }
            }
        } else if let Some((module, member)) = target.rsplit_once('.') {
            if let Some(mod_fir) = modules.get(module) {
                if let Some(sym) = mod_fir.symbols.get(member) {
                    if let Some(def) = sym.def {
                        fir.symbols.insert(
                            alias.clone(),
                            Symbol {
                                name: alias.clone(),
                                sanitized: sym.sanitized,
                                def: Some(def),
                                alias_of: Some(target.clone()),
                            },
                        );
                        fir.symbol_modules.insert(
                            alias.clone(),
                            mod_fir
                                .symbol_modules
                                .get(member)
                                .cloned()
                                .unwrap_or_else(|| module.to_string()),
                        );
                    }
                }
            }
        }
    }
    if let Some(dfg) = &mut fir.dfg {
        let nodes = dfg.nodes.clone();
        for node in nodes {
            if matches!(node.kind, DFNodeKind::Use) {
                let canonical = resolve_alias(&node.name, &fir.symbols);
                if let Some(def_id) = fir.symbols.get(&canonical).and_then(|s| s.def) {
                    if !dfg.edges.contains(&(def_id, node.id)) {
                        dfg.edges.push((def_id, node.id));
                    }
                }
            }
        }
    }
}
