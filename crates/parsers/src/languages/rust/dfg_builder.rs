use super::symbols::{mark_sanitized_aliases, mark_symbol_type};
use crate::catalog;
use ir::{DFNode, DFNodeKind, DataFlowGraph, FileIR, Symbol};
use std::collections::{HashMap, HashSet};

#[allow(clippy::too_many_arguments)]
pub(super) fn build_dfg(
    node: tree_sitter::Node,
    src: &str,
    fir: &mut FileIR,
    control: &mut Vec<usize>,
    current_fn: Option<usize>,
    fn_ids: &mut HashMap<String, usize>,
    fn_params: &mut HashMap<usize, Vec<usize>>,
    fn_returns: &mut HashMap<usize, Vec<usize>>,
    call_args: &mut Vec<(usize, usize, usize)>,
    branch_stack: &mut Vec<usize>,
    branch_counter: &mut usize,
) {
    fn func_name(func: tree_sitter::Node, src: &str) -> Option<String> {
        match func.kind() {
            "scoped_identifier" => func
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(src.as_bytes()).ok())
                .map(|s| s.to_string()),
            "field_expression" => func
                .child_by_field_name("field")
                .and_then(|n| n.utf8_text(src.as_bytes()).ok())
                .map(|s| s.to_string()),
            _ => func.utf8_text(src.as_bytes()).ok().map(|s| s.to_string()),
        }
    }

    fn expr_name(expr: tree_sitter::Node, src: &str) -> Option<String> {
        match expr.kind() {
            "identifier" => expr.utf8_text(src.as_bytes()).ok().map(|s| s.to_string()),
            "field_expression" => {
                let base = expr
                    .child_by_field_name("value")
                    .or_else(|| expr.child_by_field_name("argument"))
                    .or_else(|| expr.child(0))?;
                let field = expr.child_by_field_name("field")?;
                let base_name = expr_name(base, src)?;
                let field_name = field.utf8_text(src.as_bytes()).ok()?;
                Some(format!("{base_name}.{field_name}"))
            }
            "index_expression" => {
                let base = expr
                    .child_by_field_name("value")
                    .or_else(|| expr.child_by_field_name("collection"))
                    .or_else(|| expr.child(0))?;
                let index = expr
                    .child_by_field_name("index")
                    .or_else(|| expr.child(2))?;
                let base_name = expr_name(base, src)?;
                let index_text = index.utf8_text(src.as_bytes()).ok()?;
                Some(format!("{base_name}[{index_text}]"))
            }
            "call_expression" => {
                let func = expr.child_by_field_name("function")?;
                if func.kind() == "field_expression" {
                    let recv = func.child_by_field_name("value")?;
                    let method = func.child_by_field_name("field")?;
                    let recv_name = expr_name(recv, src)?;
                    let method_name = method.utf8_text(src.as_bytes()).ok()?;
                    match method_name {
                        "get" | "remove" => {
                            let args = expr.child_by_field_name("arguments")?;
                            let mut c = args.walk();
                            let arg = args.children(&mut c).find(|n| n.is_named())?;
                            let arg_text = arg.utf8_text(src.as_bytes()).ok()?;
                            Some(format!("{recv_name}[{arg_text}]"))
                        }
                        "pop" => {
                            let index = expr
                                .child_by_field_name("arguments")
                                .and_then(|args| {
                                    let mut c = args.walk();
                                    let arg = args.children(&mut c).find(|n| n.is_named());
                                    arg
                                })
                                .and_then(|n| n.utf8_text(src.as_bytes()).ok());
                            let idx = index
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| "0".to_string());
                            Some(format!("{recv_name}[{idx}]"))
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    let mut cursor = node.walk();
    match node.kind() {
        "function_item" => {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(fname) = name.utf8_text(src.as_bytes()) {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    dfg.nodes.push(DFNode {
                        id,
                        name: fname.to_string(),
                        kind: DFNodeKind::Def,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                    });
                    fn_ids.insert(fname.to_string(), id);
                    // track `unsafe fn` declarations
                    let mut uc = node.walk();
                    for child in node.children(&mut uc) {
                        if child.kind() == "unsafe" {
                            let uid = dfg.nodes.len();
                            dfg.nodes.push(DFNode {
                                id: uid,
                                name: "unsafe".to_string(),
                                kind: DFNodeKind::Use,
                                sanitized: false,
                                branch: branch_stack.last().copied(),
                            });
                            dfg.edges.push((id, uid));
                            break;
                        }
                    }
                    if let Some(params) = node.child_by_field_name("parameters") {
                        let mut pc = params.walk();
                        for param in params.children(&mut pc) {
                            if !param.is_named() {
                                continue;
                            }
                            let ident = param
                                .child_by_field_name("pattern")
                                .or_else(|| param.child_by_field_name("name"))
                                .or_else(|| param.child(0));
                            if let Some(ident) = ident {
                                if ident.kind() == "identifier" {
                                    if let Ok(pname) = ident.utf8_text(src.as_bytes()) {
                                        let pid = dfg.nodes.len();
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
                    if let Some(body) = node.child_by_field_name("body") {
                        build_dfg(
                            body,
                            src,
                            fir,
                            control,
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
        "if_expression" => {
            if let Some(cond) = node.child_by_field_name("condition") {
                build_dfg(
                    cond,
                    src,
                    fir,
                    control,
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
                name: "if".to_string(),
                kind: DFNodeKind::Branch,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            if let Some(&parent) = control.last() {
                dfg.edges.push((parent, id));
            }
            control.push(id);
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(cons) = node.child_by_field_name("consequence") {
                let bid = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(bid);
                build_dfg(
                    cons,
                    src,
                    fir,
                    control,
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
            if let Some(alt) = node.child_by_field_name("alternative") {
                let bid = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(bid);
                build_dfg(
                    alt,
                    src,
                    fir,
                    control,
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
            } else {
                branch_states.push(before.clone());
            }
            control.pop();
            let mut names = HashSet::new();
            for state in &branch_states {
                for name in state.keys() {
                    names.insert(name.clone());
                }
            }
            let mut merged = HashMap::new();
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
        "while_expression" => {
            if let Some(cond) = node.child_by_field_name("condition") {
                build_dfg(
                    cond,
                    src,
                    fir,
                    control,
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
                name: "while".to_string(),
                kind: DFNodeKind::Branch,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            if let Some(&parent) = control.last() {
                dfg.edges.push((parent, id));
            }
            control.push(id);
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let bid = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(bid);
                build_dfg(
                    body,
                    src,
                    fir,
                    control,
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
            control.pop();
            branch_states.push(before.clone());
            let mut names = HashSet::new();
            for state in &branch_states {
                for name in state.keys() {
                    names.insert(name.clone());
                }
            }
            let mut merged = HashMap::new();
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
        "for_expression" => {
            if let Some(iter) = node.child_by_field_name("value") {
                build_dfg(
                    iter,
                    src,
                    fir,
                    control,
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
                name: "for".to_string(),
                kind: DFNodeKind::Branch,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            if let Some(&parent) = control.last() {
                dfg.edges.push((parent, id));
            }
            control.push(id);
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let bid = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(bid);
                if let Some(pat) = node.child_by_field_name("pattern") {
                    if pat.kind() == "identifier" {
                        if let Ok(name) = pat.utf8_text(src.as_bytes()) {
                            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                            let pid = dfg.nodes.len();
                            dfg.nodes.push(DFNode {
                                id: pid,
                                name: name.to_string(),
                                kind: DFNodeKind::Def,
                                sanitized: false,
                                branch: branch_stack.last().copied(),
                            });
                            fir.symbols.insert(
                                name.to_string(),
                                Symbol {
                                    name: name.to_string(),
                                    sanitized: false,
                                    def: Some(pid),
                                    alias_of: None,
                                },
                            );
                        }
                    } else {
                        build_dfg(
                            pat,
                            src,
                            fir,
                            control,
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
                build_dfg(
                    body,
                    src,
                    fir,
                    control,
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
            control.pop();
            branch_states.push(before.clone());
            let mut names = HashSet::new();
            for state in &branch_states {
                for name in state.keys() {
                    names.insert(name.clone());
                }
            }
            let mut merged = HashMap::new();
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
        "loop_expression" => {
            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
            let id = dfg.nodes.len();
            dfg.nodes.push(DFNode {
                id,
                name: "loop".to_string(),
                kind: DFNodeKind::Branch,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            if let Some(&parent) = control.last() {
                dfg.edges.push((parent, id));
            }
            control.push(id);
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let bid = *branch_counter;
                *branch_counter += 1;
                fir.symbols = before.clone();
                branch_stack.push(bid);
                build_dfg(
                    body,
                    src,
                    fir,
                    control,
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
            control.pop();
            branch_states.push(before.clone());
            let mut names = HashSet::new();
            for state in &branch_states {
                for name in state.keys() {
                    names.insert(name.clone());
                }
            }
            let mut merged = HashMap::new();
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
        "match_expression" => {
            if let Some(val) = node.child_by_field_name("value") {
                build_dfg(
                    val,
                    src,
                    fir,
                    control,
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
            if let Some(&parent) = control.last() {
                dfg.edges.push((parent, id));
            }
            control.push(id);
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(body) = node.child_by_field_name("body") {
                let mut bc = body.walk();
                for arm in body.children(&mut bc) {
                    if !arm.is_named() {
                        continue;
                    }
                    let bid = *branch_counter;
                    *branch_counter += 1;
                    fir.symbols = before.clone();
                    branch_stack.push(bid);
                    build_dfg(
                        arm,
                        src,
                        fir,
                        control,
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
            control.pop();
            if branch_states.is_empty() {
                branch_states.push(before.clone());
            }
            let mut names = HashSet::new();
            for state in &branch_states {
                for name in state.keys() {
                    names.insert(name.clone());
                }
            }
            let mut merged = HashMap::new();
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
        "let_declaration" => {
            if let Some(pat) = node.child_by_field_name("pattern") {
                if pat.kind() == "identifier" {
                    if let Ok(name) = pat.utf8_text(src.as_bytes()) {
                        let mut kind = DFNodeKind::Def;
                        let mut alias_of = None;
                        if let Some(init) = node.child_by_field_name("value") {
                            if init.kind() == "identifier" {
                                if let Ok(rhs) = init.utf8_text(src.as_bytes()) {
                                    kind = DFNodeKind::Assign;
                                    alias_of = Some(rhs.to_string());
                                }
                            } else if init.kind() == "call_expression" {
                                if let Some(func) = init.child_by_field_name("function") {
                                    if let Some(fname) = func_name(func, src) {
                                        mark_symbol_type(fir, &fname);
                                        if catalog::is_sanitizer("rust", &fname) {
                                            fir.symbols
                                                .entry(name.to_string())
                                                .or_insert_with(|| Symbol {
                                                    name: name.to_string(),
                                                    ..Default::default()
                                                })
                                                .sanitized = true;
                                        }
                                        if fname == "Ok" || fname == "Err" {
                                            if let Some(args) =
                                                init.child_by_field_name("arguments")
                                            {
                                                let mut c = args.walk();
                                                let arg_opt =
                                                    args.children(&mut c).find(|n| n.is_named());
                                                if let Some(arg) = arg_opt {
                                                    let rhs = if arg.kind() == "identifier" {
                                                        arg.utf8_text(src.as_bytes())
                                                            .ok()
                                                            .map(|s| s.to_string())
                                                    } else if arg.kind() == "field_expression"
                                                        || arg.kind() == "index_expression"
                                                    {
                                                        expr_name(arg, src)
                                                    } else {
                                                        None
                                                    };
                                                    if let Some(rhs) = rhs {
                                                        kind = DFNodeKind::Assign;
                                                        alias_of = Some(rhs);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if init.kind() == "macro_invocation" {
                                if let Some(mac) = init.child_by_field_name("macro") {
                                    if let Ok(fname) = mac.utf8_text(src.as_bytes()) {
                                        mark_symbol_type(fir, fname);
                                        if catalog::is_sanitizer("rust", fname) {
                                            fir.symbols
                                                .entry(name.to_string())
                                                .or_insert_with(|| Symbol {
                                                    name: name.to_string(),
                                                    ..Default::default()
                                                })
                                                .sanitized = true;
                                        }
                                    }
                                }
                                if let Some(tt) = init.named_child(1) {
                                    let mut stack = vec![tt];
                                    while let Some(tt_node) = stack.pop() {
                                        let mut c = tt_node.walk();
                                        for child in tt_node.children(&mut c) {
                                            if !child.is_named() {
                                                continue;
                                            }
                                            if child.kind() == "identifier" {
                                                if let Ok(rhs) = child.utf8_text(src.as_bytes()) {
                                                    kind = DFNodeKind::Assign;
                                                    alias_of = Some(rhs.to_string());
                                                    stack.clear();
                                                    break;
                                                }
                                            } else {
                                                stack.push(child);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        let id = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id,
                            name: name.to_string(),
                            kind: kind.clone(),
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        });
                        if let Some(init) = node.child_by_field_name("value") {
                            if init.kind() == "identifier" {
                                if let Ok(rhs) = init.utf8_text(src.as_bytes()) {
                                    if let Some(sym) = fir.symbols.get(rhs).and_then(|s| s.def) {
                                        dfg.edges.push((sym, id));
                                    }
                                }
                            } else if init.kind() == "field_expression"
                                || init.kind() == "index_expression"
                            {
                                if let Some(rhs) = expr_name(init, src) {
                                    if let Some(sym) = fir.symbols.get(&rhs).and_then(|s| s.def) {
                                        dfg.edges.push((sym, id));
                                    }
                                }
                            } else if init.kind() == "call_expression" {
                                if let Some(func) = init.child_by_field_name("function") {
                                    if let Some(fname) = func_name(func, src) {
                                        if let Some(&callee_id) = fn_ids.get(&fname) {
                                            if let Some(caller) = current_fn {
                                                dfg.calls.push((caller, callee_id));
                                            }
                                            dfg.call_returns.push((id, callee_id));
                                            if let Some(args) =
                                                init.child_by_field_name("arguments")
                                            {
                                                let mut c = args.walk();
                                                let mut idx = 0;
                                                for arg in args.children(&mut c) {
                                                    if !arg.is_named() {
                                                        continue;
                                                    }
                                                    if arg.kind() == "identifier" {
                                                        if let Ok(rhs) =
                                                            arg.utf8_text(src.as_bytes())
                                                        {
                                                            if let Some(sym) = fir
                                                                .symbols
                                                                .get(rhs)
                                                                .and_then(|s| s.def)
                                                            {
                                                                call_args
                                                                    .push((sym, callee_id, idx));
                                                            }
                                                            if fname == "Ok" || fname == "Err" {
                                                                if let Some(sym) = fir
                                                                    .symbols
                                                                    .get(rhs)
                                                                    .and_then(|s| s.def)
                                                                {
                                                                    dfg.edges.push((sym, id));
                                                                }
                                                            }
                                                        }
                                                    } else if arg.kind() == "field_expression"
                                                        || arg.kind() == "index_expression"
                                                    {
                                                        if let Some(rhs) = expr_name(arg, src) {
                                                            if let Some(sym) = fir
                                                                .symbols
                                                                .get(&rhs)
                                                                .and_then(|s| s.def)
                                                            {
                                                                call_args
                                                                    .push((sym, callee_id, idx));
                                                                if fname == "Ok" || fname == "Err" {
                                                                    dfg.edges.push((sym, id));
                                                                }
                                                            }
                                                        }
                                                    }
                                                    idx += 1;
                                                }
                                            }
                                        }
                                        if fname == "Ok" || fname == "Err" {
                                            if let Some(args) =
                                                init.child_by_field_name("arguments")
                                            {
                                                let mut c = args.walk();
                                                let arg_opt =
                                                    args.children(&mut c).find(|n| n.is_named());
                                                if let Some(arg) = arg_opt {
                                                    let rhs = if arg.kind() == "identifier" {
                                                        arg.utf8_text(src.as_bytes())
                                                            .ok()
                                                            .map(|s| s.to_string())
                                                    } else if arg.kind() == "field_expression"
                                                        || arg.kind() == "index_expression"
                                                    {
                                                        expr_name(arg, src)
                                                    } else {
                                                        None
                                                    };
                                                    if let Some(rhs) = rhs {
                                                        if let Some(sym) = fir
                                                            .symbols
                                                            .get(&rhs)
                                                            .and_then(|s| s.def)
                                                        {
                                                            dfg.edges.push((sym, id));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            } else if init.kind() == "macro_invocation" {
                                if let Some(tt) = init.named_child(1) {
                                    let mut stack = vec![tt];
                                    while let Some(tt_node) = stack.pop() {
                                        let mut c = tt_node.walk();
                                        for child in tt_node.children(&mut c) {
                                            if !child.is_named() {
                                                continue;
                                            }
                                            if child.kind() == "identifier" {
                                                if let Ok(var) = child.utf8_text(src.as_bytes()) {
                                                    if let Some(sym) =
                                                        fir.symbols.get(var).and_then(|s| s.def)
                                                    {
                                                        dfg.edges.push((sym, id));
                                                    }
                                                }
                                            } else {
                                                stack.push(child);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        if let Some(&ctrl) = control.last() {
                            dfg.edges.push((ctrl, id));
                        }
                        let was_sanitized = fir.symbols.get(name).is_some_and(|s| s.sanitized);
                        fir.symbols.insert(
                            name.to_string(),
                            Symbol {
                                name: name.to_string(),
                                sanitized: was_sanitized,
                                def: Some(id),
                                alias_of,
                            },
                        );
                        if was_sanitized {
                            mark_sanitized_aliases(fir, name);
                        }
                    }
                }
            }
        }
        "assignment_expression"
        | "compound_assignment_expr"
        | "augmented_assignment_expression" => {
            if let Some(left) = node.child_by_field_name("left") {
                if let Some(name) = match left.kind() {
                    "identifier" => left.utf8_text(src.as_bytes()).ok().map(|s| s.to_string()),
                    "field_expression" | "index_expression" => expr_name(left, src),
                    _ => None,
                } {
                    let id = {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        let id = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id,
                            name: name.clone(),
                            kind: DFNodeKind::Assign,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        });
                        if let Some(sym) = fir.symbols.get(&name).and_then(|s| s.def) {
                            dfg.edges.push((sym, id));
                        }
                        if let Some(&ctrl) = control.last() {
                            dfg.edges.push((ctrl, id));
                        }
                        id
                    };
                    if let Some(right) = node.child_by_field_name("right") {
                        match right.kind() {
                            "identifier" => {
                                if let Ok(rhs) = right.utf8_text(src.as_bytes()) {
                                    if let Some(sym) = fir.symbols.get(rhs).and_then(|s| s.def) {
                                        if let Some(dfg) = &mut fir.dfg {
                                            dfg.edges.push((sym, id));
                                        }
                                    }
                                }
                            }
                            "field_expression" | "index_expression" => {
                                if let Some(rhs) = expr_name(right, src) {
                                    if let Some(sym) = fir.symbols.get(&rhs).and_then(|s| s.def) {
                                        if let Some(dfg) = &mut fir.dfg {
                                            dfg.edges.push((sym, id));
                                        }
                                    }
                                }
                            }
                            "call_expression" => {
                                if let Some(func) = right.child_by_field_name("function") {
                                    if let Some(fname) = func_name(func, src) {
                                        mark_symbol_type(fir, &fname);
                                        if let Some(&callee_id) = fn_ids.get(&fname) {
                                            if let Some(caller) = current_fn {
                                                fir.dfg
                                                    .get_or_insert_with(DataFlowGraph::default)
                                                    .calls
                                                    .push((caller, callee_id));
                                            }
                                            fir.dfg
                                                .get_or_insert_with(DataFlowGraph::default)
                                                .call_returns
                                                .push((id, callee_id));
                                            if let Some(args) =
                                                right.child_by_field_name("arguments")
                                            {
                                                let mut c = args.walk();
                                                let mut idx = 0;
                                                for arg in args.children(&mut c) {
                                                    if !arg.is_named() {
                                                        continue;
                                                    }
                                                    if let Some(var) = expr_name(arg, src) {
                                                        if let Some(sym) = fir
                                                            .symbols
                                                            .get(&var)
                                                            .and_then(|s| s.def)
                                                        {
                                                            call_args.push((sym, callee_id, idx));
                                                            if let Some(dfg) = &mut fir.dfg {
                                                                dfg.edges.push((sym, id));
                                                            }
                                                        }
                                                    }
                                                    idx += 1;
                                                }
                                            }
                                        } else if let Some(args) =
                                            right.child_by_field_name("arguments")
                                        {
                                            let mut c = args.walk();
                                            for arg in args.children(&mut c) {
                                                if !arg.is_named() {
                                                    continue;
                                                }
                                                if let Some(var) = expr_name(arg, src) {
                                                    if let Some(sym) =
                                                        fir.symbols.get(&var).and_then(|s| s.def)
                                                    {
                                                        if let Some(dfg) = &mut fir.dfg {
                                                            dfg.edges.push((sym, id));
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        if catalog::is_sanitizer("rust", &fname) {
                                            fir.symbols
                                                .entry(name.clone())
                                                .or_insert_with(|| Symbol {
                                                    name: name.clone(),
                                                    ..Default::default()
                                                })
                                                .sanitized = true;
                                        }
                                    }
                                    if func.kind() == "field_expression" {
                                        if let Some(method) = func
                                            .child_by_field_name("field")
                                            .and_then(|f| f.utf8_text(src.as_bytes()).ok())
                                        {
                                            if matches!(method, "pop" | "get" | "unwrap") {
                                                if let Some(recv) =
                                                    func.child_by_field_name("value")
                                                {
                                                    if let Some(recv_name) = expr_name(recv, src) {
                                                        if let Some(src_id) = fir
                                                            .symbols
                                                            .get(&recv_name)
                                                            .and_then(|s| s.def)
                                                        {
                                                            if let Some(dfg) = &mut fir.dfg {
                                                                dfg.edges.push((src_id, id));
                                                            }
                                                        }
                                                    }
                                                }
                                            } else if matches!(method, "push" | "insert") {
                                                if let Some(recv) =
                                                    func.child_by_field_name("value")
                                                {
                                                    if let Some(recv_name) = expr_name(recv, src) {
                                                        if let Some(args) =
                                                            right.child_by_field_name("arguments")
                                                        {
                                                            let mut c = args.walk();
                                                            let mut idx = 0;
                                                            for arg in args.children(&mut c) {
                                                                if !arg.is_named() {
                                                                    continue;
                                                                }
                                                                let needed = match method {
                                                                    "push" => 0,
                                                                    "insert" => 1,
                                                                    _ => usize::MAX,
                                                                };
                                                                if idx == needed {
                                                                    if let Some(arg_name) =
                                                                        expr_name(arg, src)
                                                                    {
                                                                        if let (
                                                                            Some(src_id),
                                                                            Some(dst_id),
                                                                        ) = (
                                                                            fir.symbols
                                                                                .get(&arg_name)
                                                                                .and_then(|s| {
                                                                                    s.def
                                                                                }),
                                                                            fir.symbols
                                                                                .get(&recv_name)
                                                                                .and_then(|s| {
                                                                                    s.def
                                                                                }),
                                                                        ) {
                                                                            if let Some(dfg) =
                                                                                &mut fir.dfg
                                                                            {
                                                                                dfg.edges.push((
                                                                                    src_id, dst_id,
                                                                                ));
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                                idx += 1;
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
                    }
                    let was_sanitized = fir.symbols.get(&name).is_some_and(|s| s.sanitized);
                    fir.symbols.insert(
                        name.clone(),
                        Symbol {
                            name: name.clone(),
                            sanitized: was_sanitized,
                            def: Some(id),
                            alias_of: None,
                        },
                    );
                    if was_sanitized {
                        mark_sanitized_aliases(fir, &name);
                    }
                }
            }
        }
        "call_expression" => {
            if let Some(func) = node.child_by_field_name("function") {
                if let Some(fname) = func_name(func, src) {
                    mark_symbol_type(fir, &fname);
                    let callee_id = fn_ids.get(&fname).copied();
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let mut c = args.walk();
                        let mut idx = 0;
                        for arg in args.children(&mut c) {
                            if !arg.is_named() {
                                continue;
                            }
                            if let Some(var) = expr_name(arg, src) {
                                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                let id = dfg.nodes.len();
                                dfg.nodes.push(DFNode {
                                    id,
                                    name: var.clone(),
                                    kind: DFNodeKind::Use,
                                    sanitized: false,
                                    branch: branch_stack.last().copied(),
                                });
                                if let Some(sym) = fir.symbols.get(&var).and_then(|s| s.def) {
                                    dfg.edges.push((sym, id));
                                    if let Some(callee) = callee_id {
                                        call_args.push((sym, callee, idx));
                                    }
                                }
                                if arg.kind() == "identifier"
                                    && catalog::is_sanitizer("rust", &fname)
                                {
                                    fir.symbols
                                        .entry(var.clone())
                                        .or_insert_with(|| Symbol {
                                            name: var.clone(),
                                            ..Default::default()
                                        })
                                        .sanitized = true;
                                    mark_sanitized_aliases(fir, &var);
                                }
                            }
                            idx += 1;
                        }
                    }
                    if let Some(callee) = callee_id {
                        if let Some(caller) = current_fn {
                            fir.dfg
                                .get_or_insert_with(DataFlowGraph::default)
                                .calls
                                .push((caller, callee));
                        }
                    }
                    if func.kind() == "field_expression" {
                        if let Some(method) = func
                            .child_by_field_name("field")
                            .and_then(|f| f.utf8_text(src.as_bytes()).ok())
                        {
                            if matches!(method, "push" | "insert") {
                                if let Some(recv) = func.child_by_field_name("value") {
                                    if let Some(recv_name) = expr_name(recv, src) {
                                        if let Some(args) = node.child_by_field_name("arguments") {
                                            let mut c = args.walk();
                                            let mut idx = 0;
                                            for arg in args.children(&mut c) {
                                                if !arg.is_named() {
                                                    continue;
                                                }
                                                let needed = match method {
                                                    "push" => 0,
                                                    "insert" => 1,
                                                    _ => usize::MAX,
                                                };
                                                if idx == needed {
                                                    if let Some(arg_name) = expr_name(arg, src) {
                                                        if let (Some(src_id), Some(dst_id)) = (
                                                            fir.symbols
                                                                .get(&arg_name)
                                                                .and_then(|s| s.def),
                                                            fir.symbols
                                                                .get(&recv_name)
                                                                .and_then(|s| s.def),
                                                        ) {
                                                            fir.dfg
                                                                .get_or_insert_with(
                                                                    DataFlowGraph::default,
                                                                )
                                                                .edges
                                                                .push((src_id, dst_id));
                                                        }
                                                    }
                                                }
                                                idx += 1;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return;
        }
        "macro_invocation" => {
            if let Some(mac) = node.child_by_field_name("macro") {
                if let Ok(fname) = mac.utf8_text(src.as_bytes()) {
                    mark_symbol_type(fir, fname);
                    if let Some(tt) = node.named_child(1) {
                        let mut stack = vec![tt];
                        while let Some(tt_node) = stack.pop() {
                            let mut c = tt_node.walk();
                            for child in tt_node.children(&mut c) {
                                if !child.is_named() {
                                    continue;
                                }
                                if child.kind() == "identifier" {
                                    if let Ok(var) = child.utf8_text(src.as_bytes()) {
                                        let dfg =
                                            fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                        let id = dfg.nodes.len();
                                        dfg.nodes.push(DFNode {
                                            id,
                                            name: var.to_string(),
                                            kind: DFNodeKind::Use,
                                            sanitized: false,
                                            branch: branch_stack.last().copied(),
                                        });
                                        if let Some(sym) = fir.symbols.get(var).and_then(|s| s.def)
                                        {
                                            dfg.edges.push((sym, id));
                                            if catalog::is_sanitizer("rust", fname) {
                                                fir.symbols
                                                    .entry(var.to_string())
                                                    .or_insert_with(|| Symbol {
                                                        name: var.to_string(),
                                                        ..Default::default()
                                                    })
                                                    .sanitized = true;
                                                mark_sanitized_aliases(fir, var);
                                            }
                                        }
                                    }
                                } else {
                                    stack.push(child);
                                }
                            }
                        }
                    }
                }
            }
            return;
        }
        "unsafe_block" => {
            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
            let id = dfg.nodes.len();
            dfg.nodes.push(DFNode {
                id,
                name: "unsafe".to_string(),
                kind: DFNodeKind::Use,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            if let Some(&parent) = control.last() {
                dfg.edges.push((parent, id));
            }
            control.push(id);
            let mut c = node.walk();
            for child in node.children(&mut c) {
                if child.kind() != "unsafe" {
                    build_dfg(
                        child,
                        src,
                        fir,
                        control,
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
            control.pop();
            return;
        }
        "unsafe" => {
            if node.parent().map(|p| p.kind()) != Some("unsafe_block") {
                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                let id = dfg.nodes.len();
                dfg.nodes.push(DFNode {
                    id,
                    name: "unsafe".to_string(),
                    kind: DFNodeKind::Use,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                });
                if let Some(&parent) = control.last() {
                    dfg.edges.push((parent, id));
                }
            }
        }
        "try_expression" => {
            if let Some(expr) = node.named_child(0) {
                if expr.kind() == "identifier" {
                    if let Ok(name) = expr.utf8_text(src.as_bytes()) {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        let id = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id,
                            name: name.to_string(),
                            kind: DFNodeKind::Return,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        });
                        if let Some(sym) = fir.symbols.get(name).and_then(|s| s.def) {
                            dfg.edges.push((sym, id));
                        }
                        if let Some(&ctrl) = control.last() {
                            dfg.edges.push((ctrl, id));
                        }
                        if let Some(fid) = current_fn {
                            fn_returns.entry(fid).or_default().push(id);
                        }
                    }
                } else {
                    build_dfg(
                        expr,
                        src,
                        fir,
                        control,
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
            return;
        }
        "return_expression" => {
            if let Some(expr) = node.named_child(0) {
                if expr.kind() == "identifier" {
                    if let Ok(name) = expr.utf8_text(src.as_bytes()) {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        let id = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id,
                            name: name.to_string(),
                            kind: DFNodeKind::Return,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        });
                        if let Some(sym) = fir.symbols.get(name).and_then(|s| s.def) {
                            dfg.edges.push((sym, id));
                        }
                        if let Some(&ctrl) = control.last() {
                            dfg.edges.push((ctrl, id));
                        }
                        if let Some(fid) = current_fn {
                            fn_returns.entry(fid).or_default().push(id);
                        }
                    }
                } else if expr.kind() == "call_expression" {
                    if let Some(func) = expr.child_by_field_name("function") {
                        if let Some(fname) = func_name(func, src) {
                            if fname == "Ok" || fname == "Err" {
                                if let Some(args) = expr.child_by_field_name("arguments") {
                                    let mut c = args.walk();
                                    let arg_opt = args.children(&mut c).find(|n| n.is_named());
                                    if let Some(arg) = arg_opt {
                                        let rhs = if arg.kind() == "identifier" {
                                            arg.utf8_text(src.as_bytes())
                                                .ok()
                                                .map(|s| s.to_string())
                                        } else if arg.kind() == "field_expression"
                                            || arg.kind() == "index_expression"
                                        {
                                            expr_name(arg, src)
                                        } else {
                                            None
                                        };
                                        if let Some(rhs) = rhs {
                                            let dfg =
                                                fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                            let id = dfg.nodes.len();
                                            dfg.nodes.push(DFNode {
                                                id,
                                                name: rhs.to_string(),
                                                kind: DFNodeKind::Return,
                                                sanitized: false,
                                                branch: branch_stack.last().copied(),
                                            });
                                            if let Some(sym) =
                                                fir.symbols.get(&rhs).and_then(|s| s.def)
                                            {
                                                dfg.edges.push((sym, id));
                                            }
                                            if let Some(&ctrl) = control.last() {
                                                dfg.edges.push((ctrl, id));
                                            }
                                            if let Some(fid) = current_fn {
                                                fn_returns.entry(fid).or_default().push(id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if expr.kind() == "macro_invocation" {
                    if let Some(tt) = expr.named_child(1) {
                        let mut stack = vec![tt];
                        while let Some(tt_node) = stack.pop() {
                            let mut c = tt_node.walk();
                            for child in tt_node.children(&mut c) {
                                if !child.is_named() {
                                    continue;
                                }
                                if child.kind() == "identifier" {
                                    if let Ok(var) = child.utf8_text(src.as_bytes()) {
                                        let dfg =
                                            fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                        let id = dfg.nodes.len();
                                        dfg.nodes.push(DFNode {
                                            id,
                                            name: var.to_string(),
                                            kind: DFNodeKind::Return,
                                            sanitized: false,
                                            branch: branch_stack.last().copied(),
                                        });
                                        if let Some(sym) = fir.symbols.get(var).and_then(|s| s.def)
                                        {
                                            dfg.edges.push((sym, id));
                                        }
                                        if let Some(&ctrl) = control.last() {
                                            dfg.edges.push((ctrl, id));
                                        }
                                        if let Some(fid) = current_fn {
                                            fn_returns.entry(fid).or_default().push(id);
                                        }
                                        return;
                                    }
                                } else {
                                    stack.push(child);
                                }
                            }
                        }
                    }
                }
            }
        }
        "identifier" => {
            if let Ok(name) = node.utf8_text(src.as_bytes()) {
                let mut skip = false;
                if let Some(parent) = node.parent() {
                    let pk = parent.kind();
                    let is_left = (pk == "assignment_expression"
                        || pk == "compound_assignment_expr"
                        || pk == "augmented_assignment_expression")
                        && parent
                            .child_by_field_name("left")
                            .map(|n| n.byte_range() == node.byte_range())
                            .unwrap_or(false);
                    skip = pk == "let_declaration" || pk == "return_expression" || is_left;
                }
                if !skip {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    dfg.nodes.push(DFNode {
                        id,
                        name: name.to_string(),
                        kind: DFNodeKind::Use,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                    });
                    if let Some(sym) = fir.symbols.get(name) {
                        if let Some(def_id) = sym.def {
                            dfg.edges.push((def_id, id));
                        }
                    }
                }
            }
        }
        "field_expression" | "index_expression" => {
            if let Some(name) = expr_name(node, src) {
                let mut skip = false;
                if let Some(parent) = node.parent() {
                    let pk = parent.kind();
                    let is_left = (pk == "assignment_expression"
                        || pk == "compound_assignment_expr"
                        || pk == "augmented_assignment_expression")
                        && parent
                            .child_by_field_name("left")
                            .map(|n| n.byte_range() == node.byte_range())
                            .unwrap_or(false);
                    skip = pk == "return_expression" || is_left;
                }
                if !skip {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    dfg.nodes.push(DFNode {
                        id,
                        name: name.clone(),
                        kind: DFNodeKind::Use,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                    });
                    if let Some(sym) = fir.symbols.get(&name).and_then(|s| s.def) {
                        dfg.edges.push((sym, id));
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
            control,
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
