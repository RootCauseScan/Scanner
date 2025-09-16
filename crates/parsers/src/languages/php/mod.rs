use crate::ParserMetrics;
use anyhow::{anyhow, Context, Result};
use ir::{
    AstNode, DFNode, DFNodeKind, DataFlowGraph, FileAst, FileIR, IRNode, Meta, Symbol, SymbolKind,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use tracing::debug;

#[cfg(test)]
mod tests;

const SANITIZERS: &[&str] = &[
    "htmlspecialchars",
    "htmlentities",
    "mysqli_real_escape_string",
    "strip_tags",
    "sanitize",
];

const SUPERGLOBALS: &[&str] = &[
    "_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_ENV", "_FILES", "_SESSION", "GLOBALS",
];

// Parser pool to avoid concurrency issues with tree-sitter
static PARSER_POOL: Mutex<Vec<tree_sitter::Parser>> = Mutex::new(Vec::new());

fn get_parser() -> tree_sitter::Parser {
    let mut pool = PARSER_POOL.lock().expect("parser pool lock poisoned");
    if let Some(mut parser) = pool.pop() {
        // Reset parser for reuse
        parser.reset();
        parser
    } else {
        // Create new parser if none are available
        tree_sitter::Parser::new()
    }
}

fn return_parser(mut parser: tree_sitter::Parser) {
    let mut pool = PARSER_POOL.lock().expect("parser pool lock poisoned");
    if pool.len() < 10 {
        // Limit the pool size
        parser.reset();
        pool.push(parser);
    }
}

pub fn parse_php(content: &str, fir: &mut FileIR) -> Result<()> {
    fn to_camel(kind: &str) -> String {
        let mut out = String::new();
        let mut up = true;
        for ch in kind.chars() {
            if ch == '_' {
                up = true;
            } else if up {
                out.push(ch.to_ascii_uppercase());
                up = false;
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn resolve_alias<'a>(
        mut name: &'a str,
        symbols: &'a std::collections::HashMap<String, Symbol>,
    ) -> String {
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

    fn is_sanitizer(name: &str, fir: &FileIR) -> bool {
        SANITIZERS.contains(&name)
            || matches!(fir.symbol_types.get(name), Some(SymbolKind::Sanitizer))
    }

    #[allow(clippy::single_match)]
    fn process_sanitization(node: tree_sitter::Node, src: &str, fir: &mut FileIR) {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "echo_statement" | "print_expression" => {
                    let mut cursor2 = child.walk();
                    for grandchild in child.children(&mut cursor2) {
                        if grandchild.kind() == "function_call_expression" {
                            if let Some(name_node) = grandchild
                                .child_by_field_name("name")
                                .or_else(|| grandchild.child_by_field_name("function"))
                            {
                                if let Ok(fname) = name_node.utf8_text(src.as_bytes()) {
                                    if is_sanitizer(fname, fir) {
                                        mark_sanitized_vars(grandchild, src, fir);
                                    }
                                }
                            }
                        }
                    }
                }
                "function_call_expression" => {
                    if let Some(name_node) = child
                        .child_by_field_name("name")
                        .or_else(|| child.child_by_field_name("function"))
                    {
                        if let Ok(fname) = name_node.utf8_text(src.as_bytes()) {
                            if fname == "printf" || fname == "sprintf" {
                                if let Some(args) = child.child_by_field_name("arguments") {
                                    let mut ac = args.walk();
                                    for arg in args.named_children(&mut ac) {
                                        if arg.kind() == "function_call_expression" {
                                            if let Some(anode) = arg
                                                .child_by_field_name("name")
                                                .or_else(|| arg.child_by_field_name("function"))
                                            {
                                                if let Ok(aname) = anode.utf8_text(src.as_bytes()) {
                                                    if is_sanitizer(aname, fir) {
                                                        mark_sanitized_vars(arg, src, fir);
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
            process_sanitization(child, src, fir);
        }
    }

    fn collect_vars(node: tree_sitter::Node, src: &str, out: &mut Vec<String>) {
        match node.kind() {
            "variable_name" => {
                if let Ok(t) = node.utf8_text(src.as_bytes()) {
                    out.push(t.trim_start_matches('$').to_string());
                }
            }
            "member_access_expression" => {
                let base = node.child_by_field_name("object").or_else(|| node.child(0));
                let field = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("property"))
                    .or_else(|| node.child(1));
                if let (Some(b), Some(f)) = (base, field) {
                    let mut bases = Vec::new();
                    collect_vars(b, src, &mut bases);
                    if let Ok(fname) = f.utf8_text(src.as_bytes()) {
                        for bv in bases {
                            out.push(format!("{bv}.{fname}"));
                        }
                    }
                }
            }
            "subscript_expression" => {
                let base = node.child_by_field_name("value").or_else(|| node.child(0));
                let index = node.child_by_field_name("index").or_else(|| node.child(1));
                if let Some(b) = base {
                    let mut bases = Vec::new();
                    collect_vars(b, src, &mut bases);
                    if let Some(i) = index {
                        if let Ok(itxt) = i.utf8_text(src.as_bytes()) {
                            for bv in bases.clone() {
                                if SUPERGLOBALS.contains(&bv.as_str()) {
                                    out.push(bv.clone());
                                } else {
                                    out.push(format!("{bv}[{itxt}]"));
                                    out.push(bv.clone());
                                }
                            }
                        }
                        collect_vars(i, src, out);
                    } else {
                        for bv in bases {
                            out.push(bv);
                        }
                    }
                }
            }
            _ => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    collect_vars(child, src, out);
                }
            }
        }
    }

    fn mark_sanitized_vars(node: tree_sitter::Node, src: &str, fir: &mut FileIR) {
        let mut vars = Vec::new();
        collect_vars(node, src, &mut vars);
        for v in vars {
            let canonical = resolve_alias(&v, &fir.symbols);
            let sym = fir
                .symbols
                .entry(canonical.clone())
                .or_insert_with(|| Symbol {
                    name: canonical.clone(),
                    ..Default::default()
                });
            sym.sanitized = true;
            if let Some(dfg) = &mut fir.dfg {
                for node in &mut dfg.nodes {
                    if resolve_alias(&node.name, &fir.symbols) == canonical {
                        node.sanitized = true;
                    }
                }
            }
            let keys: Vec<String> = fir.symbols.keys().cloned().collect();
            for name in keys {
                if resolve_alias(&name, &fir.symbols) == canonical {
                    if let Some(s) = fir.symbols.get_mut(&name) {
                        s.sanitized = true;
                    }
                }
            }
        }
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
    fn build_ir(
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
        if node.kind() == "if_statement" {
            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
            let bid = dfg.nodes.len();
            dfg.nodes.push(DFNode {
                id: bid,
                name: "if".into(),
                kind: DFNodeKind::Branch,
                sanitized: false,
                branch: branch_stack.last().copied(),
            });
            if let Some(cond) = node.child_by_field_name("condition") {
                build_ir(
                    cond,
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
            let before = fir.symbols.clone();
            let mut branch_states: Vec<HashMap<String, Symbol>> = Vec::new();
            if let Some(cons) = node.child_by_field_name("consequence") {
                let id = *branch_counter;
                *branch_counter += 1;
                branch_stack.push(id);
                fir.symbols = before.clone();
                build_ir(
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
                if matches!(child.kind(), "else_clause" | "else_if_clause") {
                    alt_found = true;
                    let id = *branch_counter;
                    *branch_counter += 1;
                    branch_stack.push(id);
                    fir.symbols = before.clone();
                    build_ir(
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
        if node.kind() == "while_statement" {
            {
                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                let nid = dfg.nodes.len();
                dfg.nodes.push(DFNode {
                    id: nid,
                    name: "while".into(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                });
            }
            if let Some(cond) = node.child_by_field_name("condition") {
                let mut vars = Vec::new();
                collect_vars(cond, src, &mut vars);
                for v in vars {
                    let canonical = resolve_alias(&v, &fir.symbols);
                    let sanitized = fir
                        .symbols
                        .get(&canonical)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        let id = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id,
                            name: v.clone(),
                            kind: DFNodeKind::Use,
                            sanitized,
                            branch: branch_stack.last().copied(),
                        });
                        if let Some(def) = fir.symbols.get(&canonical).and_then(|s| s.def) {
                            dfg.edges.push((def, id));
                        }
                    }
                    fir.symbols.entry(v.clone()).or_insert_with(|| Symbol {
                        name: v.clone(),
                        ..Default::default()
                    });
                }
            }
            let before = fir.symbols.clone();
            let bid = *branch_counter;
            *branch_counter += 1;
            branch_stack.push(bid);
            if let Some(body) = node
                .child_by_field_name("body")
                .or_else(|| node.child_by_field_name("statement"))
            {
                build_ir(
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
        if node.kind() == "for_statement" {
            let _nid = {
                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                let nid = dfg.nodes.len();
                dfg.nodes.push(DFNode {
                    id: nid,
                    name: "for".into(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                });
                nid
            };
            if let Some(init) = node.child_by_field_name("initializer") {
                build_ir(
                    init,
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
            if let Some(cond) = node.child_by_field_name("condition") {
                let mut vars = Vec::new();
                collect_vars(cond, src, &mut vars);
                for v in vars {
                    let canonical = resolve_alias(&v, &fir.symbols);
                    let sanitized = fir
                        .symbols
                        .get(&canonical)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    dfg.nodes.push(DFNode {
                        id,
                        name: v.clone(),
                        kind: DFNodeKind::Use,
                        sanitized,
                        branch: branch_stack.last().copied(),
                    });
                    if let Some(def) = fir.symbols.get(&canonical).and_then(|s| s.def) {
                        dfg.edges.push((def, id));
                    }
                }
            }
            if let Some(update) = node.child_by_field_name("update") {
                build_ir(
                    update,
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
            let before = fir.symbols.clone();
            let bid = *branch_counter;
            *branch_counter += 1;
            branch_stack.push(bid);
            if let Some(body) = node.child_by_field_name("body") {
                build_ir(
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
        if node.kind() == "function_definition" {
            if let Some(name_node) = node.child_by_field_name("name") {
                if let Ok(fname) = name_node.utf8_text(src.as_bytes()) {
                    let pos = node.start_position();
                    fir.push(IRNode {
                        id: 0,
                        kind: "php".into(),
                        path: format!("function.{fname}"),
                        value: JsonValue::Null,
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
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
                    if let Some(params) = node.child_by_field_name("parameters") {
                        let mut pc = params.walk();
                        for param in params.named_children(&mut pc) {
                            let mut vars = Vec::new();
                            collect_vars(param, src, &mut vars);
                            if let Some(pname) = vars.first() {
                                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                let pid = dfg.nodes.len();
                                dfg.nodes.push(DFNode {
                                    id: pid,
                                    name: pname.clone(),
                                    kind: DFNodeKind::Param,
                                    sanitized: false,
                                    branch: branch_stack.last().copied(),
                                });
                                fn_params.entry(id).or_default().push(pid);
                                fir.symbols.insert(
                                    pname.clone(),
                                    Symbol {
                                        name: pname.clone(),
                                        sanitized: false,
                                        def: Some(pid),
                                        alias_of: None,
                                    },
                                );
                            }
                        }
                    }
                    let mut cursor = node.walk();
                    for child in node.children(&mut cursor) {
                        build_ir(
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
                }
            }
            return;
        }

        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            build_ir(
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

        match node.kind() {
            "function_call_expression" => {
                let mut callee = None;
                if let Some(name) = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("function"))
                {
                    if let Ok(id) = name.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "php".into(),
                            path: format!("call.{id}"),
                            value: JsonValue::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                        if let Some(&callee_id) = fn_ids.get(id) {
                            callee = Some(callee_id);
                            if let Some(caller_id) = current_fn {
                                fir.dfg
                                    .get_or_insert_with(DataFlowGraph::default)
                                    .calls
                                    .push((caller_id, callee_id));
                            }
                        }
                    }
                }
                if let Some(callee_id) = callee {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        let mut ac = args.walk();
                        for (idx, arg) in args.named_children(&mut ac).enumerate() {
                            let mut ids = Vec::new();
                            collect_vars(arg, src, &mut ids);
                            for name in ids {
                                let canonical = resolve_alias(&name, &fir.symbols);
                                if let Some(def_id) =
                                    fir.symbols.get(&canonical).and_then(|s| s.def)
                                {
                                    call_args.push((def_id, callee_id, idx));
                                }
                            }
                        }
                    }
                }
                let mut vars = Vec::new();
                collect_vars(node, src, &mut vars);
                for v in vars {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    let canonical = resolve_alias(&v, &fir.symbols);
                    let sanitized = fir
                        .symbols
                        .get(&canonical)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    dfg.nodes.push(DFNode {
                        id,
                        name: v.clone(),
                        kind: DFNodeKind::Use,
                        sanitized,
                        branch: branch_stack.last().copied(),
                    });
                    if let Some(def) = fir.symbols.get(&canonical).and_then(|s| s.def) {
                        dfg.edges.push((def, id));
                    }
                }
            }
            "variable_name" => {
                if let Ok(text) = node.utf8_text(src.as_bytes()) {
                    let name = text.trim_start_matches('$');
                    if SUPERGLOBALS.contains(&name) {
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "php".into(),
                            path: format!("var.{name}"),
                            value: JsonValue::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                        if !fir.symbols.contains_key(name) {
                            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                            let id = dfg.nodes.len();
                            dfg.nodes.push(DFNode {
                                id,
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
                                    def: Some(id),
                                    alias_of: None,
                                },
                            );
                        }
                    }
                }
            }
            "assignment_expression"
            | "by_ref_assignment_expression"
            | "reference_assignment_expression" => {
                let left = node
                    .child_by_field_name("left")
                    .or_else(|| node.child_by_field_name("variable"));
                let right = node
                    .child_by_field_name("right")
                    .or_else(|| node.child_by_field_name("value"));
                if let (Some(left), Some(right)) = (left, right) {
                    let mut lvars = Vec::new();
                    collect_vars(left, src, &mut lvars);
                    if let Some(lname) = lvars.first() {
                        let mut sanitized = false;
                        let mut alias: Option<String> = None;
                        let mut sources = Vec::new();
                        let mut callee_ret: Option<usize> = None;
                        if right.kind() == "variable_name" {
                            if let Ok(rtext) = right.utf8_text(src.as_bytes()) {
                                let rname = rtext.trim_start_matches('$');
                                alias = Some(resolve_alias(rname, &fir.symbols));
                                if let Some(sym) = fir.symbols.get(rname) {
                                    sanitized = sym.sanitized;
                                    if let Some(def) = sym.def {
                                        sources.push(def);
                                    }
                                }
                            }
                        } else if right.kind() == "function_call_expression" {
                            if let Some(name_node) = right
                                .child_by_field_name("name")
                                .or_else(|| right.child_by_field_name("function"))
                            {
                                if let Ok(fname) = name_node.utf8_text(src.as_bytes()) {
                                    sanitized = is_sanitizer(fname, fir);
                                    if let Some(&cid) = fn_ids.get(fname) {
                                        callee_ret = Some(cid);
                                    }
                                }
                            }
                        } else {
                            let mut vars = Vec::new();
                            collect_vars(right, src, &mut vars);
                            for v in &vars {
                                if alias.is_none() && vars.len() == 1 {
                                    alias = Some(resolve_alias(v, &fir.symbols));
                                }
                                if let Some(sym) = fir.symbols.get(v) {
                                    if !sanitized && vars.len() == 1 {
                                        sanitized = sym.sanitized;
                                    }
                                    if let Some(def) = sym.def {
                                        sources.push(def);
                                    }
                                }
                            }
                        }
                        let is_ref = node.kind() == "by_ref_assignment_expression"
                            || node.kind() == "reference_assignment_expression"
                            || right.kind() == "variable_reference";
                        if is_ref {
                            if let Some(canonical) = alias.clone() {
                                let sanitized = fir
                                    .symbols
                                    .get(&canonical)
                                    .map(|s| s.sanitized)
                                    .unwrap_or(false);
                                let def = fir.symbols.get(&canonical).and_then(|s| s.def);
                                fir.symbols.insert(
                                    lname.clone(),
                                    Symbol {
                                        name: lname.clone(),
                                        sanitized,
                                        def,
                                        alias_of: Some(canonical),
                                    },
                                );
                            }
                        } else {
                            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                            let id = dfg.nodes.len();
                            dfg.nodes.push(DFNode {
                                id,
                                name: lname.clone(),
                                kind: DFNodeKind::Def,
                                sanitized,
                                branch: branch_stack.last().copied(),
                            });
                            for src_id in sources {
                                dfg.edges.push((src_id, id));
                            }
                            if let Some(cid) = callee_ret {
                                dfg.call_returns.push((id, cid));
                            }
                            fir.symbols.insert(
                                lname.clone(),
                                Symbol {
                                    name: lname.clone(),
                                    sanitized,
                                    def: Some(id),
                                    alias_of: alias.clone(),
                                },
                            );
                            if let Some(canonical) = alias {
                                fir.symbols.entry(canonical).or_default();
                            }
                        }
                    }
                }
            }
            "return_statement" => {
                let mut vars = Vec::new();
                collect_vars(node, src, &mut vars);
                for v in vars {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    let canonical = resolve_alias(&v, &fir.symbols);
                    let sanitized = fir
                        .symbols
                        .get(&canonical)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    dfg.nodes.push(DFNode {
                        id,
                        name: v.clone(),
                        kind: DFNodeKind::Return,
                        sanitized,
                        branch: branch_stack.last().copied(),
                    });
                    fir.symbols.entry(v.clone()).or_insert_with(|| Symbol {
                        name: v.clone(),
                        ..Default::default()
                    });
                    if let Some(def) = fir.symbols.get(&canonical).and_then(|s| s.def) {
                        dfg.edges.push((def, id));
                    }
                    if let Some(fid) = current_fn {
                        fn_returns.entry(fid).or_default().push(id);
                    }
                }
            }
            "echo_statement" => {
                let pos = node.start_position();
                fir.push(IRNode {
                    id: 0,
                    kind: "php".into(),
                    path: "call.echo".into(),
                    value: JsonValue::Null,
                    meta: Meta {
                        file: fir.file_path.clone(),
                        line: pos.row + 1,
                        column: pos.column + 1,
                    },
                });
                let mut vars = Vec::new();
                collect_vars(node, src, &mut vars);
                if let Ok(txt) = node.utf8_text(src.as_bytes()) {
                    for sg in ["_REQUEST", "_GET", "_POST"] {
                        if txt.contains(&format!("${sg}")) && !vars.iter().any(|v| v == sg) {
                            vars.push(sg.to_string());
                        }
                    }
                }
                for v in vars {
                    let canonical = resolve_alias(&v, &fir.symbols);
                    if !fir.symbols.contains_key(&canonical) {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        let did = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id: did,
                            name: canonical.clone(),
                            kind: DFNodeKind::Def,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        });
                        fir.push(IRNode {
                            id: 0,
                            kind: "php".into(),
                            path: format!("var.{canonical}"),
                            value: JsonValue::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                        fir.symbols.insert(
                            canonical.clone(),
                            Symbol {
                                name: canonical.clone(),
                                sanitized: false,
                                def: Some(did),
                                alias_of: None,
                            },
                        );
                    }
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    let sanitized = fir
                        .symbols
                        .get(&canonical)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    dfg.nodes.push(DFNode {
                        id,
                        name: v.clone(),
                        kind: DFNodeKind::Use,
                        sanitized,
                        branch: branch_stack.last().copied(),
                    });
                    if let Some(def) = fir.symbols.get(&canonical).and_then(|s| s.def) {
                        dfg.edges.push((def, id));
                    }
                }
            }
            _ => {}
        }
    }

    fn walk_ast(
        node: tree_sitter::Node,
        src: &str,
        file: &str,
        counter: &mut usize,
        parent: Option<usize>,
    ) -> AstNode {
        let id = *counter;
        *counter += 1;
        let kind = to_camel(node.kind());
        let mut value = JsonValue::Null;
        match node.kind() {
            "function_call_expression" => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .or_else(|| node.child_by_field_name("function"))
                {
                    if let Ok(txt) = name.utf8_text(src.as_bytes()) {
                        value = JsonValue::String(txt.to_string());
                    }
                }
            }
            "function_definition" => {
                if let Some(name) = node.child_by_field_name("name") {
                    if let Ok(txt) = name.utf8_text(src.as_bytes()) {
                        value = JsonValue::String(txt.to_string());
                    }
                }
            }
            "assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    if let Ok(txt) = left.utf8_text(src.as_bytes()) {
                        value = JsonValue::String(txt.trim_start_matches('$').to_string());
                    }
                }
            }
            "variable_name" => {
                if let Ok(txt) = node.utf8_text(src.as_bytes()) {
                    value = JsonValue::String(txt.trim_start_matches('$').to_string());
                }
            }
            _ => {}
        }
        let pos = node.start_position();
        let mut children = Vec::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            children.push(walk_ast(child, src, file, counter, Some(id)));
        }
        AstNode {
            id,
            parent,
            kind,
            value,
            children,
            meta: Meta {
                file: file.to_string(),
                line: pos.row + 1,
                column: pos.column + 1,
            },
        }
    }

    debug!("Getting PHP parser from pool for file: {}", fir.file_path);
    let mut parser = get_parser();
    debug!("Setting PHP language for file: {}", fir.file_path);
    parser
        .set_language(tree_sitter_php::language())
        .context("load php grammar")?;
    debug!("Parsing PHP content for file: {}", fir.file_path);
    let tree = parser
        .parse(content, None)
        .ok_or_else(|| anyhow!("failed to parse php source"))?;
    debug!("PHP parsing completed for file: {}", fir.file_path);

    // Devolver el parser al pool
    return_parser(parser);
    let root = tree.root_node();
    let mut fn_ids = HashMap::new();
    let mut fn_params: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut fn_returns: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut call_args: Vec<(usize, usize, usize)> = Vec::new();
    let mut branch_stack: Vec<usize> = Vec::new();
    let mut branch_counter: usize = 0;
    build_ir(
        root,
        content,
        fir,
        None,
        &mut fn_ids,
        &mut fn_params,
        &mut fn_returns,
        &mut call_args,
        &mut branch_stack,
        &mut branch_counter,
    );
    if let Some(dfg) = &mut fir.dfg {
        for (src, callee, idx) in call_args {
            if let Some(params) = fn_params.get(&callee) {
                if let Some(&pid) = params.get(idx) {
                    dfg.edges.push((src, pid));
                    if dfg.nodes[src].sanitized {
                        if let Some(node) = dfg.nodes.get_mut(pid) {
                            node.sanitized = true;
                            let canonical = resolve_alias(&node.name, &fir.symbols);
                            if let Some(sym) = fir.symbols.get_mut(&canonical) {
                                sym.sanitized = true;
                            }
                        }
                    }
                }
            }
        }
        let returns = dfg.call_returns.clone();
        for (dest, callee) in returns {
            if let Some(rets) = fn_returns.get(&callee) {
                for &rid in rets {
                    dfg.edges.push((rid, dest));
                }
            }
        }
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
            for &(s, d) in &dfg.edges.clone() {
                if s == id {
                    if let Some(node) = dfg.nodes.get_mut(d) {
                        if matches!(node.kind, DFNodeKind::Assign) && node.branch.is_none() {
                            continue;
                        }
                        if !node.sanitized {
                            node.sanitized = true;
                            let canonical = resolve_alias(&node.name, &fir.symbols);
                            if let Some(sym) = fir.symbols.get_mut(&canonical) {
                                sym.sanitized = true;
                            }
                            queue.push(d);
                        }
                    }
                }
            }
        }
    }
    let mut file_ast = FileAst::new(fir.file_path.clone(), "php".into());
    let mut cursor = root.walk();
    let mut counter = 0usize;
    for child in root.children(&mut cursor) {
        file_ast.push(walk_ast(child, content, &fir.file_path, &mut counter, None));
    }
    fir.ast = Some(file_ast);

    // Second pass: process sanitization
    process_sanitization(root, content, fir);

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct CachedFile {
    hash: String,
    path: String,
    ir: FileIR,
}

#[derive(Default, Serialize, Deserialize)]
struct CacheData {
    files: HashMap<String, CachedFile>,
}

fn find_includes(content: &str, file: &Path) -> Vec<std::path::PathBuf> {
    fn eval_expr(
        node: tree_sitter::Node,
        src: &str,
        vars: &std::collections::HashMap<String, String>,
        base: &Path,
    ) -> Option<String> {
        match node.kind() {
            "string" => node
                .utf8_text(src.as_bytes())
                .ok()
                .map(|s| s.trim_matches(['"', '\'']).to_string()),
            "parenthesized_expression" => node
                .named_child(0)
                .and_then(|c| eval_expr(c, src, vars, base)),
            "binary_expression" => {
                if node.child(1).and_then(|c| c.utf8_text(src.as_bytes()).ok()) == Some(".") {
                    let left = node.child(0).and_then(|c| eval_expr(c, src, vars, base));
                    let right = node.child(2).and_then(|c| eval_expr(c, src, vars, base));
                    match (left, right) {
                        (Some(l), Some(r)) => Some(format!("{l}{r}")),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            "variable_name" => node
                .utf8_text(src.as_bytes())
                .ok()
                .map(|s| s.trim_start_matches('$').to_string())
                .and_then(|n| vars.get(&n).cloned()),
            "name" => node
                .utf8_text(src.as_bytes())
                .ok()
                .filter(|s| *s == "__DIR__")
                .map(|_| base.to_string_lossy().into_owned()),
            _ => None,
        }
    }

    fn walk(
        node: tree_sitter::Node,
        src: &str,
        vars: &mut std::collections::HashMap<String, String>,
        out: &mut Vec<std::path::PathBuf>,
        base: &Path,
    ) {
        match node.kind() {
            "assignment_expression"
            | "by_ref_assignment_expression"
            | "reference_assignment_expression" => {
                let left = node
                    .child_by_field_name("left")
                    .or_else(|| node.child_by_field_name("variable"));
                let right = node
                    .child_by_field_name("right")
                    .or_else(|| node.child_by_field_name("value"));
                if let (Some(l), Some(r)) = (left, right) {
                    if let Ok(name) = l.utf8_text(src.as_bytes()) {
                        if let Some(val) = eval_expr(r, src, vars, base) {
                            vars.insert(name.trim_start_matches('$').to_string(), val);
                        }
                    }
                }
            }
            "include_expression"
            | "include_once_expression"
            | "require_expression"
            | "require_once_expression" => {
                if let Some(arg) = node
                    .child_by_field_name("argument")
                    .or_else(|| node.named_child(0))
                {
                    if let Some(val) = eval_expr(arg, src, vars, base) {
                        let p = std::path::PathBuf::from(&val);
                        let p = if p.is_absolute() { p } else { base.join(p) };
                        out.push(p);
                    }
                }
            }
            _ => {}
        }
        let mut c = node.walk();
        for child in node.children(&mut c) {
            walk(child, src, vars, out, base);
        }
    }

    let mut parser = get_parser();
    parser
        .set_language(tree_sitter_php::language())
        .expect("language");
    let tree = match parser.parse(content, None) {
        Some(t) => t,
        None => {
            return_parser(parser);
            return Vec::new();
        }
    };
    let mut vars = std::collections::HashMap::new();
    let mut out = Vec::new();
    let base = file.parent().unwrap_or(Path::new("."));
    walk(tree.root_node(), content, &mut vars, &mut out, base);
    return_parser(parser);
    out
}

pub fn parse_php_project(
    root: &Path,
    cache_path: &Path,
    mut metrics: Option<&mut ParserMetrics>,
) -> Result<(HashMap<String, FileIR>, usize)> {
    let mut cache: CacheData = fs::read_to_string(cache_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    let mut modules = HashMap::new();
    let mut parsed = 0usize;
    let mut stack = vec![root.to_path_buf()];

    let composer = root.join("composer.json");
    if composer.exists() {
        if let Ok(cfg) = fs::read_to_string(&composer) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&cfg) {
                for section in ["autoload", "autoload-dev"] {
                    if let Some(files) = json
                        .get(section)
                        .and_then(|v| v.get("files"))
                        .and_then(|f| f.as_array())
                    {
                        for f in files {
                            if let Some(s) = f.as_str() {
                                let p = root.join(s);
                                stack.push(p);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut seen = HashSet::new();
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path)? {
                let entry = entry?;
                stack.push(entry.path());
            }
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("php") {
            continue;
        }
        let canonical = fs::canonicalize(&path).unwrap_or(path.clone());
        let canonical_str = canonical.to_string_lossy().into_owned();
        if !seen.insert(canonical_str.clone()) {
            continue;
        }
        let content = fs::read_to_string(&path)?;
        for inc in find_includes(&content, &canonical) {
            stack.push(inc);
        }
        let h = blake3::hash(content.as_bytes()).to_hex().to_string();
        if let Some(c) = cache.files.get(&canonical_str) {
            if c.hash == h {
                if let Some(m) = metrics.as_deref_mut() {
                    m.cache_hits += 1;
                }
                modules.insert(canonical_str.clone(), c.ir.clone());
                continue;
            }
        }
        let mut fir = FileIR::new(canonical_str.clone(), "php".into());
        if let Err(e) = parse_php(&content, &mut fir) {
            if let Some(m) = metrics.as_deref_mut() {
                m.parse_errors += 1;
            }
            tracing::warn!("{e}");
            continue;
        } else if let Some(m) = metrics.as_deref_mut() {
            m.files_parsed += 1;
        }
        cache.files.insert(
            canonical_str.clone(),
            CachedFile {
                hash: h,
                path: canonical_str.clone(),
                ir: fir.clone(),
            },
        );
        modules.insert(canonical_str, fir);
        parsed += 1;
    }
    cache.files.retain(|k, _| seen.contains(k));
    if let Ok(s) = serde_json::to_string(&cache) {
        let _ = fs::write(cache_path, s);
    }
    Ok((modules, parsed))
}
