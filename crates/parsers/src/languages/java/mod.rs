use crate::{catalog as catalog_module, ParserMetrics};
use anyhow::{anyhow, Context, Result};
use ir::{
    AstNode, DFNode, DFNodeKind, DataFlowGraph, FileAst, FileIR, IRNode, Meta, Symbol, SymbolKind,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Component, Path},
};

#[cfg(test)]
mod tests;

pub mod catalog;

fn extract_package(content: &str) -> Option<String> {
    for line in content.lines() {
        let l = line.trim();
        if l.starts_with("package ") {
            return Some(
                l.trim_start_matches("package")
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .to_string(),
            );
        }
        if !l.is_empty() && !l.starts_with("//") && !l.starts_with("/*") {
            break;
        }
    }
    None
}

pub fn parse_java(content: &str, fir: &mut FileIR) -> Result<()> {
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

    fn extract_call_path(node: tree_sitter::Node, src: &str) -> Option<String> {
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

    fn gather_ids(node: tree_sitter::Node, src: &str, out: &mut Vec<String>) {
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
                if let Some(obj) = node.child_by_field_name("object") {
                    if obj.kind() == "identifier" {
                        if let Ok(id) = obj.utf8_text(src.as_bytes()) {
                            out.push(id.to_string());
                        }
                    } else {
                        gather_ids(obj, src, out);
                    }
                }
                if let Some(args) = node
                    .child_by_field_name("arguments")
                    .or_else(|| node.child_by_field_name("argument_list"))
                {
                    gather_ids(args, src, out);
                }
                return;
            }
            "object_creation_expression" => {
                // Handle constructor arguments like "new URL(urlImage)"
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

    fn walk_ir(
        node: tree_sitter::Node,
        src: &str,
        fir: &mut FileIR,
        imports: &mut HashMap<String, String>,
        wildcards: &mut Vec<String>,
    ) {
        match node.kind() {
            "import_declaration" => {
                if let Ok(text) = node.utf8_text(src.as_bytes()) {
                    let path = text
                        .trim_start_matches("import")
                        .trim()
                        .trim_start_matches("static")
                        .trim()
                        .trim_end_matches(';')
                        .trim();
                    if !path.is_empty() {
                        if path.ends_with(".*") {
                            wildcards.push(path.trim_end_matches(".*").to_string());
                        } else {
                            let base = path.rsplit('.').next().unwrap_or(path);
                            imports.insert(base.to_string(), path.to_string());
                        }
                        let pos = node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "java".into(),
                            path: format!("import.{path}"),
                            value: serde_json::Value::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                    }
                }
            }
            "method_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                        let pos = name_node.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "java".into(),
                            path: format!("function.{name}"),
                            value: serde_json::Value::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                    }
                }
            }
            "method_invocation" => {
                if let Some(path) = extract_call_path(node, src) {
                    let pos = node.start_position();
                    fir.push(IRNode {
                        id: 0,
                        kind: "java".into(),
                        path: format!("call.{path}"),
                        value: serde_json::Value::Null,
                        meta: Meta {
                            file: fir.file_path.clone(),
                            line: pos.row + 1,
                            column: pos.column + 1,
                        },
                    });
                    for full in resolve_import(&path, imports, wildcards) {
                        fir.push(IRNode {
                            id: 0,
                            kind: "java".into(),
                            path: format!("call.{full}"),
                            value: serde_json::Value::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                    }
                }
            }
            "object_creation_expression" => {
                // Handle constructor calls like "new URL(...)"
                if let Some(type_node) = node.child_by_field_name("type") {
                    if let Ok(type_name) = type_node.utf8_text(src.as_bytes()) {
                        let pos = node.start_position();
                        // Generate path in format that matches Semgrep patterns like "new URL"
                        let path = format!("new {}", type_name);
                        fir.push(IRNode {
                            id: 0,
                            kind: "java".into(),
                            path: format!("call.{path}"),
                            value: serde_json::Value::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                        // Also resolve imports for the constructor
                        for full in resolve_import(type_name, imports, wildcards) {
                            let full_path = format!("new {}", full);
                            fir.push(IRNode {
                                id: 0,
                                kind: "java".into(),
                                path: format!("call.{full_path}"),
                                value: serde_json::Value::Null,
                                meta: Meta {
                                    file: fir.file_path.clone(),
                                    line: pos.row + 1,
                                    column: pos.column + 1,
                                },
                            });
                        }
                    }
                }
            }
            "assignment_expression" => {
                if let Some(left) = node.child_by_field_name("left") {
                    if let Ok(var) = left.utf8_text(src.as_bytes()) {
                        let pos = left.start_position();
                        fir.push(IRNode {
                            id: 0,
                            kind: "java".into(),
                            path: format!("assign.{var}"),
                            value: serde_json::Value::Null,
                            meta: Meta {
                                file: fir.file_path.clone(),
                                line: pos.row + 1,
                                column: pos.column + 1,
                            },
                        });
                    }
                }
            }
            "local_variable_declaration" => {
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    if child.kind() == "variable_declarator" {
                        if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(var) = name_node.utf8_text(src.as_bytes()) {
                                let pos = name_node.start_position();
                                fir.push(IRNode {
                                    id: 0,
                                    kind: "java".into(),
                                    path: format!("assign.{var}"),
                                    value: serde_json::Value::Null,
                                    meta: Meta {
                                        file: fir.file_path.clone(),
                                        line: pos.row + 1,
                                        column: pos.column + 1,
                                    },
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_ir(child, src, fir, imports, wildcards);
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
                    for d in &defs {
                        dfg.edges.push((*d, id));
                    }
                    dfg.merges.push((id, defs.clone()));
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
    fn build_dfg(
        node: tree_sitter::Node,
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
    ) {
        match node.kind() {
            "method_declaration" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    if let Ok(name) = name_node.utf8_text(src.as_bytes()) {
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        let id = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id,
                            name: name.to_string(),
                            kind: DFNodeKind::Def,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        });
                        fn_ids.insert(name.to_string(), id);
                        if let Some(params) = node.child_by_field_name("parameters") {
                            let mut pc = params.walk();
                            for p in params.children(&mut pc) {
                                if p.kind() == "formal_parameter" {
                                    if let Some(pn) = p.child_by_field_name("name") {
                                        if let Ok(pname) = pn.utf8_text(src.as_bytes()) {
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
                            );
                        }
                        return;
                    }
                }
            }
            "lambda_expression" => {
                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                let func_id = dfg.nodes.len();
                let lname = format!("lambda_{func_id}");
                dfg.nodes.push(DFNode {
                    id: func_id,
                    name: lname,
                    kind: DFNodeKind::Def,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                });
                if let Some(params) = node.child_by_field_name("parameters") {
                    let mut pnames = Vec::new();
                    gather_ids(params, src, &mut pnames);
                    for pname in pnames {
                        let pid = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id: pid,
                            name: pname.clone(),
                            kind: DFNodeKind::Param,
                            sanitized: false,
                            branch: branch_stack.last().copied(),
                        });
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
                        );
                    } else {
                        let mut ids = Vec::new();
                        gather_ids(body, src, &mut ids);
                        for name in ids {
                            let canonical = resolve_alias(&name, &fir.symbols);
                            let sanitized = find_symbol(&canonical, &fir.symbols)
                                .map(|s| s.sanitized)
                                .unwrap_or(false);
                            let rid = dfg.nodes.len();
                            dfg.nodes.push(DFNode {
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
                                dfg.edges.push((def_id, rid));
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
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    for name in ids {
                        let canonical = resolve_alias(&name, &fir.symbols);
                        let sanitized = find_symbol(&canonical, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or(false);
                        let uid = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
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
                        if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            dfg.edges.push((def_id, uid));
                        }
                    }
                }
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
                        imports,
                        wildcards,
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
                    );
                    branch_states.push(fir.symbols.clone());
                    branch_stack.pop();
                } else {
                    branch_states.push(before.clone());
                }
                merge_states(fir, branch_states);
                return;
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
                    for name in ids {
                        let canonical = resolve_alias(&name, &fir.symbols);
                        let sanitized = find_symbol(&canonical, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or(false);
                        let uid = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
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
                        if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            dfg.edges.push((def_id, uid));
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
                    );
                    branch_states.push(fir.symbols.clone());
                    branch_stack.pop();
                }
                branch_states.push(before.clone());
                merge_states(fir, branch_states);
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
                    );
                }
                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                let nid = dfg.nodes.len();
                dfg.nodes.push(DFNode {
                    id: nid,
                    name: "for".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                });
                if let Some(cond) = node.child_by_field_name("condition") {
                    let mut ids = Vec::new();
                    gather_ids(cond, src, &mut ids);
                    for name in ids {
                        let canonical = resolve_alias(&name, &fir.symbols);
                        let sanitized = find_symbol(&canonical, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or(false);
                        let uid = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
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
                        if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            dfg.edges.push((def_id, uid));
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
                        );
                    }
                    branch_states.push(fir.symbols.clone());
                    branch_stack.pop();
                }
                branch_states.push(before.clone());
                merge_states(fir, branch_states);
                return;
            }
            "enhanced_for_statement" => {
                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                let nid = dfg.nodes.len();
                dfg.nodes.push(DFNode {
                    id: nid,
                    name: "for".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                });
                if let Some(val) = node.child_by_field_name("value") {
                    let mut ids = Vec::new();
                    gather_ids(val, src, &mut ids);
                    for name in ids {
                        let canonical = resolve_alias(&name, &fir.symbols);
                        let sanitized = find_symbol(&canonical, &fir.symbols)
                            .map(|s| s.sanitized)
                            .unwrap_or(false);
                        let uid = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
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
                        if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            dfg.edges.push((def_id, uid));
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
                    );
                    branch_states.push(fir.symbols.clone());
                    branch_stack.pop();
                }
                branch_states.push(before.clone());
                merge_states(fir, branch_states);
                return;
            }
            "switch_statement" | "switch_expression" => {
                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                let nid = dfg.nodes.len();
                dfg.nodes.push(DFNode {
                    id: nid,
                    name: "switch".to_string(),
                    kind: DFNodeKind::Branch,
                    sanitized: false,
                    branch: branch_stack.last().copied(),
                });
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
                        let uid = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
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
                        if let Some(def_id) =
                            find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                        {
                            dfg.edges.push((def_id, uid));
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
                merge_states(fir, branch_states);
                return;
            }
            "method_reference" => {
                if let Ok(text) = node.utf8_text(src.as_bytes()) {
                    let name = text.replace("::", ".");
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    dfg.nodes.push(DFNode {
                        id,
                        name,
                        kind: DFNodeKind::Use,
                        sanitized: false,
                        branch: branch_stack.last().copied(),
                    });
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
                                    if val.kind() != "lambda_expression"
                                        && val.kind() != "method_reference"
                                    {
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
                                            }
                                            if let Some(args) = val.child_by_field_name("arguments")
                                            {
                                                gather_ids(args, src, &mut ids);
                                            }
                                        } else {
                                            gather_ids(val, src, &mut ids);
                                        }
                                    }
                                }
                                let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                                let id = dfg.nodes.len();
                                dfg.nodes.push(DFNode {
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
                                            if let Some(n) = dfg.nodes.get_mut(id) {
                                                n.sanitized = true;
                                            }
                                        }
                                    }
                                }
                                for src_name in ids {
                                    let canonical = resolve_alias(&src_name, &fir.symbols);
                                    if let Some(def_id) =
                                        find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                                    {
                                        dfg.edges.push((def_id, id));
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
                                                dfg.call_returns.push((id, callee_id));
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
                            if right.kind() != "lambda_expression"
                                && right.kind() != "method_reference"
                            {
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
                                    }
                                    if let Some(args) = right.child_by_field_name("arguments") {
                                        gather_ids(args, src, &mut ids);
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
                        let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                        let id = dfg.nodes.len();
                        dfg.nodes.push(DFNode {
                            id,
                            name: var.to_string(),
                            kind: DFNodeKind::Def,
                            sanitized: sanitized || alias_sanitized,
                            branch: branch_stack.last().copied(),
                        });
                        // First, get necessary information with immutable borrows
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

                        // Now make the modifications with a mutable borrow
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
                            if let Some(n) = dfg.nodes.get_mut(id) {
                                n.sanitized = true;
                            }
                        }

                        // Add edges using previously obtained information
                        for canonical in canonical_names {
                            if let Some(def_id) =
                                find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                            {
                                dfg.edges.push((def_id, id));
                            }
                        }
                        if let Some(bid) = base_def_id {
                            dfg.edges.push((bid, id));
                        }
                        if let Some(right) = node.child_by_field_name("right") {
                            if right.kind() != "lambda_expression"
                                && right.kind() != "method_reference"
                            {
                                if let Some(call) = extract_call_path(right, src) {
                                    if let Some(&callee_id) =
                                        fn_ids.get(call.rsplit('.').next().unwrap_or(&call))
                                    {
                                        dfg.call_returns.push((id, callee_id));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            "return_statement" => {
                let mut ids = Vec::new();
                gather_ids(node, src, &mut ids);
                for name in ids {
                    let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                    let id = dfg.nodes.len();
                    let canonical = resolve_alias(&name, &fir.symbols);
                    let sanitized = find_symbol(&canonical, &fir.symbols)
                        .map(|s| s.sanitized)
                        .unwrap_or(false);
                    dfg.nodes.push(DFNode {
                        id,
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
                    if let Some(def_id) = find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                    {
                        dfg.edges.push((def_id, id));
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
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut cursor = args.walk();
                    for (idx, arg) in args
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
                            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                            let id = dfg.nodes.len();
                            dfg.nodes.push(DFNode {
                                id,
                                name: var.to_string(),
                                kind: DFNodeKind::Use,
                                sanitized,
                                branch: branch_stack.last().copied(),
                            });
                            if let Some(def_id) =
                                find_symbol(&var, &fir.symbols).and_then(|s| s.def)
                            {
                                dfg.edges.push((def_id, id));
                                if let Some(cid) = callee {
                                    call_args.push((def_id, cid, idx));
                                }
                            } else if let Some(def_id) =
                                find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                            {
                                dfg.edges.push((def_id, id));
                                if let Some(cid) = callee {
                                    call_args.push((def_id, cid, idx));
                                }
                            }
                        }
                    }
                }
            }
            "object_creation_expression" => {
                // Handle constructor calls like "new URL(...)" for data flow
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut cursor = args.walk();
                    for (idx, arg) in args
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
                            let dfg = fir.dfg.get_or_insert_with(DataFlowGraph::default);
                            let id = dfg.nodes.len();
                            dfg.nodes.push(DFNode {
                                id,
                                name: var.to_string(),
                                kind: DFNodeKind::Use,
                                sanitized,
                                branch: branch_stack.last().copied(),
                            });
                            if let Some(def_id) =
                                find_symbol(&var, &fir.symbols).and_then(|s| s.def)
                            {
                                dfg.edges.push((def_id, id));
                            } else if let Some(def_id) =
                                find_symbol(&canonical, &fir.symbols).and_then(|s| s.def)
                            {
                                dfg.edges.push((def_id, id));
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
            );
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
        let mut value = serde_json::Value::Null;
        if kind == "MethodDeclaration" {
            if let Some(name) = node.child_by_field_name("name") {
                if let Ok(n) = name.utf8_text(src.as_bytes()) {
                    value = serde_json::json!(n);
                }
            }
        } else if kind == "MethodInvocation" {
            if let Some(call) = extract_call_path(node, src) {
                value = serde_json::json!(call);
            }
        } else if kind == "LocalVariableDeclaration" {
            if let Some(var) = node
                .child_by_field_name("declarators")
                .and_then(|d| d.child(0))
                .and_then(|v| v.child_by_field_name("name"))
            {
                if let Ok(n) = var.utf8_text(src.as_bytes()) {
                    value = serde_json::json!(n);
                }
            }
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

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_java::language())
        .context("load java grammar")?;
    let tree = parser
        .parse(content, None)
        .ok_or_else(|| anyhow!("failed to parse java source"))?;
    let root = tree.root_node();
    let mut imports = HashMap::new();
    let mut wildcards = Vec::new();
    walk_ir(root, content, fir, &mut imports, &mut wildcards);
    let mut fn_ids = HashMap::new();
    let mut fn_params: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut fn_returns: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut call_args: Vec<(usize, usize, usize)> = Vec::new();
    let mut branch_stack: Vec<usize> = Vec::new();
    let mut branch_counter: usize = 0;
    build_dfg(
        root,
        content,
        fir,
        &imports,
        &wildcards,
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
    let mut file_ast = FileAst::new(fir.file_path.clone(), "java".into());
    let mut cursor = root.walk();
    let mut counter = 0usize;
    for child in root.children(&mut cursor) {
        file_ast.push(walk_ast(child, content, &fir.file_path, &mut counter, None));
    }
    fir.ast = Some(file_ast);
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct CachedFile {
    hash: String,
    package: String,
    ir: FileIR,
}

#[derive(Default, Serialize, Deserialize)]
struct CacheData {
    files: HashMap<String, CachedFile>,
}

pub fn parse_java_project_uncached(root: &Path) -> Result<HashMap<String, FileIR>> {
    let mut modules = HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("java") {
                let content = fs::read_to_string(&path)?;
                let mut fir = FileIR::new(path.to_string_lossy().into(), "java".into());
                if let Err(e) = parse_java(&content, &mut fir) {
                    tracing::warn!("{e}");
                    continue;
                }
                let package = if let Some(pkg) = extract_package(&content) {
                    let class = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default();
                    format!("{pkg}.{class}")
                } else {
                    let rel = path.strip_prefix(root).unwrap_or(&path);
                    let mut comps: Vec<String> = rel
                        .components()
                        .filter_map(|c| match c {
                            Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                            _ => None,
                        })
                        .collect();
                    if let Some(last) = comps.last_mut() {
                        if last.ends_with(".java") {
                            *last = last.trim_end_matches(".java").to_string();
                        }
                    }
                    comps.join(".")
                };
                let names: Vec<String> = fir.symbols.keys().cloned().collect();
                for name in names {
                    if fir.symbols.get(&name).and_then(|s| s.def).is_some() {
                        fir.symbol_modules.insert(name, package.clone());
                    }
                }
                modules.insert(package, fir);
            }
        }
    }
    Ok(modules)
}

pub fn parse_java_project(
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
    let mut seen = HashSet::new();
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("java") {
                let canonical = path.to_string_lossy().into_owned();
                seen.insert(canonical.clone());
                let content = fs::read_to_string(&path)?;
                let hash = blake3::hash(content.as_bytes()).to_hex().to_string();
                if let Some(c) = cache.files.get(&canonical) {
                    if c.hash == hash {
                        if let Some(m) = metrics.as_deref_mut() {
                            m.cache_hits += 1;
                        }
                        modules.insert(c.package.clone(), c.ir.clone());
                        continue;
                    }
                }
                let mut fir = FileIR::new(canonical.clone(), "java".into());
                if let Err(e) = parse_java(&content, &mut fir) {
                    if let Some(m) = metrics.as_deref_mut() {
                        m.parse_errors += 1;
                    }
                    tracing::warn!("{e}");
                    continue;
                } else if let Some(m) = metrics.as_deref_mut() {
                    m.files_parsed += 1;
                }
                let package = if let Some(pkg) = extract_package(&content) {
                    let class = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or_default();
                    format!("{pkg}.{class}")
                } else {
                    let rel = path.strip_prefix(root).unwrap_or(&path);
                    let mut comps: Vec<String> = rel
                        .components()
                        .filter_map(|c| match c {
                            Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                            _ => None,
                        })
                        .collect();
                    if let Some(last) = comps.last_mut() {
                        if last.ends_with(".java") {
                            *last = last.trim_end_matches(".java").to_string();
                        }
                    }
                    comps.join(".")
                };
                let names: Vec<String> = fir.symbols.keys().cloned().collect();
                for name in names {
                    if fir.symbols.get(&name).and_then(|s| s.def).is_some() {
                        fir.symbol_modules.insert(name, package.clone());
                    }
                }
                cache.files.insert(
                    canonical,
                    CachedFile {
                        hash,
                        package: package.clone(),
                        ir: fir.clone(),
                    },
                );
                modules.insert(package, fir);
                parsed += 1;
            }
        }
    }
    cache.files.retain(|k, _| seen.contains(k));
    if let Ok(s) = serde_json::to_string(&cache) {
        let _ = fs::write(cache_path, s);
    }
    Ok((modules, parsed))
}
