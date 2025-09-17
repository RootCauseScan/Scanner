use anyhow::{anyhow, Result};
use ir::{DFNodeKind, FileAst, FileIR, Symbol, SymbolKind};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Component, Path};

use crate::ParserMetrics;

#[cfg(test)]
mod tests;

mod ast_builder;
pub mod catalog;
mod dfg_builder;
mod imports;
mod ir_builder;
mod symbols;

pub fn parse_rust(content: &str, fir: &mut FileIR) -> Result<()> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_rust::language())
        .expect("load rust grammar");
    let Some(tree) = parser.parse(content, None) else {
        tracing::warn!("failed to parse rust source");
        return Err(anyhow!("failed to parse rust source"));
    };
    let root = tree.root_node();
    let mut namespace = Vec::new();
    let mut imports = HashMap::new();
    ir_builder::walk_ir(root, content, fir, &mut namespace, &mut imports);
    let mut fn_ids = HashMap::new();
    let mut fn_params: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut fn_returns: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut call_args: Vec<(usize, usize, usize)> = Vec::new();
    let mut branch_stack = Vec::new();
    let mut branch_counter: usize = 0;
    dfg_builder::build_dfg(
        root,
        content,
        fir,
        &mut Vec::new(),
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
                if let Some(&param_id) = params.get(idx) {
                    dfg.edges.push((src, param_id));
                }
            }
        }
        for (dest, callee) in dfg.call_returns.clone() {
            if let Some(rets) = fn_returns.get(&callee) {
                for &r in rets {
                    dfg.edges.push((r, dest));
                }
            }
        }
    }
    let mut file_ast = FileAst::new(fir.file_path.clone(), "rust".into());
    let mut cursor = root.walk();
    let mut counter = 0usize;
    for child in root.children(&mut cursor) {
        file_ast.push(ast_builder::walk_ast(
            child,
            content,
            &fir.file_path,
            &mut counter,
            None,
        ));
    }
    fir.ast = Some(file_ast);
    Ok(())
}

fn resolve_alias<'a>(name: &'a str, symbols: &'a HashMap<String, Symbol>) -> String {
    let mut cur = name;
    let mut visited = HashSet::new();
    while let Some(sym) = symbols.get(cur) {
        if let Some(next) = sym.alias_of.as_deref() {
            if !visited.insert(cur.to_string()) {
                break;
            }
            cur = next;
        } else {
            break;
        }
    }
    cur.to_string()
}

fn link_imports(fir: &mut FileIR, modules: &HashMap<String, FileIR>) {
    let imports: Vec<(String, Option<String>)> = fir
        .nodes
        .iter()
        .filter_map(|n| {
            n.path
                .strip_prefix("import.")
                .map(|p| (p.to_string(), n.value.as_str().map(|s| s.to_string())))
        })
        .collect();
    for (path, alias) in imports {
        if path.ends_with("::*") {
            let module = path.trim_end_matches("::*");
            if let Some(mod_fir) = modules.get(module) {
                let prefix = alias.clone().unwrap_or_else(|| module.to_string());
                for (name, sym) in &mod_fir.symbols {
                    if let Some(def) = sym.def {
                        let canonical = format!("{module}::{name}");
                        let qualified = format!("{prefix}::{name}");
                        fir.symbols.insert(
                            canonical.clone(),
                            Symbol {
                                name: canonical.clone(),
                                sanitized: sym.sanitized,
                                def: Some(def),
                                alias_of: None,
                            },
                        );
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
                            .unwrap_or_else(|| module.to_string());
                        fir.symbol_modules
                            .insert(canonical.clone(), module_name.clone());
                        fir.symbol_modules.insert(qualified, module_name);
                    }
                }
            }
        } else if let Some((module, member)) = path.rsplit_once("::") {
            if let Some(mod_fir) = modules.get(module) {
                if let Some(sym) = mod_fir.symbols.get(member) {
                    if let Some(def) = sym.def {
                        let canonical = format!("{module}::{member}");
                        let alias_name = alias.clone().unwrap_or_else(|| member.to_string());
                        fir.symbols.insert(
                            canonical.clone(),
                            Symbol {
                                name: canonical.clone(),
                                sanitized: sym.sanitized,
                                def: Some(def),
                                alias_of: None,
                            },
                        );
                        fir.symbols.insert(
                            alias_name.clone(),
                            Symbol {
                                name: alias_name.clone(),
                                sanitized: sym.sanitized,
                                def: Some(def),
                                alias_of: Some(canonical.clone()),
                            },
                        );
                        let module_name = mod_fir
                            .symbol_modules
                            .get(member)
                            .cloned()
                            .unwrap_or_else(|| module.to_string());
                        fir.symbol_modules
                            .insert(canonical.clone(), module_name.clone());
                        fir.symbol_modules.insert(alias_name, module_name);
                    }
                }
            }
        } else {
            let module = &path;
            if let Some(mod_fir) = modules.get(module) {
                let alias_mod = alias.clone().unwrap_or_else(|| module.to_string());
                for (name, sym) in &mod_fir.symbols {
                    if let Some(def) = sym.def {
                        let canonical = format!("{module}::{name}");
                        let qualified = format!("{alias_mod}::{name}");
                        fir.symbols.insert(
                            canonical.clone(),
                            Symbol {
                                name: canonical.clone(),
                                sanitized: sym.sanitized,
                                def: Some(def),
                                alias_of: None,
                            },
                        );
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
                            .unwrap_or_else(|| module.to_string());
                        fir.symbol_modules
                            .insert(canonical.clone(), module_name.clone());
                        fir.symbol_modules.insert(qualified, module_name);
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

#[derive(Serialize, Deserialize)]
struct CachedFile {
    hash: String,
    module: String,
    ir: FileIR,
}

#[derive(Default, Serialize, Deserialize)]
struct CacheData {
    files: HashMap<String, CachedFile>,
}

pub fn parse_rust_project_uncached(root: &Path) -> Result<HashMap<String, FileIR>> {
    let mut modules = HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let content = fs::read_to_string(&path)?;
                let mut fir = FileIR::new(path.to_string_lossy().into(), "rust".into());
                if let Err(e) = parse_rust(&content, &mut fir) {
                    tracing::warn!("{e}");
                    fir.symbol_types
                        .insert("__parse_error__".into(), SymbolKind::Special);
                }
                let rel = path.strip_prefix(root).unwrap_or(&path);
                let mut comps: Vec<String> = rel
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect();
                if let Some(last) = comps.last_mut() {
                    if last.ends_with(".rs") {
                        *last = last.trim_end_matches(".rs").to_string();
                    }
                    if last == "mod" {
                        comps.pop();
                    }
                }
                let module = comps.join("::");
                let names: Vec<String> = fir.symbols.keys().cloned().collect();
                for name in names {
                    if fir.symbols.get(&name).and_then(|s| s.def).is_some() {
                        fir.symbol_modules.insert(name, module.clone());
                    }
                }
                modules.insert(module, fir);
            }
        }
    }
    let cloned = modules.clone();
    for fir in modules.values_mut() {
        link_imports(fir, &cloned);
    }
    Ok(modules)
}

pub fn parse_rust_project(
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
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let canonical = path.to_string_lossy().into_owned();
                seen.insert(canonical.clone());
                let content = fs::read_to_string(&path)?;
                let h = blake3::hash(content.as_bytes()).to_hex().to_string();
                if let Some(c) = cache.files.get(&canonical) {
                    if c.hash == h {
                        if let Some(m) = metrics.as_deref_mut() {
                            m.cache_hits += 1;
                        }
                        modules.insert(c.module.clone(), c.ir.clone());
                        continue;
                    }
                }
                let mut fir = FileIR::new(canonical.clone(), "rust".into());
                if let Err(e) = parse_rust(&content, &mut fir) {
                    if let Some(m) = metrics.as_deref_mut() {
                        m.parse_errors += 1;
                    }
                    tracing::warn!("{e}");
                    fir.symbol_types
                        .insert("__parse_error__".into(), SymbolKind::Special);
                } else if let Some(m) = metrics.as_deref_mut() {
                    m.files_parsed += 1;
                }
                let rel = path.strip_prefix(root).unwrap_or(&path);
                let mut comps: Vec<String> = rel
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect();
                if let Some(last) = comps.last_mut() {
                    if last.ends_with(".rs") {
                        *last = last.trim_end_matches(".rs").to_string();
                    }
                    if last == "mod" {
                        comps.pop();
                    }
                }
                let module = comps.join("::");
                let names: Vec<String> = fir.symbols.keys().cloned().collect();
                for name in names {
                    if fir.symbols.get(&name).and_then(|s| s.def).is_some() {
                        fir.symbol_modules.insert(name, module.clone());
                    }
                }
                cache.files.insert(
                    canonical,
                    CachedFile {
                        hash: h,
                        module: module.clone(),
                        ir: fir.clone(),
                    },
                );
                modules.insert(module, fir);
                parsed += 1;
            }
        }
    }
    cache.files.retain(|k, _| seen.contains(k));
    let cloned = modules.clone();
    for fir in modules.values_mut() {
        link_imports(fir, &cloned);
    }
    if let Ok(s) = serde_json::to_string(&cache) {
        let _ = fs::write(cache_path, s);
    }
    Ok((modules, parsed))
}
