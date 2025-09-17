use crate::ParserMetrics;
use anyhow::{Context, Result};
use ir::{FileIR, SymbolKind};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Component, Path},
};

use super::{ast, dfg_builder, symbol_table, tokens};

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
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_java::language())
        .context("load java grammar")?;
    let Some(tree) = parser.parse(content, None) else {
        tracing::warn!("failed to parse java source: {}", fir.file_path);
        fir.symbol_types
            .insert("__parse_error__".into(), SymbolKind::Special);
        return Ok(());
    };
    let root = tree.root_node();
    let mut imports = HashMap::new();
    let mut wildcards = Vec::new();
    let has_errors = root.has_error() || root.is_error();

    if has_errors {
        tracing::warn!("java source contains parse errors: {}", fir.file_path);
        tokens::walk_ir_tolerant(root, content, fir, &mut imports, &mut wildcards);
        dfg_builder::build(root, content, fir, &imports, &wildcards);
    } else {
        tokens::walk_ir(root, content, fir, &mut imports, &mut wildcards);
        dfg_builder::build(root, content, fir, &imports, &wildcards);
    }

    let file_ast = ast::build_ast(root, content, &fir.file_path);
    fir.ast = Some(file_ast);

    if has_errors {
        fir.symbol_types
            .insert("__parse_error__".into(), SymbolKind::Special);
    }

    Ok(())
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
    symbol_table::link_imports(&mut modules);
    Ok(modules)
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
    let mut package_to_canonical: HashMap<String, String> = HashMap::new();
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
                        package_to_canonical.insert(c.package.clone(), canonical.clone());
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
                }
                let flagged_parse_error = fir.symbol_types.contains_key("__parse_error__");
                if let Some(m) = metrics.as_deref_mut() {
                    if flagged_parse_error {
                        m.parse_errors += 1;
                    } else {
                        m.files_parsed += 1;
                    }
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
                package_to_canonical.insert(package.clone(), canonical.clone());
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
    symbol_table::link_imports(&mut modules);
    for (package, canonical) in &package_to_canonical {
        if let Some(fir) = modules.get(package) {
            if let Some(entry) = cache.files.get_mut(canonical) {
                entry.package = package.clone();
                entry.ir = fir.clone();
            }
        }
    }
    cache.files.retain(|k, _| seen.contains(k));
    if let Ok(s) = serde_json::to_string(&cache) {
        let _ = fs::write(cache_path, s);
    }
    Ok((modules, parsed))
}
