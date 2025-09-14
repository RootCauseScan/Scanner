use anyhow::{anyhow, Result};
use ir::{FileIR, SymbolKind};
use std::collections::HashMap;
use std::fs;
use std::path::{Component, Path};

mod ast;
mod dfg_builder;
pub(crate) mod symbol_table;
#[cfg(test)]
mod tests;
mod tokens;

fn walk_tolerant(node: tree_sitter::Node, src: &str, fir: &mut FileIR) {
    if node.is_error() {
        return;
    }
    if node.has_error() {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_tolerant(child, src, fir);
        }
    } else {
        tokens::walk_ir(node, src, fir);
    }
}

pub fn parse_python(content: &str, fir: &mut FileIR) -> Result<()> {
    if content.trim().is_empty() {
        return Err(anyhow!("empty python source"));
    }
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_python::language())
        .expect("load python grammar");
    let Some(tree) = parser.parse(content, None) else {
        tracing::warn!("failed to parse python source");
        fir.symbol_types
            .insert("__parse_error__".into(), SymbolKind::Special);
        return Ok(());
    };
    let root = tree.root_node();
    if root.has_error() {
        tracing::warn!("python source contains parse errors");
        walk_tolerant(root, content, fir);
        fir.symbol_types
            .insert("__parse_error__".into(), SymbolKind::Special);
        return Ok(());
    }
    tokens::walk_ir(root, content, fir);
    dfg_builder::build(root, content, fir);
    let file_ast = ast::build_ast(root, content, &fir.file_path);
    fir.ast = Some(file_ast);
    Ok(())
}

pub fn helper(content: &str, fir: &mut FileIR) -> Result<()> {
    parse_python(content, fir)
}

pub fn parse_python_project(root: &Path) -> Result<HashMap<String, FileIR>> {
    let mut modules = HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("py") {
                let content = fs::read_to_string(&path)?;
                let mut fir = FileIR::new(path.to_string_lossy().into(), "python".into());
                if let Err(e) = parse_python(&content, &mut fir) {
                    tracing::warn!("{e}");
                    continue;
                }
                let rel = path.strip_prefix(root).unwrap_or(&path);
                let mut comps: Vec<String> = rel
                    .components()
                    .filter_map(|c| match c {
                        Component::Normal(os) => Some(os.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect();
                if comps.last().map(|s| s == "__init__.py").unwrap_or(false) {
                    comps.pop();
                }
                if let Some(last) = comps.last_mut() {
                    if last.ends_with(".py") {
                        *last = last.trim_end_matches(".py").to_string();
                    }
                }
                let module = comps.join(".");
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
        symbol_table::link_imports(fir, &cloned);
    }
    Ok(modules)
}
