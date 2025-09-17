use crate::catalog as catalog_module;
use ir::{FileIR, Symbol, SymbolKind};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportKind {
    Normal,
    Static,
    Wildcard,
    StaticWildcard,
}

impl ImportKind {
    fn from_str(kind: &str) -> Option<Self> {
        match kind {
            "normal" => Some(ImportKind::Normal),
            "static" => Some(ImportKind::Static),
            "wildcard" => Some(ImportKind::Wildcard),
            "static_wildcard" => Some(ImportKind::StaticWildcard),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct ImportAction {
    alias: String,
    target: String,
    kind: ImportKind,
}

fn is_symbol_sanitized(snapshot: &HashMap<String, FileIR>, full: &str) -> bool {
    if catalog_module::is_sanitizer("java", full) {
        return true;
    }
    if let Some((module_name, member)) = full.rsplit_once('.') {
        if let Some(target) = snapshot.get(module_name) {
            if let Some(sym) = target.symbols.get(member) {
                if sym.sanitized {
                    return true;
                }
            }
            if matches!(target.symbol_types.get(member), Some(SymbolKind::Sanitizer)) {
                return true;
            }
        }
    }
    false
}

fn collect_static_members(target: &FileIR) -> Vec<String> {
    target
        .nodes
        .iter()
        .filter_map(|node| node.path.strip_prefix("function.").map(|s| s.to_string()))
        .collect()
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
                    if let Some(node) = dfg.nodes.get_mut(dst) {
                        if matches!(node.kind, ir::DFNodeKind::Assign) && node.branch.is_none() {
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

pub fn link_imports(modules: &mut HashMap<String, FileIR>) {
    if modules.is_empty() {
        return;
    }
    let snapshot: HashMap<String, FileIR> = modules
        .iter()
        .map(|(name, fir)| (name.clone(), fir.clone()))
        .collect();
    let module_names: Vec<String> = snapshot.keys().cloned().collect();

    for module_name in module_names {
        let Some(fir_snapshot) = snapshot.get(&module_name) else {
            continue;
        };
        let import_entries: Vec<(String, String, ImportKind)> = fir_snapshot
            .symbol_scopes
            .iter()
            .filter_map(|(key, value)| {
                value
                    .strip_prefix("import|")?
                    .split_once('|')
                    .and_then(|(kind, path)| {
                        ImportKind::from_str(kind).map(|k| (key.clone(), path.to_string(), k))
                    })
            })
            .collect();

        let mut actions: Vec<ImportAction> = Vec::new();
        let mut sanitized_aliases: Vec<String> = Vec::new();

        for (key, path, kind) in import_entries {
            match kind {
                ImportKind::Normal => {
                    actions.push(ImportAction {
                        alias: key.clone(),
                        target: path.clone(),
                        kind: ImportKind::Normal,
                    });
                }
                ImportKind::Static => {
                    actions.push(ImportAction {
                        alias: key.clone(),
                        target: path.clone(),
                        kind: ImportKind::Static,
                    });
                    if is_symbol_sanitized(&snapshot, &path) && !sanitized_aliases.contains(&key) {
                        sanitized_aliases.push(key.clone());
                    }
                }
                ImportKind::Wildcard => {
                    let base = path.trim_end_matches(".*");
                    let prefix = format!("{base}.");
                    for target_module in snapshot.keys().filter(|name| name.starts_with(&prefix)) {
                        let remainder = &target_module[prefix.len()..];
                        if remainder.contains('.') {
                            continue;
                        }
                        let alias = remainder.to_string();
                        actions.push(ImportAction {
                            alias,
                            target: target_module.clone(),
                            kind: ImportKind::Normal,
                        });
                    }
                }
                ImportKind::StaticWildcard => {
                    let base_module = path.trim_end_matches(".*");
                    if let Some(target) = snapshot.get(base_module) {
                        for member in collect_static_members(target) {
                            let full = format!("{base_module}.{member}");
                            actions.push(ImportAction {
                                alias: member.clone(),
                                target: full.clone(),
                                kind: ImportKind::Static,
                            });
                            if is_symbol_sanitized(&snapshot, &full)
                                && !sanitized_aliases.contains(&member)
                            {
                                sanitized_aliases.push(member);
                            }
                        }
                    }
                }
            }
        }

        if actions.is_empty() && sanitized_aliases.is_empty() {
            continue;
        }

        if let Some(fir_mut) = modules.get_mut(&module_name) {
            for action in actions {
                let target = action.target.clone();
                let alias = action.alias.clone();
                let entry = fir_mut.symbols.entry(alias.clone()).or_insert(Symbol {
                    name: alias.clone(),
                    sanitized: false,
                    def: None,
                    alias_of: Some(target.clone()),
                });
                if entry.alias_of.is_none() {
                    entry.alias_of = Some(target.clone());
                }
                match action.kind {
                    ImportKind::Static | ImportKind::StaticWildcard => {
                        if let Some((module_path, _)) = target.rsplit_once('.') {
                            fir_mut
                                .symbol_modules
                                .insert(alias.clone(), module_path.to_string());
                        }
                        fir_mut
                            .symbol_scopes
                            .insert(alias.clone(), format!("import|static|{target}"));
                    }
                    _ => {
                        fir_mut.symbol_modules.insert(alias.clone(), target.clone());
                        fir_mut
                            .symbol_scopes
                            .insert(alias.clone(), format!("import|normal|{target}"));
                    }
                }
            }

            for alias in sanitized_aliases {
                if let Some(sym) = fir_mut.symbols.get_mut(&alias) {
                    sym.sanitized = true;
                    if let Some(target) = sym.alias_of.clone() {
                        fir_mut.symbol_types.insert(target, SymbolKind::Sanitizer);
                    }
                }
                fir_mut
                    .symbol_types
                    .insert(alias.clone(), SymbolKind::Sanitizer);
            }

            propagate_sanitized(fir_mut);
        }
    }
}
