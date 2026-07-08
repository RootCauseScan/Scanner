use crate::catalog as catalog_module;
use ir::{DFNodeKind, FileIR, Symbol, SymbolKind};
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
    let Some(dfg) = &mut fir.dfg else { return };

    // Build stable-id → vector-index map (dfg.nodes[id] is WRONG: id is a hash, not an index)
    let id_to_idx: HashMap<usize, usize> = dfg.nodes.iter().enumerate()
        .map(|(i, n)| (n.id, i))
        .collect();

    // Build outgoing-edge adjacency for O(E) propagation instead of O(V*E)
    let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
    for &(src, dst) in &dfg.edges {
        adj.entry(src).or_default().push(dst);
    }

    let mut queue: Vec<usize> = dfg.nodes.iter()
        .filter(|n| n.sanitized)
        .map(|n| n.id)
        .collect();
    let mut visited = HashSet::new();

    while let Some(id) = queue.pop() {
        if !visited.insert(id) {
            continue;
        }
        let Some(dsts) = adj.get(&id) else { continue };
        let dsts: Vec<usize> = dsts.clone();
        for dst in dsts {
            let Some(&idx) = id_to_idx.get(&dst) else { continue };
            let skip = {
                let node = &dfg.nodes[idx];
                (matches!(node.kind, ir::DFNodeKind::Assign) && node.branch.is_none())
                    || node.sanitized
            };
            if skip {
                continue;
            }
            dfg.nodes[idx].sanitized = true;
            let name = dfg.nodes[idx].name.clone();
            let canonical = resolve_alias(&name, &fir.symbols);
            if let Some(sym) = fir.symbols.get_mut(&canonical) {
                sym.sanitized = true;
            } else if let Some(sym) = fir.symbols.get_mut(&name) {
                sym.sanitized = true;
            }
            queue.push(dst);
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
        let mut sanitized_aliases: HashSet<String> = HashSet::new();

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
                    if is_symbol_sanitized(&snapshot, &path) {
                        sanitized_aliases.insert(key.clone());
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
                            if is_symbol_sanitized(&snapshot, &full) {
                                sanitized_aliases.insert(member);
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
                if entry.def.is_none() {
                    if let Some((module_name, member)) = target.rsplit_once('.') {
                        if let Some(target_fir) = snapshot.get(module_name) {
                            if let Some(member_sym) = target_fir.symbols.get(member) {
                                entry.def = member_sym.def;
                                if member_sym.sanitized {
                                    entry.sanitized = true;
                                }
                                fir_mut.symbols.entry(target.clone()).or_insert(Symbol {
                                    name: target.clone(),
                                    sanitized: member_sym.sanitized,
                                    def: member_sym.def,
                                    alias_of: None,
                                });
                            }
                        }
                    }
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

            if let Some(dfg) = &mut fir_mut.dfg {
                // Build id→idx map once; dfg.nodes[id] is wrong since id is a hash, not an index
                let id_to_idx: HashMap<usize, usize> = dfg.nodes.iter().enumerate()
                    .map(|(i, n)| (n.id, i))
                    .collect();
                // Build edge set for O(1) dedup instead of two O(n) scans per node
                let mut edge_set: HashSet<(usize, usize)> = dfg.edges.iter().cloned().collect();
                let nodes_snapshot = dfg.nodes.clone();
                for node in nodes_snapshot {
                    let canonical = resolve_alias(&node.name, &fir_mut.symbols);
                    if let Some(def_id) = fir_mut.symbols.get(&canonical).and_then(|s| s.def) {
                        let should_link = match node.kind {
                            DFNodeKind::Use => true,
                            DFNodeKind::Def => fir_mut
                                .symbols
                                .get(&node.name)
                                .and_then(|s| s.alias_of.as_ref())
                                .is_some(),
                            _ => false,
                        };
                        if should_link && edge_set.insert((def_id, node.id)) {
                            dfg.edges.push((def_id, node.id));
                        }
                        if should_link {
                            if let Some(sym) = fir_mut.symbols.get(&canonical) {
                                if sym.sanitized {
                                    if let Some(&idx) = id_to_idx.get(&node.id) {
                                        dfg.nodes[idx].sanitized = true;
                                    }
                                    if let Some(local_sym) = fir_mut.symbols.get_mut(&node.name) {
                                        local_sym.sanitized = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            propagate_sanitized(fir_mut);
        }
    }
}
