use crate::catalog;
use ir::{FileIR, SymbolKind};
use std::collections::HashSet;

pub(super) fn mark_symbol_type(fir: &mut FileIR, name: &str) {
    if catalog::is_source("rust", name) {
        fir.symbol_types
            .insert(name.to_string(), SymbolKind::Source);
    }
    if catalog::is_sink("rust", name) {
        fir.symbol_types.insert(name.to_string(), SymbolKind::Sink);
    }
    if catalog::is_sanitizer("rust", name) {
        fir.symbol_types
            .insert(name.to_string(), SymbolKind::Sanitizer);
    }
}

pub(super) fn mark_sanitized_aliases(fir: &mut FileIR, name: &str) {
    let mut stack = vec![name.to_string()];
    let mut visited = HashSet::new();
    while let Some(cur) = stack.pop() {
        if !visited.insert(cur.clone()) {
            continue;
        }
        if let Some(sym) = fir.symbols.get_mut(&cur) {
            sym.sanitized = true;
        }
        if let Some(dfg) = &mut fir.dfg {
            for node in &mut dfg.nodes {
                if node.name == cur {
                    node.sanitized = true;
                }
            }
        }
        let aliases: Vec<String> = fir
            .symbols
            .iter()
            .filter_map(|(k, s)| {
                if s.alias_of.as_deref() == Some(cur.as_str()) {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        stack.extend(aliases);
    }
}
