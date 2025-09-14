use anyhow::Result;
use ir::FileIR;

/// Ensure a data flow graph exists for supported languages.
pub fn build_dfg(file: &mut FileIR) -> Result<()> {
    if file.dfg.is_some() {
        return Ok(());
    }
    parsers::build_dfg(file)
}

/// Link two symbols by adding an edge from their definitions.
pub fn link_nodes(file: &mut FileIR, from: &str, to: &str) {
    if let Some(dfg) = &mut file.dfg {
        if let (Some(src), Some(dst)) = (
            file.symbols.get(from).and_then(|s| s.def),
            file.symbols.get(to).and_then(|s| s.def),
        ) {
            dfg.edges.push((src, dst));
        }
    }
}

/// Mark a symbol and its defining node as sanitized.
pub fn mark_sanitized(file: &mut FileIR, name: &str) {
    if let Some(sym) = file.symbols.get_mut(name) {
        sym.sanitized = true;
        if let Some(id) = sym.def {
            if let Some(dfg) = &mut file.dfg {
                if let Some(node) = dfg.nodes.iter_mut().find(|n| n.id == id) {
                    node.sanitized = true;
                }
            }
        }
    }
}
