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

/// Assign `block_id` to each DFG node based on line-range overlap with CFG blocks.
/// Requires both `file.dfg` and `file.cfg` to be populated.
pub fn link_cfg_to_dfg(file: &mut FileIR) {
    let block_ranges: Vec<(usize, usize, usize)> = match &file.cfg {
        Some(cfg) => cfg
            .blocks
            .iter()
            .filter(|b| b.line_start > 0)
            .map(|b| (b.id, b.line_start, b.line_end))
            .collect(),
        None => return,
    };
    if let Some(dfg) = &mut file.dfg {
        for node in &mut dfg.nodes {
            if node.line == 0 {
                continue;
            }
            node.block_id = block_ranges
                .iter()
                .find(|&&(_, ls, le)| ls <= node.line && node.line <= le)
                .map(|&(id, _, _)| id);
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
