use crate::languages::python::symbol_table;
use ir::FileIR;
use std::collections::HashMap;

/// Build a data flow graph and propagate flow between
/// variables and function boundaries.
pub(crate) fn build(root: tree_sitter::Node, src: &str, fir: &mut FileIR) {
    let mut fn_ids = HashMap::new();
    let mut fn_params: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut fn_returns: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut call_args: Vec<(usize, usize, usize)> = Vec::new();
    let mut branch_stack: Vec<usize> = Vec::new();
    let mut branch_counter: usize = 0;
    symbol_table::build_dfg(
        root,
        src,
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
        for (src_id, callee, idx) in call_args {
            if let Some(params) = fn_params.get(&callee) {
                if let Some(&param_id) = params.get(idx) {
                    dfg.edges.push((src_id, param_id));
                }
            }
        }
        for (dest_id, callee) in dfg.call_returns.clone() {
            if let Some(rets) = fn_returns.get(&callee) {
                for &r in rets {
                    dfg.edges.push((r, dest_id));
                }
            }
        }
    }
}
