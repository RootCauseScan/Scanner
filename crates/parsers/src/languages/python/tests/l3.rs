//! Level 3 adds intra-procedural dataflow and a sanitizer catalog.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::{catalog, languages::python::parse_python};
use ir::{DFNodeKind, FileIR, SymbolKind};
use std::fs;
use std::path::Path;

fn parse_dfg_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.dfg")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "python".into());
    parse_python(&content, &mut fir).unwrap();
    fir
}

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

fn parse_insecure_fixture(dir: &str, file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python")
        .join(dir)
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "python".into());
    parse_python(&content, &mut fir).unwrap();
    fir
}

fn parse_sanitizer_fixture_with_types(file: &str, types: &[(&str, SymbolKind)]) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.sanitizers")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "python".into());
    for (name, kind) in types {
        fir.symbol_types.insert((*name).to_string(), kind.clone());
    }
    parse_python(&content, &mut fir).unwrap();
    fir
}

fn parse_sanitizer_fixture(file: &str) -> FileIR {
    parse_sanitizer_fixture_with_types(file, &[])
}

// Sanitizer catalog should mark data as clean and create def-use edge.
#[test]
fn l3_def_use_y_sanitizers_catalogo() {
    let fir = parse_sanitizer_fixture("alias.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let data_def = sym.def.expect("data def");
    let alias_def = fir
        .symbols
        .get("alias")
        .and_then(|s| s.def)
        .expect("alias def");
    assert!(dfg.edges.contains(&(data_def, alias_def)));
}

// Missing sanitizer leaves data unsanitized.
#[test]
fn l3_def_use_y_sanitizers_catalogo_invalido() {
    let fir = parse_sanitizer_fixture("bad.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
}

// Call graph should track caller to callee.
#[test]
fn l3_call_graph_directo() {
    let code = r#"
def callee(x):
    return x

def caller(y):
    return callee(y)
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    assert_eq!(dfg.calls.len(), 1);
}

// Without a function definition, no calls are recorded.
#[test]
fn l3_call_graph_directo_invalido() {
    let fir = parse_snippet("callee(1)\n");
    let dfg = fir.dfg.unwrap_or_default();
    assert!(dfg.calls.is_empty());
}

// Valid sample builds full DFG without calls.
#[test]
fn builds_dfg_for_good_example() {
    let fir = parse_dfg_fixture("good.py");
    let dfg = fir.dfg.expect("missing data flow graph for good example");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "result" && matches!(n.kind, DFNodeKind::Def)));
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "result" && matches!(n.kind, DFNodeKind::Use)));
    assert!(!dfg.edges.is_empty());
    assert!(dfg.calls.is_empty());
    assert!(dfg.call_returns.is_empty());
}

// Bad sample still produces DFG nodes and edges.
#[test]
fn builds_dfg_for_bad_example() {
    let fir = parse_dfg_fixture("bad.py");
    let dfg = fir.dfg.expect("missing data flow graph for bad example");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "result" && matches!(n.kind, DFNodeKind::Def)));
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "result" && matches!(n.kind, DFNodeKind::Use)));
    assert!(dfg.calls.is_empty());
    assert!(dfg.call_returns.is_empty());
}

// Function call and return edges are recorded.
#[test]
fn records_calls_and_returns() {
    let code = r#"def callee(x):
    return x

def caller(y):
    z = callee(y)
    return z
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("missing data flow graph");
    assert_eq!(dfg.calls.len(), 1);
    assert_eq!(dfg.call_returns.len(), 1);
}

// Function without return shouldn't create call edges.
#[test]
fn handles_functions_without_return() {
    let fir = parse_snippet("def noop():\n    pass\n");
    let dfg = fir.dfg.unwrap_or_default();
    assert!(dfg.calls.is_empty());
    assert!(dfg.call_returns.is_empty());
}

// Attributes and subscripts propagate dataflow.
#[test]
fn handles_attribute_and_subscript() {
    let fir = parse_dfg_fixture("attr_subscript.py");
    let dfg = fir.dfg.expect("missing data flow graph");

    let def_ids = |name: &str| {
        dfg.nodes
            .iter()
            .filter(|n| n.name == name && matches!(n.kind, DFNodeKind::Def))
            .map(|n| n.id)
            .collect::<Vec<_>>()
    };

    let obj_attr_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "obj.attr" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("obj.attr def");
    let arr_idx_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "arr[idx]" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("arr[idx] def");
    let val_id = *def_ids("val").last().unwrap();

    assert!(dfg.edges.contains(&(val_id, obj_attr_def)));
    assert!(dfg.edges.contains(&(val_id, arr_idx_def)));
    assert!(dfg.nodes.iter().all(|n| n.name != "attr"));
}

// Augmented assignment links right-hand source to target.
#[test]
fn augmented_assignment_creates_def_and_edge() {
    let fir = parse_snippet("y = 1\nx += y\n");
    let dfg = fir.dfg.expect("missing data flow graph");
    let x_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("missing x def");
    let y_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "y" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("missing y def");
    assert!(dfg.edges.contains(&(y_def, x_def)));
}

// Augmented assignment without source adds no edge.
#[test]
fn augmented_assignment_without_source_has_no_edge() {
    let fir = parse_snippet("x += y\n");
    let dfg = fir.dfg.expect("missing data flow graph");
    let x_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("missing x def");
    assert!(dfg.edges.iter().all(|(_, to)| *to != x_def));
}

// Catalog flags pickle.load as a sink.
#[test]
fn detects_pickle_load_call() {
    let bad = parse_insecure_fixture("py.pickle-load", "bad.py");
    assert!(bad.nodes.iter().any(|n| n.path == "call.pickle.load"));
    let good = parse_insecure_fixture("py.pickle-load", "good.py");
    assert!(!good.nodes.iter().any(|n| n.path == "call.pickle.load"));
}

// Catalog flags pickle.loads as a sink.
#[test]
fn detects_pickle_loads_call() {
    let bad = parse_insecure_fixture("py.pickle-loads", "bad.py");
    assert!(bad.nodes.iter().any(|n| n.path == "call.pickle.loads"));
    let good = parse_insecure_fixture("py.pickle-loads", "good.py");
    assert!(!good.nodes.iter().any(|n| n.path == "call.pickle.loads"));
}

// YAML load should be marked as a sink.
#[test]
fn detects_yaml_load_call() {
    let bad = parse_insecure_fixture("py.yaml-load", "bad.py");
    assert!(bad.nodes.iter().any(|n| n.path == "call.yaml.load"));
    let good = parse_insecure_fixture("py.yaml-load", "good.py");
    assert!(!good.nodes.iter().any(|n| n.path == "call.yaml.load"));
}

// Custom catalog entries connect source to sink.
#[test]
fn catalog_detects_custom_source_and_sink() {
    catalog::extend("python", &["custom_source"], &["custom_sink"], &[]);
    let fir = parse_insecure_fixture("py.catalog", "source_sink.py");
    let dfg = fir.dfg.expect("dfg");
    let data_def = fir
        .symbols
        .get("data")
        .and_then(|s| s.def)
        .expect("data def");
    let sink_use = dfg
        .nodes
        .iter()
        .find(|n| matches!(n.kind, DFNodeKind::Use) && n.name == "data")
        .expect("sink use");
    assert!(dfg.edges.contains(&(data_def, sink_use.id)));
}

// Custom catalog sanitizer marks data as clean.
#[test]
fn catalog_detects_custom_sanitizer() {
    catalog::extend(
        "python",
        &["custom_source"],
        &["custom_sink"],
        &["custom_clean"],
    );
    let fir = parse_insecure_fixture("py.catalog", "sanitizer.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let data_def = sym.def.expect("data def");
    assert!(dfg
        .nodes
        .iter()
        .find(|n| n.id == data_def)
        .map(|n| n.sanitized)
        .unwrap());
}

// Sanitizer on alias flows to original symbol.
#[test]
fn marks_sanitized_flow_from_alias() {
    let fir = parse_sanitizer_fixture("alias.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
}

// Alias assignment creates dataflow edge.
#[test]
fn builds_alias_edge() {
    let fir = parse_sanitizer_fixture("alias.py");
    let dfg = fir.dfg.expect("dfg");
    let data_def = fir
        .symbols
        .get("data")
        .and_then(|s| s.def)
        .expect("data def");
    let alias_def = fir
        .symbols
        .get("alias")
        .and_then(|s| s.def)
        .expect("alias def");
    assert!(dfg.edges.contains(&(data_def, alias_def)));
}

// Without sanitizer, data stays tainted.
#[test]
fn leaves_unsanitized_when_not_cleaned() {
    let fir = parse_sanitizer_fixture("bad.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
}

// Sanitizer flag reflects in DFG node.
#[test]
fn marks_dfg_node_as_sanitized() {
    let fir = parse_sanitizer_fixture("alias.py");
    let dfg = fir.dfg.expect("dfg");
    let data_def = fir
        .symbols
        .get("data")
        .and_then(|s| s.def)
        .expect("data def");
    assert!(dfg
        .nodes
        .iter()
        .find(|n| n.id == data_def)
        .map(|n| n.sanitized)
        .unwrap());
}

// Alias chains resolve before edge creation.
#[test]
fn resolves_alias_before_connecting_nodes() {
    let fir = parse_sanitizer_fixture("alias_chain.py");
    let dfg = fir.dfg.expect("dfg");
    let data_def = fir
        .symbols
        .get("data")
        .and_then(|s| s.def)
        .expect("data def");
    let alias_def = fir
        .symbols
        .get("alias")
        .and_then(|s| s.def)
        .expect("alias def");
    let copy_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "copy")
        .map(|n| n.id)
        .expect("copy node");
    assert!(dfg.edges.contains(&(data_def, alias_def)));
    assert!(dfg.edges.contains(&(data_def, copy_def)));
    assert!(dfg
        .nodes
        .iter()
        .find(|n| n.id == data_def)
        .map(|n| n.sanitized)
        .unwrap());
}

// html.escape should sanitize data.
#[test]
fn marks_html_escape_as_sanitizer() {
    let fir = parse_sanitizer_fixture("html_escape.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
}

// html.unescape is not a sanitizer.
#[test]
fn ignores_html_unescape() {
    let fir = parse_sanitizer_fixture("html_unescape.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
}

// bleach.clean acts as sanitizer.
#[test]
fn marks_bleach_clean_as_sanitizer() {
    let fir = parse_sanitizer_fixture("bleach_clean.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
}

// bleach.linkify is not a sanitizer.
#[test]
fn ignores_bleach_linkify() {
    let fir = parse_sanitizer_fixture("bleach_linkify.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
}

// Custom rule-provided sanitizer is honored.
#[test]
fn allows_custom_rule_sanitizer() {
    let fir = parse_sanitizer_fixture_with_types(
        "custom.py",
        [("custom_filter", SymbolKind::Sanitizer)].as_slice(),
    );
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
}

// Sanitizer resolves through module alias.
#[test]
fn marks_html_escape_via_module_alias() {
    let fir = parse_sanitizer_fixture("module_alias.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
}

// Non-sanitizer stays tainted even via alias.
#[test]
fn ignores_html_unescape_via_module_alias() {
    let fir = parse_sanitizer_fixture("module_alias_bad.py");
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
}
