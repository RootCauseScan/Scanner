use ir::{DFNodeKind, FileIR};
use parsers::languages::{python::parse_python, rust::parse_rust};

#[test]
fn python_match_dfg_branches() {
    let code = r#"

def main(cond, data):
    match cond:
        case 0:
            data = sanitize(data)
        case _:
            data = source()
    sink(data)
"#;
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let assigns: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Assign))
        .collect();
    assert!(assigns.iter().all(|n| n.branch.is_some()));
}

#[test]
fn rust_match_branch_node() {
    let code = r#"
fn main(cond: i32) {
    let mut data = source();
    match cond {
        0 => { data = sanitize(data); }
        _ => { data = source(); }
    }
    sink(data);
}
"#;
    let mut fir = FileIR::new("<mem>".into(), "rust".into());
    parse_rust(code, &mut fir).unwrap();
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "match" && matches!(n.kind, DFNodeKind::Branch)));
}
