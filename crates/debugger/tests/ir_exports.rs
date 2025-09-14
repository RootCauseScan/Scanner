use engine::{build_cfg, parse_file_with_events};
use parsers::build_dfg;
use std::path::Path;

fn load_fir() -> ir::FileIR {
    parse_file_with_events(
        Path::new("../../examples/fixtures/python/py.no-eval/bad.py"),
        None,
        None,
    )
    .unwrap()
    .unwrap()
}

#[test]
fn ast_to_dot() {
    let fir = load_fir();
    let ast = fir.ast.expect("ast");
    insta::assert_snapshot!(ast.to_dot());
}

#[test]
fn ast_to_json() {
    let fir = load_fir();
    let ast = fir.ast.expect("ast");
    insta::assert_snapshot!(ast.to_json().unwrap());
}

#[test]
fn cfg_to_dot() {
    let fir = load_fir();
    let cfg = build_cfg(&fir).expect("cfg");
    insta::assert_snapshot!(cfg.to_dot());
}

#[test]
fn cfg_to_json() {
    let fir = load_fir();
    let cfg = build_cfg(&fir).expect("cfg");
    insta::assert_snapshot!(cfg.to_json().unwrap());
}

#[test]
fn ssa_to_dot() {
    let mut fir = load_fir();
    build_dfg(&mut fir).unwrap();
    let dfg = fir.dfg.expect("dfg");
    insta::assert_snapshot!(dfg.to_dot());
}

#[test]
fn ssa_to_json() {
    let mut fir = load_fir();
    build_dfg(&mut fir).unwrap();
    let dfg = fir.dfg.expect("dfg");
    insta::assert_snapshot!(dfg.to_json().unwrap());
}
