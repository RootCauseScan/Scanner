//! Level 1 checks that we build a real AST and minimal IR with basic call canonicalization.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::languages::python::parse_python;
use ir::FileIR;

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

// Basic code should produce AST and key IR nodes.
#[test]
fn l1_ast_and_ir_minimos() {
    let code = "import os\nx = 1\nprint(x)\n";
    let fir = parse_snippet(code);
    assert!(fir.ast.is_some(), "expected AST");
    assert!(fir.nodes.iter().any(|n| n.path == "import.os"));
    let dfg = fir.dfg.as_ref().expect("dfg");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "x" && matches!(n.kind, ir::DFNodeKind::Def)));
    assert!(fir.nodes.iter().any(|n| n.path == "call.print"));
    assert!(fir
        .nodes
        .iter()
        .all(|n| n.meta.line > 0 && n.meta.column > 0));
}

// Invalid syntax yields no IR nodes.
#[test]
fn l1_ast_and_ir_minimos_invalido() {
    let code = "import\n";
    let fir = parse_snippet(code);
    assert!(fir.nodes.is_empty());
}

// Aliased imports resolve to canonical call paths.
#[test]
fn l1_canonicalizacion_basica() {
    let code = "import pkg.mod as m\nm.func()\n";
    let fir = parse_snippet(code);
    assert!(fir.nodes.iter().any(|n| n.path == "call.pkg.mod.func"));
}

// Broken aliasing should not resolve a call path.
#[test]
fn l1_canonicalizacion_basica_invalido() {
    let code = "import pkg.mod as\nm.func()\n";
    let fir = parse_snippet(code);
    assert!(!fir.nodes.iter().any(|n| n.path == "call.pkg.mod.func"));
}

// Entirely invalid code should produce no analysis artifacts.
#[test]
fn ignores_invalid_syntax() {
    let code = "def f(:\n  pass";
    let fir = parse_snippet(code);
    assert!(
        fir.nodes.is_empty(),
        "IR nodes should be empty for invalid code"
    );
    assert!(
        fir.dfg.is_none(),
        "DFG should not be produced for invalid code"
    );
    assert!(
        fir.symbols.is_empty(),
        "No symbols should be recorded for invalid code"
    );
}
