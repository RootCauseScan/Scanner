//! Tests that functions decorated with @timeit are marked as special.

use crate::languages::python::parse_python;
use ir::{FileIR, SymbolKind};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

#[test]
fn marks_timeit_function_as_special() {
    let code = "@timeit\ndef timed():\n    pass\n";
    let fir = parse_snippet(code);
    assert!(matches!(
        fir.symbol_types.get("timed"),
        Some(SymbolKind::Special)
    ));
}
