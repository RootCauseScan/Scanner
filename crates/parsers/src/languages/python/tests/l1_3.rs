//! Ensures non-@timeit functions are not treated as special.

use crate::languages::python::parse_python;
use ir::{FileIR, SymbolKind};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

#[test]
fn ignores_normal_function() {
    let code = "def regular():\n    pass\n";
    let fir = parse_snippet(code);
    assert!(!matches!(
        fir.symbol_types.get("regular"),
        Some(SymbolKind::Special)
    ));
}
