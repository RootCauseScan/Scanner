//! Level 2 focuses on resolving aliases into canonical names.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_php;
use ir::{FileIR, Symbol};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

fn parse_fixture(file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/php/php.aliasing")
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "php".into());
    parse_php(&content, &mut fir).expect("parse php fixture");
    fir
}

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "php".into());
    parse_php(code, &mut fir).expect("parse php snippet");
    fir
}

fn resolve_alias(name: &str, symbols: &HashMap<String, Symbol>) -> String {
    let mut name = name;
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(name.to_string());
    while let Some(sym) = symbols.get(name).and_then(|s| s.alias_of.as_deref()) {
        if !visited.insert(sym.to_string()) {
            break;
        }
        name = sym;
    }
    name.to_string()
}

// Sanitized variable propagates through alias.
#[test]
fn l2_aliasing_y_canonicalizacion() {
    let fir = parse_fixture("good.php");
    let sym = fir.symbols.get("b").expect("missing symbol for b");
    assert_eq!(resolve_alias("b", &fir.symbols), "a");
    assert!(sym.sanitized);
}

// Unsanitized data remains tainted through alias.
#[test]
fn l2_aliasing_y_canonicalizacion_invalido() {
    let fir = parse_fixture("bad.php");
    let sym = fir.symbols.get("b").expect("missing symbol for b");
    assert_eq!(resolve_alias("b", &fir.symbols), "_GET");
    assert!(!sym.sanitized);
}

// Alias chains resolve to original definition.
#[test]
fn resolves_alias_chain() {
    let code = "<?php\n$a = 1;\n$b = $a;\n$c = $b;\n";
    let fir = parse_snippet(code);
    assert_eq!(resolve_alias("c", &fir.symbols), "a");
}
