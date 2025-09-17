//! Maturity Level L2 Tests for Python Parser
//!
//! This module contains tests that verify the parser can:
//! - Resolve symbol names correctly (imports, aliases, namespaces)
//! - Handle complex import statements (relative, wildcard)
//! - Detect and handle import cycles
//! - Understand qualified names and language-specific qualifiers
//!
//! See docs/architecture/crates/parsers/maturity.md for detailed maturity criteria.

use crate::languages::python::parse_python;
use ir::{DFNodeKind, FileIR, Symbol};
use std::collections::{HashMap, HashSet};

/// Helper function to parse Python code snippets for testing
fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

/// Helper function to parse Python code with a specific file path for relative imports
fn parse_snippet_with_path(code: &str, path: &str) -> FileIR {
    let mut fir = FileIR::new(path.into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

/// Helper function to resolve aliases through the symbol table
///
/// This function follows the alias chain to find the canonical name,
/// handling circular references gracefully.
fn resolve_alias(name: &str, symbols: &HashMap<String, Symbol>) -> String {
    let mut name = name;
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(name.to_string());
    let mut last_alias = None;
    while let Some(sym) = symbols.get(name) {
        if let Some(next) = sym.alias_of.as_deref() {
            last_alias = Some(next.to_string());
            if !visited.insert(next.to_string()) {
                break;
            }
            name = next;
        } else {
            break;
        }
    }
    last_alias.unwrap_or_else(|| name.to_string())
}

/// Test complex import statements including wildcard imports
///
/// This test verifies handling of:
/// - Wildcard imports (from .mod import *)
/// - Complex import statements
/// - Proper IR node generation for imports
#[test]
fn l2_imports_compuestos() {
    let code = "from module import *\n";
    let fir = parse_snippet(code);
    assert!(
        fir.nodes.iter().any(|n| n.path == "import_from.module.*"),
        "Star imports should appear in IR as import_from.module.* nodes",
    );
}

// Incomplete star import yields no IR.
#[test]
fn l2_imports_compuestos_invalido() {
    let code = "from module import\n";
    let fir = parse_snippet(code);
    assert!(
        !fir.nodes.iter().any(|n| n.path == "import_from.module.*"),
        "invalid star import should not create IR node",
    );
}

// Cyclic aliasing should still track definitions.
#[test]
fn resolve_alias_handles_cycles() {
    let code = "import source as a\nimport a as source\nx = a()\n";
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("missing data flow graph");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "x" && matches!(n.kind, DFNodeKind::Def)));
}

// Alias cycles with normal names resolve calls.
#[test]
fn resolve_alias_cycle_with_non_special_name() {
    let code = "import foo as bar\nimport bar as foo\nbar()\n";
    let fir = parse_snippet(code);
    assert!(fir.nodes.iter().any(|n| n.path == "call.bar"));
}

// Import alias should record a symbol.
#[test]
fn import_alias_creates_symbol() {
    let code = "import pkg.mod as m\n";
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("m").expect("missing symbol for m");
    assert_eq!(sym.alias_of.as_deref(), Some("pkg.mod"));
}

// Broken alias should not resolve call path.
#[test]
fn l2_aliasing_y_canonicalizacion_invalido() {
    let code = "from pkg.mod import Foo as\nFoo()\n";
    let fir = parse_snippet(code);
    assert!(!fir.nodes.iter().any(|n| n.path == "call.pkg.mod.Foo"));
}

// from-import adds a canonical symbol.
#[test]
fn import_from_creates_symbol() {
    let code = "from pkg.mod import Foo\n";
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("Foo").expect("missing symbol for Foo");
    assert_eq!(sym.alias_of.as_deref(), Some("pkg.mod.Foo"));
}

// Alias resolution should produce canonical call path.
#[test]
fn l2_aliasing_y_canonicalizacion() {
    let code = "from pkg.mod import Foo\nFoo()\n";
    let fir = parse_snippet(code);
    assert_eq!(resolve_alias("Foo", &fir.symbols), "pkg.mod.Foo");
    assert!(fir.nodes.iter().any(|n| n.path == "call.pkg.mod.Foo"));
}

// Relative import should create a symbol.
#[test]
fn relative_from_import_creates_symbol() {
    let code = "from . import Foo\n";
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("Foo").expect("missing symbol for Foo");
    assert_eq!(sym.alias_of.as_deref(), Some("Foo"));
}

// Aliased relative import resolves call.
#[test]
fn relative_from_import_alias_resolves_call() {
    let code = "from . import Foo as Bar\nBar()\n";
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("Bar").expect("missing symbol for Bar");
    assert_eq!(sym.alias_of.as_deref(), Some("Foo"));
    assert!(fir.nodes.iter().any(|n| n.path == "call.Foo"));
}

// Invalid relative alias should create no symbols.
#[test]
fn invalid_relative_from_import_alias_does_not_create_symbol() {
    let code = "from . import Foo as\n";
    let fir = parse_snippet(code);
    assert!(!fir.symbols.contains_key("Foo"));
    assert!(!fir.symbols.contains_key("Bar"));
}

// Malformed from-import adds no symbols.
#[test]
fn invalid_from_import_does_not_create_symbol() {
    let code = "from pkg.mod import\n";
    let fir = parse_snippet(code);
    assert!(!fir.symbols.contains_key("Foo"));
}

// Module alias should resolve in call path.
#[test]
fn resolves_module_alias_in_call() {
    let code = "import pkg.mod as m\nm.func()\n";
    let fir = parse_snippet(code);
    assert!(fir.nodes.iter().any(|n| n.path == "call.pkg.mod.func"));
}

// Function alias should resolve in call path.
#[test]
fn resolves_function_alias_in_call() {
    let code = "from pkg.mod import func as f\nf()\n";
    let fir = parse_snippet(code);
    assert!(fir.nodes.iter().any(|n| n.path == "call.pkg.mod.func"));
}

// Complex package aliases should resolve fully.
#[test]
fn resolves_cryptography_ecb_mode_call() {
    let code = "from cryptography.hazmat.primitives.ciphers.modes import ECB\nECB(iv)\n";
    let fir = parse_snippet(code);
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "call.cryptography.hazmat.primitives.ciphers.modes.ECB"));
}

#[test]
fn does_not_normalize_other_modes_to_ecb() {
    let code = "from cryptography.hazmat.primitives.ciphers.modes import CBC\nCBC(iv)\n";
    let fir = parse_snippet(code);
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "call.cryptography.hazmat.primitives.ciphers.modes.CBC"));
    assert!(!fir
        .nodes
        .iter()
        .any(|n| n.path == "call.cryptography.hazmat.primitives.ciphers.modes.ECB"));
}

#[test]
fn resolves_single_dot_relative_import() {
    let code = "from .sub import Foo\n";
    let fir = parse_snippet_with_path(code, "pkg/sub/module.py");
    let sym = fir.symbols.get("Foo").expect("missing symbol for Foo");
    assert_eq!(sym.alias_of.as_deref(), Some("pkg.sub.Foo"));
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "import_from.pkg.sub.Foo"));
}

#[test]
fn resolves_double_dot_relative_import() {
    let code = "from ..pkg.mod import Bar\n";
    let fir = parse_snippet_with_path(code, "pkg/sub/module.py");
    let sym = fir.symbols.get("Bar").expect("missing symbol for Bar");
    assert_eq!(sym.alias_of.as_deref(), Some("pkg.mod.Bar"));
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "import_from.pkg.mod.Bar"));
}

#[test]
fn invalid_relative_import_creates_no_symbol() {
    let code = "from .sub import\n";
    let fir = parse_snippet_with_path(code, "pkg/sub/module.py");
    assert!(fir.symbols.is_empty());
    assert!(fir.nodes.iter().all(|n| !n.path.starts_with("import_from")));
}
