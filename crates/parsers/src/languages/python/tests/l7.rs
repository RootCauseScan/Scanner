//! Maturity Level L7 Tests for Python Parser
//!
//! This module contains tests that verify the parser can handle real-world projects with:
//! - Multi-file/project analysis with real unit resolution
//! - Incremental analysis/cache/parallelism
//! - Error tolerance (does not crash on faulty files)
//! - Reproducible reporting (stable IDs, correct positions)
//! - Internal metrics and robustness
//!
//! See docs/architecture/crates/parsers/maturity.md for detailed maturity criteria.

use crate::catalog;
use crate::languages::python::{parse_python, parse_python_project};
use ir::{DFNodeKind, FileIR, SymbolKind};
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(prefix: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir();
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = base.join(format!("{prefix}{uniq}"));
    std::fs::create_dir(&dir).unwrap();
    dir
}

#[test]
fn l7_multi_archivo() {
    catalog::extend("python", &["source"], &["sink"], &[]);
    let dir = temp_dir("pyproj_");
    let pkg = dir.join("pkg");
    std::fs::create_dir(&pkg).unwrap();
    std::fs::write(pkg.join("__init__.py"), "").unwrap();
    std::fs::write(pkg.join("mod_a.py"), "user_input = source()\n").unwrap();
    std::fs::write(
        dir.join("main.py"),
        "from pkg import mod_a as m\n sink(m.user_input)\n",
    )
    .unwrap();
    let project = parse_python_project(&dir).unwrap();
    let main = project.get("main").unwrap();
    let mod_a = project.get("pkg.mod_a").unwrap();
    let def_id = mod_a
        .dfg
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "user_input" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .unwrap();
    let use_id = main
        .dfg
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .find(|n| n.name == "m.user_input" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .unwrap();
    assert!(main.dfg.as_ref().unwrap().edges.contains(&(def_id, use_id)));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn l7_importa_modulo_inexistente() {
    let dir = temp_dir("pyproj_bad_");
    std::fs::write(dir.join("main.py"), "from pkg import missing\n").unwrap();
    let project = parse_python_project(&dir).unwrap();
    let main = project.get("main").unwrap();
    let edges = main.dfg.as_ref().map(|d| d.edges.len()).unwrap_or(0);
    assert_eq!(edges, 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn l7_ids_estables() {
    use crate::languages::python::parse_python;
    use ir::{DFNodeKind, FileIR};

    let code = "user_input = source()\n";
    let mut fir1 = FileIR::new("a.py".into(), "python".into());
    parse_python(code, &mut fir1).unwrap();
    let mut fir2 = FileIR::new("a.py".into(), "python".into());
    parse_python(code, &mut fir2).unwrap();

    let def1 = fir1
        .dfg
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .find(|n| n.name == "user_input" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .unwrap();
    let def2 = fir2
        .dfg
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .find(|n| n.name == "user_input" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .unwrap();
    assert_eq!(def1, def2);

    let ir1 = fir1
        .nodes
        .iter()
        .find(|n| n.path == "call.source")
        .map(|n| n.id)
        .unwrap();
    let ir2 = fir2
        .nodes
        .iter()
        .find(|n| n.path == "call.source")
        .map(|n| n.id)
        .unwrap();
    assert_eq!(ir1, ir2);

    let code2 = "\nuser_input = source()\n";
    let mut fir3 = FileIR::new("a.py".into(), "python".into());
    parse_python(code2, &mut fir3).unwrap();
    let def3 = fir3
        .dfg
        .as_ref()
        .unwrap()
        .nodes
        .iter()
        .find(|n| n.name == "user_input" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .unwrap();
    assert_ne!(def1, def3);
    let ir3 = fir3
        .nodes
        .iter()
        .find(|n| n.path == "call.source")
        .map(|n| n.id)
        .unwrap();
    assert_ne!(ir1, ir3);
}

/// Test project-level robustness with mixed good and bad files
///
/// This test verifies that the parser can:
/// - Handle projects with both valid and invalid files
/// - Continue analysis despite individual file failures
/// - Mark parse errors appropriately in the symbol table
/// - Maintain project integrity when some files are malformed
#[test]
fn l7_robustez_proyecto() {
    let dir = temp_dir("pyrob_");
    std::fs::write(dir.join("good.py"), "a = 1\n").unwrap();
    std::fs::write(dir.join("bad.py"), "def broken(:\n").unwrap();
    std::fs::write(dir.join("other.py"), "b = 2\n").unwrap();

    let project = parse_python_project(&dir).unwrap();

    // Good file should parse successfully
    let good = project.get("good").unwrap();
    assert!(
        !good.symbol_types.contains_key("__parse_error__"),
        "Valid files should not have parse errors"
    );

    // Bad file should be marked with parse error
    let bad = project.get("bad").unwrap();
    assert_eq!(
        bad.symbol_types.get("__parse_error__"),
        Some(&SymbolKind::Special),
        "Invalid files should be marked with parse error symbol"
    );

    // Other valid file should also parse successfully
    let other = project.get("other").unwrap();
    assert!(
        !other.symbol_types.contains_key("__parse_error__"),
        "Other valid files should not have parse errors"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

/// Test that empty files are handled gracefully
///
/// This test verifies that the parser:
/// - Handles empty files appropriately
/// - Returns meaningful errors for empty content
/// - Doesn't crash on edge cases
#[test]
fn l7_archivo_vacio_err() {
    let mut fir = FileIR::new("empty.py".into(), "python".into());
    let res = parse_python("", &mut fir);
    assert!(res.is_err(), "Empty files should produce parse errors");
}
