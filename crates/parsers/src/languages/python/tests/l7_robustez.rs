use crate::languages::python::{parse_python, parse_python_project};
use ir::{FileIR, SymbolKind};
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
fn l7_robustez_proyecto() {
    let dir = temp_dir("pyrob_");
    std::fs::write(dir.join("good.py"), "a = 1\n").unwrap();
    std::fs::write(dir.join("bad.py"), "def broken(:\n").unwrap();
    std::fs::write(dir.join("other.py"), "b = 2\n").unwrap();
    let project = parse_python_project(&dir).unwrap();
    let good = project.get("good").unwrap();
    assert!(!good.symbol_types.contains_key("__parse_error__"));
    let bad = project.get("bad").unwrap();
    assert_eq!(
        bad.symbol_types.get("__parse_error__"),
        Some(&SymbolKind::Special)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn l7_archivo_vacio_err() {
    let mut fir = FileIR::new("empty.py".into(), "python".into());
    let res = parse_python("", &mut fir);
    assert!(res.is_err());
}
