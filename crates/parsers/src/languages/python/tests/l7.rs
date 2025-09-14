use crate::languages::python::parse_python_project;
use ir::DFNodeKind;
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
