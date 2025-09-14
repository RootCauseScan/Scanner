//! Level 6 handles field and container accesses with composite names.
//! It tracks definitions like `cfg.endpoint` or `map["k"]`.

use crate::languages::python::parse_python;
use ir::{DFNodeKind, FileIR};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

fn parse_snippet_with_path(code: &str, path: &str) -> FileIR {
    let mut fir = FileIR::new(path.into(), "python".into());
    parse_python(code, &mut fir).unwrap();
    fir
}

#[test]
fn l6_fields_y_containers() {
    let code = r#"
cfg = object()
cfg.endpoint = source()
sink(cfg.endpoint)
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_id = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "cfg.endpoint" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("def cfg.endpoint");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "cfg.endpoint" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use cfg.endpoint");
    assert!(dfg.edges.contains(&(def_id, use_id)));

    let code = r#"
m = {}
m["k"] = source()
sink(m["k"])
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_id = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "m[\"k\"]" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("def m['k']");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "m[\"k\"]" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use m['k']");
    assert!(dfg.edges.contains(&(def_id, use_id)));

    let code = r#"
arr = [0]
arr[0] = source()
sink(arr[0])
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_id = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "arr[0]" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("def arr[0]");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "arr[0]" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use arr[0]");
    assert!(dfg.edges.contains(&(def_id, use_id)));
}

#[test]
fn l6_clave_inexistente_sin_flujo() {
    let code = r#"
m = {}
sink(m["missing"])
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "m[\"missing\"]" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use m['missing']");
    assert!(dfg.edges.iter().all(|(_, to)| *to != use_id));
}

#[test]
fn l6_indice_fuera_de_rango_sin_flujo() {
    let code = r#"
arr = [0]
sink(arr[1])
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "arr[1]" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use arr[1]");
    assert!(dfg.edges.iter().all(|(_, to)| *to != use_id));
}

#[test]
fn l6_getattr_flujo() {
    let code = r#"
cfg = object()
cfg.endpoint = source()
v = getattr(cfg, "endpoint")
sink(v)
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_attr = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "cfg.endpoint" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("def cfg.endpoint");
    let def_v = dfg
        .nodes
        .iter()
        .find(|n| n.name == "v" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("def v");
    assert!(dfg.edges.contains(&(def_attr, def_v)));
    let use_v = dfg
        .nodes
        .iter()
        .find(|n| n.name == "v" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use v");
    assert!(dfg.edges.contains(&(def_v, use_v)));
}

#[test]
fn l6_setattr_flujo() {
    let code = r#"
cfg = object()
setattr(cfg, "endpoint", source())
sink(cfg.endpoint)
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_id = dfg
        .nodes
        .iter()
        .rev()
        .find(|n| n.name == "cfg.endpoint" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("def cfg.endpoint");
    let use_id = dfg
        .nodes
        .iter()
        .find(|n| n.name == "cfg.endpoint" && matches!(n.kind, DFNodeKind::Use))
        .map(|n| n.id)
        .expect("use cfg.endpoint");
    assert!(dfg.edges.contains(&(def_id, use_id)));
}

#[test]
fn l6_getattr_nombre_dinamico_sin_flujo() {
    let code = r#"
cfg = object()
cfg.endpoint = source()
key = "endpoint"
v = getattr(cfg, key)
sink(v)
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def_attr = dfg
        .nodes
        .iter()
        .find(|n| n.name == "cfg.endpoint" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("def cfg.endpoint");
    let def_v = dfg
        .nodes
        .iter()
        .find(|n| n.name == "v" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("def v");
    assert!(!dfg.edges.contains(&(def_attr, def_v)));
}

#[test]
fn l6_import_from_relativo_estrellado() {
    let fir = parse_snippet("from .utils import *\n");
    assert!(fir.nodes.iter().any(|n| n.path == "import_from.utils.*"));
}

#[test]
fn l6_import_from_relativo_estrellado_invalido() {
    let fir = parse_snippet_with_path("from ..bad import *\n", "module.py");
    assert!(fir.nodes.iter().any(|n| n.path == "import_from.bad.*"));
}

#[test]
fn l6_getattr_llamada_equivalente_a_metodo() {
    let code = r#"
class Obj:
    def m(self, p):
        return p

obj = Obj()
x = source()
sink(getattr(obj, "m")(x))
"#;
    let fir = parse_snippet(code);
    assert!(fir.nodes.iter().any(|n| n.path == "getattr.obj.m"));
    let dfg = fir.dfg.expect("dfg");
    assert!(dfg
        .nodes
        .iter()
        .any(|n| n.name == "obj.m" && matches!(n.kind, DFNodeKind::Use)));
}

#[test]
fn l6_getattr_llamada_nombre_dinamico_sin_flujo() {
    let code = r#"
class Obj:
    def m(self, p):
        return p

obj = Obj()
x = source()
name = "m"
getattr(obj, name)(x)
"#;
    let fir = parse_snippet(code);
    assert!(!fir.nodes.iter().any(|n| n.path == "getattr.obj.m"));
    let dfg = fir.dfg.expect("dfg");
    assert!(dfg.nodes.iter().all(|n| n.name != "obj.m"));
}
