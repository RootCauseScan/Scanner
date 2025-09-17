//! Level 7 ensures cross-module imports wire DFG edges and sanitization.

use crate::languages::java::{parse_java, parse_java_project};
use ir::{DFNodeKind, FileIR};
use std::fs;
use tempfile::tempdir;

fn write_java(root: &std::path::Path, relative: &str, contents: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create java fixture dirs");
    }
    fs::write(path, contents).expect("write java fixture");
}

#[test]
fn l7_cross_module_import_edges_propagate_sanitization() {
    let tmp = tempdir().expect("temp dir");
    let root = tmp.path();

    write_java(
        root,
        "pkg/Safe.java",
        r#"package pkg;

public class Safe {
    public static String ESCAPED;

    static {
        ESCAPED = org.apache.commons.text.StringEscapeUtils.escapeHtml("<x>");
    }
}
"#,
    );

    write_java(
        root,
        "app/App.java",
        r#"package app;

import static pkg.Safe.ESCAPED;

public class App {
    public String value(String input) {
        String result = ESCAPED;
        return result;
    }
}
"#,
    );

    let cache = root.join("cache.json");
    let (modules, _parsed) = parse_java_project(root, &cache, None).expect("parse project");

    let safe = modules.get("pkg.Safe").expect("safe module");
    let escaped_symbol = safe.symbols.get("ESCAPED").expect("escaped symbol in safe");
    let def_id = escaped_symbol.def.expect("escaped def id");

    let app = modules.get("app.App").expect("app module");
    let dfg = app.dfg.as_ref().expect("app dfg");
    let result_def_node = dfg
        .nodes
        .iter()
        .find(|n| n.name == "result" && matches!(n.kind, DFNodeKind::Def))
        .expect("result def node");

    assert!(
        dfg.edges.contains(&(def_id, result_def_node.id)),
        "assignment should link imported definition into local def",
    );

    let result_sym = app.symbols.get("result").expect("result symbol");
    assert!(
        result_sym.sanitized,
        "result should inherit sanitization from import",
    );
}

#[test]
fn l7_stable_ids() {
    let code = r#"class Sample {
  void run() {
    String data = source();
    sink(data);
  }
}
"#;
    let mut fir1 = FileIR::new("Sample.java".into(), "java".into());
    parse_java(code, &mut fir1).expect("parse first");
    let mut fir2 = FileIR::new("Sample.java".into(), "java".into());
    parse_java(code, &mut fir2).expect("parse second");

    let def1 = fir1
        .dfg
        .as_ref()
        .expect("dfg1")
        .nodes
        .iter()
        .find(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("data def id fir1");
    let def2 = fir2
        .dfg
        .as_ref()
        .expect("dfg2")
        .nodes
        .iter()
        .find(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("data def id fir2");
    assert_eq!(def1, def2);

    let call1 = fir1
        .nodes
        .iter()
        .find(|n| n.path == "call.source")
        .map(|n| n.id)
        .expect("call id fir1");
    let call2 = fir2
        .nodes
        .iter()
        .find(|n| n.path == "call.source")
        .map(|n| n.id)
        .expect("call id fir2");
    assert_eq!(call1, call2);

    let code_shifted = r#"
class Sample {
  void run() {
    String data = source();
    sink(data);
  }
}
"#;
    let mut fir3 = FileIR::new("Sample.java".into(), "java".into());
    parse_java(code_shifted, &mut fir3).expect("parse shifted");
    let def3 = fir3
        .dfg
        .as_ref()
        .expect("dfg3")
        .nodes
        .iter()
        .find(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Def))
        .map(|n| n.id)
        .expect("data def id fir3");
    assert_ne!(def1, def3);
    let call3 = fir3
        .nodes
        .iter()
        .find(|n| n.path == "call.source")
        .map(|n| n.id)
        .expect("call id fir3");
    assert_ne!(call1, call3);
}
