//! Level 6 validates container field tracking and data flow.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::parse_java;
use ir::{DFNodeKind, FileIR};
use serde_json::Value;

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "java".into());
    parse_java(code, &mut fir).expect("parse java snippet");
    fir
}

#[test]
fn l6_map_put_get_propagates_taint() {
    let code = r#"
import java.util.HashMap;
import java.util.Map;

class T {
  void main(String input) {
    Map<String, String> map = new HashMap<>();
    map.put("key", input);
    String out = map.get("key");
    sink(out);
  }
}
"#;
    let fir = parse_snippet(code);
    let map_entry = fir.symbols.get("map[\"key\"]").expect("map entry symbol");
    assert!(
        !map_entry.sanitized,
        "map entry should remain tainted when value is tainted"
    );

    let dfg = fir.dfg.expect("dfg");
    let input_param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "input" && matches!(n.kind, DFNodeKind::Param))
        .expect("input param node");
    let entry_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "map[\"key\"]" && matches!(n.kind, DFNodeKind::Def))
        .expect("map entry def");
    let out_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "out" && matches!(n.kind, DFNodeKind::Def))
        .expect("out def");

    assert!(
        dfg.edges.contains(&(input_param.id, entry_def.id)),
        "value assigned into map should create edge from input param"
    );
    assert!(
        dfg.edges.contains(&(entry_def.id, out_def.id)),
        "reading from map should connect entry def to consumer"
    );
}

#[test]
fn l6_list_add_get_propagates_sanitization() {
    let code = r#"
import java.util.ArrayList;
import java.util.List;

class T {
  void main(String input) {
    List<String> list = new ArrayList<>();
    list.add(0, org.apache.commons.text.StringEscapeUtils.escapeHtml(input));
    String safe = list.get(0);
    sink(safe);
  }
}
"#;
    let fir = parse_snippet(code);
    let list_entry = fir.symbols.get("list[0]").expect("list entry symbol");
    assert!(
        list_entry.sanitized,
        "list entry should be marked sanitized when value is sanitized"
    );

    let dfg = fir.dfg.expect("dfg");
    let entry_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "list[0]" && matches!(n.kind, DFNodeKind::Def))
        .expect("list entry def");
    let safe_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "safe" && matches!(n.kind, DFNodeKind::Def))
        .expect("safe def");
    assert!(entry_def.sanitized, "list entry def should be sanitized");
    assert!(
        safe_def.sanitized,
        "safe assignment should inherit sanitization"
    );
    assert!(
        dfg.edges.contains(&(entry_def.id, safe_def.id)),
        "sanitized value should flow from list entry to consumer"
    );
}

#[test]
fn l6_reflection_for_name_records_target() {
    let code = r#"
class T {
  void main() throws Exception {
    Class<?> klass = Class.forName("com.example.Exec");
  }
}
"#;
    let fir = parse_snippet(code);
    assert!(fir
        .nodes
        .iter()
        .any(|node| node.path == "call.reflect.for_name.target"
            && matches!(node.value, Value::String(ref v) if v == "com.example.Exec")));
}

#[test]
fn l6_reflection_invoke_propagates_taint() {
    let code = r#"
import java.lang.reflect.Method;

class T {
  void main(String name, Object instance) throws Exception {
    Class<?> clazz = Class.forName("com.example.Exec");
    Method method = clazz.getDeclaredMethod(name);
    Object out = method.invoke(instance);
    sink(out);
  }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    let name_param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "name" && matches!(n.kind, DFNodeKind::Param))
        .expect("name param");
    let method_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "method" && matches!(n.kind, DFNodeKind::Def))
        .expect("method def");
    let method_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "method" && matches!(n.kind, DFNodeKind::Use))
        .expect("method use");
    let out_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "out" && matches!(n.kind, DFNodeKind::Def))
        .expect("out def");

    assert!(
        dfg.edges.contains(&(name_param.id, method_def.id)),
        "method definition should depend on reflective name parameter",
    );
    assert!(
        dfg.edges.contains(&(method_def.id, method_use.id)),
        "invoke should read the reflected method handle",
    );
    assert!(
        dfg.edges.contains(&(method_def.id, out_def.id)),
        "result of invoke should depend on reflected method handle",
    );

    assert!(fir
        .nodes
        .iter()
        .any(|node| node.path == "call.reflect.invoke.target"
            && matches!(node.value, Value::String(ref v) if v == "method")));
}
