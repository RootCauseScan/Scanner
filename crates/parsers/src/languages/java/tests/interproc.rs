use crate::parse_java;
use ir::{DFNodeKind, FileIR};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "java".into());
    parse_java(code, &mut fir).expect("parse java snippet");
    fir
}

#[test]
fn links_params_and_returns() {
    let code = r#"class Sample {
  static String id(String x) { return x; }
  void caller() {
    String a = dangerous();
    String b = id(a);
  }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("missing dfg");
    use std::mem::discriminant;
    let id = |name: &str, kind: DFNodeKind| {
        dfg.nodes
            .iter()
            .find(|n| n.name == name && discriminant(&n.kind) == discriminant(&kind))
            .map(|n| n.id)
            .unwrap()
    };
    let a_def = id("a", DFNodeKind::Def);
    let b_def = id("b", DFNodeKind::Def);
    let param = id("x", DFNodeKind::Param);
    let ret = id("x", DFNodeKind::Return);
    assert!(dfg.edges.contains(&(a_def, param)));
    assert!(dfg.edges.contains(&(param, ret)));
    assert!(dfg.edges.contains(&(ret, b_def)));
    assert_eq!(dfg.calls.len(), 1);
    assert_eq!(dfg.call_returns.len(), 1);
    assert!(fir.symbols.get("b").is_some_and(|s| !s.sanitized));
}

#[test]
fn propagates_sanitization_through_calls() {
    let code = r#"import org.apache.commons.text.StringEscapeUtils;
class Sample {
  static String id(String x) { return x; }
  void caller() {
    String raw = dangerous();
    String safe = StringEscapeUtils.escapeHtml(raw);
    String out = id(safe);
  }
}
"#;
    let fir = parse_snippet(code);
    assert!(fir.symbols.get("out").is_some_and(|s| s.sanitized));
    let dfg = fir.dfg.expect("missing dfg");
    use std::mem::discriminant;
    let id = |name: &str, kind: DFNodeKind| {
        dfg.nodes
            .iter()
            .find(|n| n.name == name && discriminant(&n.kind) == discriminant(&kind))
            .map(|n| n.id)
            .unwrap()
    };
    let safe_def = id("safe", DFNodeKind::Def);
    let param = id("x", DFNodeKind::Param);
    let ret = id("x", DFNodeKind::Return);
    let out_def = id("out", DFNodeKind::Def);
    assert!(dfg.edges.contains(&(safe_def, param)));
    assert!(dfg.edges.contains(&(param, ret)));
    assert!(dfg.edges.contains(&(ret, out_def)));
    assert!(
        dfg.nodes
            .iter()
            .find(|n| n.id == out_def)
            .unwrap()
            .sanitized
    );
}
