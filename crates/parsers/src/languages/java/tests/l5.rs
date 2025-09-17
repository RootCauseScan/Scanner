//! Branch tracking and conservative merging for Java.
//! Ensures taint is cleared only when all paths sanitize and loop
//! conditions produce use nodes.

use crate::parse_java;
use ir::{DFNodeKind, FileIR};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "java".into());
    parse_java(code, &mut fir).unwrap();
    fir
}

// Sanitizing only one branch should leave data tainted.
#[test]
fn unsanitized_when_only_one_branch_cleans() {
    let code = r#"
class T {
  void main(boolean cond, String data) {
    if (cond) {
      data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
    } else {
      data = source();
    }
    sink(data);
  }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
    let dfg = fir.dfg.expect("dfg");
    let defs: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Def))
        .collect();
    assert!(defs.iter().all(|n| n.branch.is_some()));
}

// Sanitizing in all branches should mark data clean.
#[test]
fn sanitized_when_all_branches_clean() {
    let code = r#"
class T {
  void main(boolean cond, String data) {
    if (cond) {
      data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
    } else {
      data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
    }
    sink(data);
  }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
}

// The condition variable of a while loop should produce a use node linked to its definition.
#[test]
fn while_cond_use() {
    let code = r#"
class T {
  void main() {
    boolean flag = true;
    while (flag) {
      flag = false;
    }
  }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");
    let def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "flag" && matches!(n.kind, DFNodeKind::Def))
        .expect("flag def");
    let use_node = dfg
        .nodes
        .iter()
        .find(|n| n.name == "flag" && matches!(n.kind, DFNodeKind::Use))
        .expect("flag use");
    assert!(dfg.edges.contains(&(def.id, use_node.id)));
}

// Sanitizing inside a for loop alone should not clean data.
#[test]
fn for_unsanitized_when_body_cleans() {
    let code = r#"
class T {
  void main(boolean cond, String data) {
    data = source();
    for (; cond;) {
      data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
    }
    sink(data);
  }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
}

// Sanitizing inside an enhanced for loop alone should not clean data.
#[test]
fn enhanced_for_unsanitized_when_body_cleans() {
    let code = r#"
class T {
  void main(String[] arr, String data) {
    data = source();
    for (String item : arr) {
      data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
    }
    sink(data);
  }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
}

// A switch with an unsanitized case should leave data tainted.
#[test]
fn switch_unsanitized_when_case_unsanitized() {
    let code = r#"
class T {
  void main(int x, String data) {
    switch (x) {
      case 1:
        data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
        break;
      default:
        data = source();
    }
    sink(data);
  }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized);
}

// When all switch cases sanitize, data should be clean.
#[test]
fn switch_sanitized_when_all_cases_clean() {
    let code = r#"
class T {
  void main(int x, String data) {
    switch (x) {
      case 1:
        data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
        break;
      default:
        data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
    }
    sink(data);
  }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized);
}

// A try/catch should keep data tainted if any handler leaves it unsafe.
#[test]
fn try_catch_preserves_taint_on_unsanitized_handler() {
    let code = r#"
class T {
  void main(String data) {
    try {
      data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
    } catch (Exception ex) {
      data = source();
    }
    sink(data);
  }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(
        !sym.sanitized,
        "data should remain tainted when catch branch reintroduces source"
    );
    let dfg = fir.dfg.expect("dfg");
    assert!(
        dfg.nodes
            .iter()
            .any(|node| matches!(node.kind, DFNodeKind::Branch) && node.name == "try"),
        "try statement should register a branch node",
    );
}
