//! Level 1 checks Java parsing for basic IR, data flow, and sanitization.
//! See docs/docs/architecture/crates/parsers/maturity.md for details.

use crate::{catalog, parse_java};
use ir::{DFNodeKind, FileIR};
use std::fs;
use std::path::Path;

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "java".into());
    parse_java(code, &mut fir).expect("parse java snippet");
    fir
}

fn parse_fixture(dir: &str, file: &str) -> FileIR {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/java")
        .join(dir)
        .join(file);
    let content = fs::read_to_string(&path).expect("fixture");
    let mut fir = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    parse_java(&content, &mut fir).expect("parse java fixture");
    fir
}

// Sanitizer call should propagate clean data through aliases.
#[test]
fn builds_ir_and_dfg_with_sanitizer() {
    let code = r#"import org.apache.commons.text.StringEscapeUtils;
class Sample {
  void foo() {
    String s = dangerous();
    String safe = StringEscapeUtils.escapeHtml(s);
    String alias = safe;
    bar(alias);
  }
}
"#;
    let fir = parse_snippet(code);
    // IR nodes
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "import.org.apache.commons.text.StringEscapeUtils"));
    assert!(fir.nodes.iter().any(|n| n.path == "function.foo"));
    assert!(fir.nodes.iter().any(|n| n.path == "call.dangerous"));
    assert!(fir
        .nodes
        .iter()
        .any(|n| n.path == "call.org.apache.commons.text.StringEscapeUtils.escapeHtml"));
    assert!(fir.nodes.iter().any(|n| n.path == "assign.s"));
    assert!(fir.nodes.iter().any(|n| n.path == "assign.safe"));
    assert!(fir.nodes.iter().any(|n| n.path == "assign.alias"));
    // Sanitization
    assert!(fir.symbols.get("safe").is_some_and(|s| s.sanitized));
    assert!(fir.symbols.get("alias").is_some_and(|s| s.sanitized));
    let dfg = fir.dfg.expect("missing dfg");
    use std::mem::discriminant;
    let id = |name: &str, kind: DFNodeKind| {
        dfg.nodes
            .iter()
            .find(|n| n.name == name && discriminant(&n.kind) == discriminant(&kind))
            .map(|n| n.id)
            .unwrap()
    };
    let s_def = id("s", DFNodeKind::Def);
    let safe_def = id("safe", DFNodeKind::Def);
    let alias_def = id("alias", DFNodeKind::Def);
    let bar_use = id("alias", DFNodeKind::Use);
    assert!(dfg.edges.contains(&(s_def, safe_def)));
    assert!(dfg.edges.contains(&(safe_def, alias_def)));
    assert!(dfg.edges.contains(&(alias_def, bar_use)));
    assert!(
        dfg.nodes
            .iter()
            .find(|n| n.id == safe_def)
            .unwrap()
            .sanitized
    );
    assert!(
        dfg.nodes
            .iter()
            .find(|n| n.id == alias_def)
            .unwrap()
            .sanitized
    );
}

// Runtime.exec should be detected in IR.
#[test]
fn detects_runtime_exec_call() {
    let bad = parse_fixture("java.no-runtime-exec", "bad.java");
    assert!(bad
        .nodes
        .iter()
        .any(|n| n.path == "call.Runtime.getRuntime().exec"));
    let good = parse_fixture("java.no-runtime-exec", "good.java");
    assert!(!good
        .nodes
        .iter()
        .any(|n| n.path == "call.Runtime.getRuntime().exec"));
}

// Class.forName invocation is flagged.
#[test]
fn detects_class_forname_call() {
    let bad = parse_fixture("java.no-class-forname", "bad.java");
    assert!(bad.nodes.iter().any(|n| n.path == "call.Class.forName"));
    let good = parse_fixture("java.no-class-forname", "good.java");
    assert!(!good.nodes.iter().any(|n| n.path == "call.Class.forName"));
}

// System.exit should appear in IR.
#[test]
fn detects_system_exit_call() {
    let bad = parse_fixture("java.no-system-exit", "bad.java");
    assert!(bad.nodes.iter().any(|n| n.path == "call.System.exit"));
    let good = parse_fixture("java.no-system-exit", "good.java");
    assert!(!good.nodes.iter().any(|n| n.path == "call.System.exit"));
}

// Static import alias propagates sanitizer status.
#[test]
fn propagates_sanitized_from_static_import_alias() {
    let good = parse_fixture("java.sanitizer-alias", "good.java");
    assert!(good.symbols.get("alias").is_some_and(|s| s.sanitized));
    let bad = parse_fixture("java.sanitizer-alias", "bad.java");
    assert!(bad.symbols.get("alias").is_some_and(|s| !s.sanitized));
}

// Ordinary function should not sanitize.
#[test]
fn non_sanitizer_not_marked() {
    let code = r#"class S { void f() { String x = input(); sink(x); } }"#;
    let fir = parse_snippet(code);
    assert!(fir.symbols.get("x").is_some_and(|s| !s.sanitized));
}

// Catalog entry can mark function as sanitizer.
#[test]
fn allows_custom_catalog_sanitizer() {
    catalog::extend("java", &[], &[], &["com.example.CustomSan.clean"]);
    let code = r#"import com.example.CustomSan;
class S {
  void f() {
    String s = dangerous();
    String safe = CustomSan.clean(s);
    sink(safe);
  }
}
"#;
    let fir = parse_snippet(code);
    assert!(fir.symbols.get("safe").is_some_and(|s| s.sanitized));
}

// Without catalog entry, custom function isn't sanitizer.
#[test]
fn ignores_custom_rule_without_type() {
    let code = r#"import com.example.Custom;
class S {
  void f() {
    String s = dangerous();
    String safe = Custom.clean(s);
    sink(safe);
  }
}
"#;
    let fir = parse_snippet(code);
    assert!(fir.symbols.get("safe").is_some_and(|s| !s.sanitized));
}

// Wildcard import allows fully qualified call path.
#[test]
fn resolves_call_with_wildcard_import() {
    let code = r#"import foo.*;
class S {
  void f() {
    Bar.baz();
  }
}
"#;
    let fir = parse_snippet(code);
    assert!(fir.nodes.iter().any(|n| n.path == "import.foo.*"));
    assert!(fir.nodes.iter().any(|n| n.path == "call.Bar.baz"));
    assert!(fir.nodes.iter().any(|n| n.path == "call.foo.Bar.baz"));
}

// Wildcard import shouldn't qualify bare method calls.
#[test]
fn wildcard_import_ignored_for_bare_method() {
    let code = r#"import foo.*;
class S {
  void f() {
    baz();
  }
}
"#;
    let fir = parse_snippet(code);
    assert!(fir.nodes.iter().any(|n| n.path == "call.baz"));
    assert!(!fir.nodes.iter().any(|n| n.path == "call.foo.baz"));
}
