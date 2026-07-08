//! Level 8: constructor DFG, do-while branches, catch parameter Param nodes,
//! initialized field declarations, intra-file taint, compound assignments,
//! ternary expressions, and string concatenation taint for Java.

use crate::parse_java;
use ir::{DFNodeKind, FileIR};

fn parse_snippet(code: &str) -> FileIR {
    let mut fir = FileIR::new("<mem>".into(), "java".into());
    parse_java(code, &mut fir).expect("parse java snippet");
    fir
}

// -------------------------------------------------------------------
// Constructor DFG
// -------------------------------------------------------------------

#[test]
fn constructor_creates_def_and_param_nodes() {
    let code = r#"
class Foo {
    private String value;

    Foo(String input) {
        this.value = input;
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    // Constructor itself should register a Def node named "Foo"
    let ctor_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "Foo" && matches!(n.kind, DFNodeKind::Def))
        .expect("constructor Def node");
    assert!(ctor_def.line > 0, "constructor Def should have line > 0");

    // Parameter `input` should create a Param node
    let param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "input" && matches!(n.kind, DFNodeKind::Param))
        .expect("input Param node");
    assert!(param.line > 0, "param Param should have line > 0");
}

#[test]
fn constructor_taint_flows_through_assignment() {
    let code = r#"
class Foo {
    String secret;

    Foo(String rawInput) {
        secret = rawInput;
    }
}
"#;
    let fir = parse_snippet(code);
    // rawInput param → secret local assignment — secret should not be sanitized
    let sym = fir.symbols.get("secret").expect("secret symbol");
    assert!(!sym.sanitized, "secret should remain tainted from rawInput");
}

#[test]
fn constructor_with_sanitized_param_marks_field_clean() {
    let code = r#"
class Foo {
    String safe;

    Foo(String rawInput) {
        safe = org.apache.commons.text.StringEscapeUtils.escapeHtml(rawInput);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("safe").expect("safe symbol");
    assert!(sym.sanitized, "safe should be marked sanitized");
}

// -------------------------------------------------------------------
// Catch formal parameter
// -------------------------------------------------------------------

#[test]
fn catch_formal_parameter_creates_param_node() {
    let code = r#"
class T {
    void run() {
        try {
            risky();
        } catch (Exception ex) {
            log(ex);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    let ex_param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "ex" && matches!(n.kind, DFNodeKind::Param))
        .expect("ex Param node");
    assert!(ex_param.line > 0, "catch param should have line > 0");

    let sym = fir.symbols.get("ex").expect("ex symbol");
    assert_eq!(sym.def, Some(ex_param.id));
}

#[test]
fn catch_exception_taint_flows_to_use() {
    let code = r#"
class T {
    void run() {
        String data;
        try {
            data = source();
        } catch (Exception ex) {
            data = ex.getMessage();
        }
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    // data can come from source() or from ex.getMessage(); both paths are tainted
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized, "data should remain tainted after catch branch");
}

// -------------------------------------------------------------------
// Initialized field declarations
// -------------------------------------------------------------------

#[test]
fn initialized_field_creates_def_node() {
    let code = r#"
class T {
    String secret = getInput();
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    let field_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "this.secret" && matches!(n.kind, DFNodeKind::Def))
        .expect("this.secret Def node");
    assert!(field_def.line > 0, "field Def should have line > 0");

    let sym = fir.symbols.get("this.secret").expect("this.secret symbol");
    assert_eq!(sym.def, Some(field_def.id));
}

#[test]
fn uninitialized_field_does_not_create_def_node() {
    let code = r#"
class T {
    String secret;
}
"#;
    let fir = parse_snippet(code);
    // A class with only an uninitialized field has no DFG at all (nothing to track),
    // or the DFG has no Def for `this.secret`.
    if let Some(dfg) = &fir.dfg {
        let found = dfg
            .nodes
            .iter()
            .any(|n| n.name == "this.secret" && matches!(n.kind, DFNodeKind::Def));
        assert!(!found, "uninitialized field should not create a Def node");
    }
    // symbols table must also not register this.secret
    assert!(
        fir.symbols.get("this.secret").is_none(),
        "this.secret should not appear in symbol table for uninitialized field"
    );
}

#[test]
fn sanitized_field_initializer_marks_symbol_clean() {
    let code = r#"
class T {
    String safe = org.apache.commons.text.StringEscapeUtils.escapeHtml(getInput());
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("this.safe").expect("this.safe symbol");
    assert!(sym.sanitized, "field initialized with sanitizer should be clean");
}

// -------------------------------------------------------------------
// Do-while branches
// -------------------------------------------------------------------

#[test]
fn do_while_creates_branch_node() {
    let code = r#"
class T {
    void run() {
        boolean flag = true;
        do {
            flag = false;
        } while (flag);
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    let branch = dfg
        .nodes
        .iter()
        .find(|n| n.name == "do" && matches!(n.kind, DFNodeKind::Branch))
        .expect("do Branch node");
    assert!(branch.line > 0, "do Branch should have line > 0");
}

#[test]
fn do_while_cond_creates_use_edge() {
    let code = r#"
class T {
    void run() {
        boolean flag = true;
        do {
            flag = check();
        } while (flag);
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.expect("dfg");

    // There should be a Use node for `flag` in the while condition
    let flag_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "flag" && matches!(n.kind, DFNodeKind::Use));
    assert!(flag_use.is_some(), "do-while condition should produce a Use node for flag");
}

#[test]
fn do_while_body_sanitize_does_not_clear_taint() {
    // Body executes at least once but loop may not execute again; conservative merge should keep taint.
    let code = r#"
class T {
    void run(boolean cond, String data) {
        data = source();
        do {
            data = org.apache.commons.text.StringEscapeUtils.escapeHtml(source());
        } while (cond);
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized, "do-while body sanitization alone should not clear taint");
}

// -------------------------------------------------------------------
// Intra-file taint: source() → sink() detection
// -------------------------------------------------------------------

#[test]
fn java_taint_source_to_sink_detected() {
    let code = r#"
class Bad {
    void run() {
        String data = source();
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.as_ref().expect("dfg");

    // DFG should contain a Def for `data` (from source()) and a Use for `data` (in sink())
    let data_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Def))
        .expect("data Def");
    let data_use = dfg
        .nodes
        .iter()
        .find(|n| n.name == "data" && matches!(n.kind, DFNodeKind::Use))
        .expect("data Use");

    // Edge must exist from Def → Use
    assert!(
        dfg.edges.contains(&(data_def.id, data_use.id)),
        "DFG edge must link data Def to data Use for taint tracking"
    );
    assert!(!data_def.sanitized);
    assert!(!data_use.sanitized);
    assert!(data_def.line > 0, "Def node must have line > 0");
    assert!(data_use.line > 0, "Use node must have line > 0");
}

#[test]
fn java_taint_sanitized_path_not_flagged() {
    let code = r#"
class Good {
    void run() {
        String data = source();
        String safe = org.apache.commons.text.StringEscapeUtils.escapeHtml(data);
        sink(safe);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("safe").expect("safe symbol");
    assert!(sym.sanitized, "safe should be marked sanitized after escapeHtml");

    let dfg = fir.dfg.as_ref().expect("dfg");
    let safe_def = dfg
        .nodes
        .iter()
        .find(|n| n.name == "safe" && matches!(n.kind, DFNodeKind::Def))
        .expect("safe Def");
    assert!(safe_def.sanitized, "safe Def should be sanitized");
}

// -------------------------------------------------------------------
// DFG node line numbers for all new features
// -------------------------------------------------------------------

#[test]
fn all_dfg_nodes_have_nonzero_line() {
    let code = r#"
class T {
    String field = source();

    T(String input) {
        field = input;
    }

    void run() {
        String data = source();
        try {
            data = risky();
        } catch (Exception ex) {
            data = ex.getMessage();
        }
        boolean go = true;
        do {
            go = check();
        } while (go);
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.as_ref().expect("dfg");

    // Assign (merge/phi) nodes are synthetic — they represent the convergence point of
    // multiple branches and have no single corresponding source line. All other node
    // kinds must have a real line number populated by the parser.
    let zero_line_nodes: Vec<_> = dfg
        .nodes
        .iter()
        .filter(|n| n.line == 0 && !matches!(n.kind, DFNodeKind::Assign))
        .collect();

    assert!(
        zero_line_nodes.is_empty(),
        "non-Assign DFG nodes should have line > 0; zero-line nodes: {:?}",
        zero_line_nodes
            .iter()
            .map(|n| format!("{}({:?})", n.name, n.kind))
            .collect::<Vec<_>>()
    );
}

// -------------------------------------------------------------------
// Compound assignment (+=) taint propagation
// -------------------------------------------------------------------

#[test]
fn compound_assignment_tainted_rhs_marks_lhs_tainted() {
    let code = r#"
class T {
    void test() {
        String msg = "";
        String input = source();
        msg += input;
        sink(msg);
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.as_ref().expect("dfg");

    // msg should appear as a Def node (from the compound assignment)
    assert!(
        dfg.nodes.iter().any(|n| n.name == "msg" && matches!(n.kind, DFNodeKind::Def)),
        "compound += should create a Def node for msg"
    );
    // After msg += input (where input is tainted), msg should NOT be sanitized
    let sym = fir.symbols.get("msg").expect("msg symbol");
    assert!(!sym.sanitized, "msg should remain tainted after += with tainted input");
}

#[test]
fn compound_assignment_safe_rhs_keeps_taint_if_lhs_was_tainted() {
    let code = r#"
class T {
    void test() {
        String msg = source();
        msg += " safe suffix";
        sink(msg);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("msg").expect("msg symbol");
    // msg started tainted; += with a literal suffix should keep it tainted (conservative)
    assert!(!sym.sanitized, "msg should stay tainted after += with a literal when lhs was already tainted");
}

#[test]
fn compound_assignment_creates_def_with_nonzero_line() {
    let code = r#"
class T {
    void test() {
        String s = "hello";
        s += " world";
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.as_ref().expect("dfg");
    let compound_def = dfg.nodes.iter().find(|n| n.name == "s" && n.line > 2);
    // The compound_assignment Def should be on the line of `s += " world"`
    assert!(
        compound_def.is_some(),
        "compound_assignment_expression should create a Def node for s with line > 0"
    );
}

// -------------------------------------------------------------------
// Ternary expression taint propagation
// -------------------------------------------------------------------

#[test]
fn ternary_tainted_consequence_marks_result_tainted() {
    let code = r#"
class T {
    void run(boolean cond) {
        String data = cond ? source() : "safe";
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    // Conservative: if any branch of ternary can be tainted, result is tainted.
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized, "ternary with tainted consequence should mark result tainted");
}

#[test]
fn ternary_both_safe_marks_result_sanitized() {
    let code = r#"
class T {
    void run(boolean cond) {
        String data = cond ? "safe_a" : "safe_b";
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized, "ternary with two literal branches should be sanitized");
}

#[test]
fn ternary_sanitized_alternative_with_tainted_consequence_is_tainted() {
    let code = r#"
class T {
    void run(boolean cond) {
        String raw = source();
        String data = cond ? raw : "fallback";
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized, "ternary where consequence is tainted identifier should be tainted");
}

// -------------------------------------------------------------------
// String concatenation (+) taint propagation
// -------------------------------------------------------------------

#[test]
fn string_concat_with_tainted_var_is_tainted() {
    let code = r#"
class T {
    void run() {
        String userInput = source();
        String query = "SELECT * FROM t WHERE name = '" + userInput + "'";
        sink(query);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("query").expect("query symbol");
    assert!(!sym.sanitized, "string concatenation with tainted var should produce tainted result");
}

#[test]
fn string_concat_all_literals_is_sanitized() {
    let code = r#"
class T {
    void run() {
        String msg = "Hello" + " " + "world";
        sink(msg);
    }
}
"#;
    let fir = parse_snippet(code);
    // All parts are literals; msg should be treated as safe.
    // (gather_ids recurses but finds no identifier children → no tainted edges)
    let sym = fir.symbols.get("msg").expect("msg symbol");
    assert!(sym.sanitized, "concatenation of only literals should produce sanitized result");
}

#[test]
fn reassignment_overwrites_taint_state() {
    // After `x = source()`, x is tainted.
    // After `x = "safe"`, x should be sanitized (simple overwrite).
    let code = r#"
class T {
    void run() {
        String x = source();
        x = "safe_literal";
        sink(x);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("x").expect("x symbol");
    assert!(sym.sanitized, "reassignment to literal should overwrite taint and mark x sanitized");
}

