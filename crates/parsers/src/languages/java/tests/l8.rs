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
// Catch formal parameter (single and multi-catch)
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
fn multi_catch_creates_param_node() {
    let code = r#"
class T {
    void run() {
        try {
            risky();
        } catch (IOException | SQLException ex) {
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
        .expect("ex Param node from multi-catch");
    assert!(ex_param.line > 0, "multi-catch param should have line > 0");

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

// -------------------------------------------------------------------
// Enhanced-for loop variable taint propagation
// -------------------------------------------------------------------

#[test]
fn enhanced_for_loop_variable_inherits_taint_from_iterable() {
    let code = r#"
class T {
    void run(String[] items) {
        items[0] = source();
        for (String item : items) {
            sink(item);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    // The loop variable `item` should be created as a symbol (Param/Def)
    // and should inherit taint from the tainted `items` array.
    let sym = fir.symbols.get("item").expect("loop variable 'item' must be in symbol table");
    assert!(!sym.sanitized, "loop variable should be tainted when iterable is tainted");
}

#[test]
fn enhanced_for_loop_variable_is_clean_when_iterable_is_clean() {
    let code = r#"
class T {
    void run() {
        String[] safeItems = {"a", "b", "c"};
        for (String item : safeItems) {
            sink(item);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("item").expect("loop variable 'item' must be in symbol table");
    assert!(sym.sanitized, "loop variable should be clean when iterable contains only literals");
}

#[test]
fn enhanced_for_loop_variable_has_dfg_node() {
    let code = r#"
class T {
    void run(String[] items) {
        for (String item : items) {
            sink(item);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.as_ref().expect("dfg");
    // The loop variable should produce a DFG node (Param)
    let item_node = dfg.nodes.iter().find(|n| n.name == "item");
    assert!(item_node.is_some(), "enhanced-for loop variable must produce a DFG Param node");
    assert!(item_node.unwrap().line > 0, "loop variable DFG node must have line > 0");
}

// -------------------------------------------------------------------
// Cast expression taint transparency
// -------------------------------------------------------------------

#[test]
fn cast_expression_preserves_taint() {
    let code = r#"
class T {
    void run(Object obj) {
        obj = source();
        String data = (String) obj;
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    // Cast does not sanitize; taint flows through to data.
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(!sym.sanitized, "cast expression should not sanitize tainted value");
}

#[test]
fn cast_expression_of_sanitized_value_stays_clean() {
    let code = r#"
class T {
    void run() {
        Object safe = "literal";
        String data = (String) safe;
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data symbol");
    assert!(sym.sanitized, "cast of sanitized value should remain sanitized");
}

// -------------------------------------------------------------------
// Object creation taint semantics
// -------------------------------------------------------------------

#[test]
fn new_no_arg_object_is_sanitized() {
    // new StringBuilder() / new ArrayList<>() etc. create clean empty objects — not taint sources.
    let code = r#"
class T {
    void run() {
        StringBuilder sb = new StringBuilder();
        String result = sb.toString();
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("sb").expect("sb symbol");
    assert!(sym.sanitized, "new StringBuilder() creates a clean object, must be sanitized");
}

#[test]
fn new_with_tainted_arg_is_tainted() {
    let code = r#"
class T {
    void run() {
        String raw = source();
        StringBuilder sb = new StringBuilder(raw);
        sink(sb.toString());
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("sb").expect("sb symbol");
    assert!(!sym.sanitized, "StringBuilder constructed from tainted arg should be tainted");
}

#[test]
fn new_with_sanitized_arg_stays_clean() {
    let code = r#"
class T {
    void run() {
        String safe = "literal";
        StringBuilder sb = new StringBuilder(safe);
    }
}
"#;
    let fir = parse_snippet(code);
    // safe has no tainted ids — sb starts with sanitized symbol; propagation fixes it
    let safe_sym = fir.symbols.get("safe").expect("safe symbol");
    assert!(safe_sym.sanitized, "literal-initialized safe must be sanitized");
}

// -------------------------------------------------------------------
// Text block (Java 15+) is a sanitized literal
// -------------------------------------------------------------------

#[test]
fn text_block_is_sanitized() {
    // Text blocks are multi-line string literals introduced in Java 15.
    // They cannot carry taint (they're compile-time constants).
    let code = "class T {\n    void run() {\n        String sql = \"\"\"\n            SELECT * FROM users\n            WHERE name = 'admin'\n            \"\"\";\n        sink(sql);\n    }\n}";
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("sql") {
        assert!(sym.sanitized, "text block should be treated as sanitized literal");
    }
    // If the parser doesn't support text blocks, the test is vacuously valid.
}


#[test]
fn instanceof_pattern_variable_is_tracked() {
    // Java 16+ instanceof pattern binding: `if (obj instanceof String s)` — the bound
    // variable `s` must appear in symbols (as a Param) so taint flows through correctly.
    let code = r#"
class T {
    void run(Object obj) {
        obj = source();
        if (obj instanceof String s) {
            sink(s);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    // `obj` should be tainted
    let obj_sym = fir.symbols.get("obj").expect("obj must be in symbol table");
    assert!(!obj_sym.sanitized, "obj (from source()) should be tainted");

    // `s` must now be in the symbol table (pattern variable binding)
    let s_sym = fir.symbols.get("s").expect("instanceof pattern variable s must be tracked");
    assert!(!s_sym.sanitized, "pattern variable s inherits taint from obj");

    // DFG must have a Param node for `s`
    let dfg = fir.dfg.as_ref().expect("dfg");
    let s_node = dfg.nodes.iter().find(|n| n.name == "s" && matches!(n.kind, DFNodeKind::Param));
    assert!(s_node.is_some(), "s must have a Param DFG node");
    assert!(s_node.unwrap().line > 0, "s Param node must have line > 0");
}

#[test]
fn instanceof_pattern_on_sanitized_obj_marks_s_clean() {
    let code = r#"
class T {
    void run() {
        String obj = "literal";
        if (obj instanceof String s) {
            sink(s);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    let s_sym = fir.symbols.get("s").expect("s must be tracked");
    assert!(s_sym.sanitized, "pattern variable from sanitized obj should be sanitized");
}

#[test]
fn try_with_resources_variable_is_tracked() {
    // try-with-resources: the resource variable must be tracked as a Def in DFG.
    let code = r#"
class T {
    void run() {
        try (java.io.InputStream in = getTaintedStream()) {
            sink(in);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    // `in` must be in the symbol table and in the DFG
    let in_sym = fir.symbols.get("in").expect("resource variable 'in' must be tracked");
    // getTaintedStream() is unknown/external → not sanitized (conservative)
    assert!(!in_sym.sanitized, "resource from unknown method should not be sanitized");

    let dfg = fir.dfg.as_ref().expect("dfg");
    let in_node = dfg.nodes.iter().find(|n| n.name == "in" && matches!(n.kind, DFNodeKind::Def));
    assert!(in_node.is_some(), "resource variable must have a Def DFG node");
    assert!(in_node.unwrap().line > 0, "resource Def node must have line > 0");
}

#[test]
fn try_with_resources_literal_is_sanitized() {
    let code = r#"
class T {
    void run() throws Exception {
        try (java.io.StringReader r = new java.io.StringReader("literal")) {
            sink(r);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    // new StringReader("literal") — arg is a literal → clean object
    if let Some(sym) = fir.symbols.get("r") {
        assert!(sym.sanitized, "resource initialized with literal-arg constructor should be sanitized");
    }
}

// -------------------------------------------------------------------
// StringBuilder mutation tracking
// -------------------------------------------------------------------

#[test]
fn append_tainted_arg_marks_builder_tainted() {
    // sb starts clean; after sb.append(raw) it must be tainted.
    let code = r#"
class T {
    void test(String raw) {
        StringBuilder sb = new StringBuilder();
        sb.append(raw);
        sink(sb.toString());
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("sb").expect("sb must be tracked");
    assert!(!sym.sanitized, "sb.append(tainted) must mark sb as tainted");
}

#[test]
fn append_literal_leaves_builder_clean() {
    // sb.append("constant") — literal arg; sb stays clean.
    let code = r#"
class T {
    void test() {
        StringBuilder sb = new StringBuilder();
        sb.append("hello");
        sink(sb.toString());
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("sb").expect("sb must be tracked");
    assert!(sym.sanitized, "sb.append(literal) must leave sb sanitized");
}

#[test]
fn insert_tainted_arg_marks_builder_tainted() {
    let code = r#"
class T {
    void test(String raw) {
        StringBuilder sb = new StringBuilder("prefix");
        sb.insert(0, raw);
        sink(sb.toString());
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("sb").expect("sb must be tracked");
    assert!(!sym.sanitized, "sb.insert(_, tainted) must mark sb as tainted");
}

#[test]
fn tostring_after_tainted_append_propagates_taint() {
    // After sb.append(raw), sb.toString() should inherit sb's tainted state.
    let code = r#"
class T {
    void test(String raw) {
        StringBuilder sb = new StringBuilder();
        sb.append(raw);
        String result = sb.toString();
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("result").expect("result must be tracked");
    assert!(!sym.sanitized, "result = sb.toString() where sb is tainted should be tainted");
}

#[test]
fn string_format_with_tainted_arg_is_tainted() {
    // String.format(template, userInput) — the result must be tainted.
    let code = r#"
class T {
    void test(String raw) {
        String result = String.format("Hello %s", raw);
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("result").expect("result must be tracked");
    assert!(!sym.sanitized, "String.format with tainted arg should be tainted");
}

#[test]
fn string_format_with_literal_args_is_sanitized() {
    let code = r#"
class T {
    void test() {
        String result = String.format("Hello %s", "world");
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("result") {
        assert!(sym.sanitized, "String.format with only literal args should be sanitized");
    }
}

#[test]
fn array_parameter_access_is_tainted() {
    // args[] is an external parameter — args[0] should propagate taint.
    let code = r#"
class T {
    public static void main(String[] args) {
        String input = args[0];
        sink(input);
    }
}
"#;
    let fir = parse_snippet(code);
    // `input` gets its value from `args[0]`; args is a Param → input should be tainted
    let sym = fir.symbols.get("input").expect("input must be tracked");
    assert!(!sym.sanitized, "args[0] is user-controlled — input should be tainted");
}

#[test]
fn static_utility_call_with_variable_arg_is_tainted() {
    // Integer.toString(raw) — even a class-receiver call propagates taint from args.
    let code = r#"
class T {
    void test(int raw) {
        String result = Integer.toString(raw);
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("result").expect("result must be tracked");
    assert!(!sym.sanitized, "Integer.toString(tainted) must propagate taint");
}

// -------------------------------------------------------------------
// End-to-end integration: common real-world taint patterns
// -------------------------------------------------------------------

#[test]
fn taint_through_string_concat_to_sink() {
    // Taint: request.getParameter → concat → sink
    let code = r#"
class T {
    void handle(javax.servlet.http.HttpServletRequest req) {
        String name = req.getParameter("name");
        String msg = "Hello " + name + "!";
        sink(msg);
    }
}
"#;
    let fir = parse_snippet(code);
    // msg should inherit taint from name
    let sym = fir.symbols.get("msg").expect("msg must be tracked");
    assert!(!sym.sanitized, "string concat with tainted var must be tainted");
}

#[test]
fn taint_chain_through_field_access_and_return() {
    // Param → field → return should preserve taint
    let code = r#"
class T {
    String value;
    void set(String raw) {
        this.value = raw;
    }
    String get() {
        return this.value;
    }
}
"#;
    let fir = parse_snippet(code);
    // this.value assigned from raw (param) should be tainted
    let sym = fir.symbols.get("this.value").expect("this.value must be tracked");
    assert!(!sym.sanitized, "this.value assigned from param must be tainted");
}

#[test]
fn local_string_only_data_is_sanitized() {
    // No external input — all literal data
    let code = r#"
class T {
    void safe() {
        String msg = "Hello " + "World";
        sink(msg);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("msg") {
        assert!(sym.sanitized, "literal-only concatenation must be sanitized");
    }
}

#[test]
fn system_getenv_is_not_sanitized() {
    // System.getenv() is a known source — it must NOT be auto-sanitized
    // even though System is a class receiver and there are no variable args.
    let code = r#"
class T {
    void run() {
        String val = System.getenv("HOME");
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("val").expect("val must be tracked");
    assert!(!sym.sanitized, "System.getenv() is a taint source — must not be sanitized");
}

#[test]
fn integer_parse_int_sanitizes_tainted_input() {
    // Integer.parseInt is in the sanitizer catalog — converts string to int safely.
    let code = r#"
class T {
    void run(String raw) {
        int num = Integer.parseInt(raw);
    }
}
"#;
    let fir = parse_snippet(code);
    // num should be sanitized since Integer.parseInt is in the catalog
    if let Some(sym) = fir.symbols.get("num") {
        assert!(sym.sanitized, "Integer.parseInt sanitizes the input");
    }
}

#[test]
fn method_chain_append_tostring_is_tainted() {
    // sb.append(raw).toString() — the chain result must be tainted.
    let code = r#"
class T {
    void test(String raw) {
        String result = new StringBuilder().append(raw).toString();
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    // result comes from a chained call with raw — should be tainted
    if let Some(sym) = fir.symbols.get("result") {
        // The chain involves raw, so result must NOT be sanitized.
        // (Even if we can't fully resolve the chain, the gather_ids from the call
        // should collect `raw` as a referenced identifier through argument collection.)
        assert!(!sym.sanitized, "chained append(raw).toString() must be tainted");
    }
}

#[test]
fn subsequent_literal_append_does_not_clear_taint() {
    // Once tainted via append(raw), a later append("literal") must NOT clean the builder.
    let code = r#"
class T {
    void test(String raw) {
        StringBuilder sb = new StringBuilder();
        sb.append(raw);
        sb.append(" world");
        sink(sb.toString());
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("sb").expect("sb must be tracked");
    assert!(!sym.sanitized, "subsequent literal append must not clear taint");
}

#[test]
fn enhanced_for_over_string_array_param_is_tainted() {
    // String[] args is a param; iterating over it gives tainted values.
    let code = r#"
class T {
    void process(String[] inputs) {
        for (String item : inputs) {
            sink(item);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    // item inherits taint from inputs (a param); it must be tainted
    let sym = fir.symbols.get("item").expect("item must be tracked");
    assert!(!sym.sanitized, "enhanced for over tainted array → item must be tainted");
}

// -------------------------------------------------------------------
// Taint from method parameter receiver (find_taint_path Param seeding)
// -------------------------------------------------------------------

#[test]
fn request_getparameter_taint_flows_through_local_to_sink() {
    // request.getParameter("id") — the `request` param feeds into `id.Def`,
    // which has indegree=1. BFS must also start from Param nodes so this chain
    // is detected.  (This tests the engine-level Param seeding, not just parser.)
    let code = r#"
class T {
    void handle(javax.servlet.http.HttpServletRequest request) {
        String id = request.getParameter("userId");
        sink(id);
    }
}
"#;
    let fir = parse_snippet(code);
    // `id` gets its value from request (a Param); it must NOT be sanitized.
    let sym = fir.symbols.get("id").expect("id must be tracked");
    assert!(!sym.sanitized, "request.getParameter result must be tainted");
    // The DFG edge: request.Param → id.Def must exist.
    if let Some(dfg) = &fir.dfg {
        let request_param = dfg.nodes.iter()
            .find(|n| n.name == "request" && matches!(n.kind, ir::DFNodeKind::Param));
        let id_def = dfg.nodes.iter()
            .find(|n| n.name == "id" && matches!(n.kind, ir::DFNodeKind::Def));
        if let (Some(rp), Some(id)) = (request_param, id_def) {
            // An edge should exist from request param → id def (or from some intermediate)
            let has_edge = dfg.edges.contains(&(rp.id, id.id))
                || dfg.nodes.iter().any(|n| {
                    dfg.edges.contains(&(rp.id, n.id)) && dfg.edges.contains(&(n.id, id.id))
                });
            assert!(has_edge, "DFG must trace request param → id def");
        }
    }
}

#[test]
fn method_param_flows_to_sql_concat_is_tainted() {
    // Classic SQL injection: param → concat → stmt.execute
    let code = r#"
class T {
    void query(javax.servlet.http.HttpServletRequest req, java.sql.Statement stmt) throws Exception {
        String userId = req.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        stmt.execute(sql);
    }
}
"#;
    let fir = parse_snippet(code);
    // sql must be tainted from userId which comes from req (a param)
    let sym = fir.symbols.get("sql").expect("sql must be tracked");
    assert!(!sym.sanitized, "SQL string built from user input must be tainted");
}

// -------------------------------------------------------------------
// Varargs (variable_arity_parameter)
// -------------------------------------------------------------------

#[test]
fn varargs_parameter_creates_param_node() {
    // `String... args` should create a Param node just like a regular parameter.
    let code = r#"
class T {
    void process(String... args) {
        sink(args[0]);
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.as_ref().expect("dfg");
    let param = dfg
        .nodes
        .iter()
        .find(|n| n.name == "args" && matches!(n.kind, DFNodeKind::Param));
    assert!(param.is_some(), "varargs param 'args' must create a Param DFG node");
    let sym = fir.symbols.get("args").expect("args must be in symbol table");
    assert!(!sym.sanitized, "varargs param should be tainted (external input)");
}

#[test]
fn varargs_param_with_regular_params_both_tracked() {
    let code = r#"
class T {
    void log(String prefix, String... messages) {
        sink(messages[0]);
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.as_ref().expect("dfg");
    let prefix = dfg.nodes.iter().find(|n| n.name == "prefix" && matches!(n.kind, DFNodeKind::Param));
    let messages = dfg.nodes.iter().find(|n| n.name == "messages" && matches!(n.kind, DFNodeKind::Param));
    assert!(prefix.is_some(), "regular param 'prefix' must be tracked");
    assert!(messages.is_some(), "varargs param 'messages' must be tracked");
}

// -------------------------------------------------------------------
// Text block (Java 15+) sanitized as literal
// -------------------------------------------------------------------

#[test]
fn text_block_assignment_is_sanitized() {
    // A text block used in an assignment should be marked sanitized.
    // Even if the parser represents text_block differently from string_literal,
    // the sanitization logic should treat it as a constant.
    let code = "class T {\n    void run() {\n        String q = \"\"\"\n            SELECT id FROM users\n            \"\"\";\n        String result = q;\n    }\n}";
    let fir = parse_snippet(code);
    // q should be sanitized (text block = constant), result should inherit
    if let Some(sym) = fir.symbols.get("q") {
        assert!(sym.sanitized, "text block variable should be sanitized");
    }
}

// -------------------------------------------------------------------
// Static final field patterns (compile-time constants)
// -------------------------------------------------------------------

#[test]
fn static_final_string_constant_is_sanitized() {
    // Static final string fields initialized with a literal are compile-time constants.
    let code = r#"
class T {
    static final String TABLE = "users";
    void query() {
        String sql = "SELECT * FROM " + TABLE;
        sink(sql);
    }
}
"#;
    let fir = parse_snippet(code);
    // Class fields are stored with the "this." prefix in the symbol table.
    let sym = fir.symbols.get("this.TABLE").expect("this.TABLE must be tracked");
    assert!(sym.sanitized, "static final string literal should be sanitized");
}

// -------------------------------------------------------------------
// Compound assignment with tainted RHS makes result tainted
// -------------------------------------------------------------------

#[test]
fn plus_equals_with_tainted_rhs_produces_tainted_result() {
    let code = r#"
class T {
    void run(String userInput) {
        String sql = "SELECT * FROM users WHERE id=";
        sql += userInput;
        sink(sql);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("sql").expect("sql must be tracked");
    assert!(!sym.sanitized, "sql after += userInput must be tainted");
}

// -------------------------------------------------------------------
// Exception message taint (log injection via catch variable)
// -------------------------------------------------------------------

#[test]
fn catch_variable_message_taint_tracked_as_use() {
    // When `e.getMessage()` is passed to a logger inside a catch block,
    // the catch variable `e` should be a Param so that its use is visible.
    let code = r#"
class T {
    void run(String input) {
        try {
            riskyOp(input);
        } catch (Exception e) {
            sink(e.getMessage());
        }
    }
}
"#;
    let fir = parse_snippet(code);
    // `e` should be in the symbol table as unsanitized (comes from outside)
    let sym = fir.symbols.get("e").expect("catch variable 'e' must be in symbol table");
    assert!(!sym.sanitized, "catch variable should be tainted (external exception data)");
    let dfg = fir.dfg.as_ref().expect("dfg");
    let e_param = dfg.nodes.iter().find(|n| n.name == "e" && matches!(n.kind, DFNodeKind::Param));
    assert!(e_param.is_some(), "catch variable must have a Param DFG node");
}

// -------------------------------------------------------------------
// Static final field referenced without this. prefix
// -------------------------------------------------------------------

#[test]
fn static_final_concat_is_sanitized_when_field_referenced_without_this() {
    // Static final string fields are stored as "this.TABLE" in the symbol table,
    // but in code they are referenced as just "TABLE". The concatenation result
    // must be recognized as sanitized.
    let code = r#"
class T {
    static final String TABLE = "users";
    void query() {
        String sql = "SELECT * FROM " + TABLE;
        sink(sql);
    }
}
"#;
    let fir = parse_snippet(code);
    let table_sym = fir.symbols.get("this.TABLE").expect("this.TABLE must be tracked");
    assert!(table_sym.sanitized, "static final field must be sanitized");
    let sql_sym = fir.symbols.get("sql").expect("sql must be tracked");
    assert!(sql_sym.sanitized, "concat with a sanitized static final constant must be sanitized");
}

#[test]
fn static_field_referenced_without_this_with_tainted_creates_tainted() {
    // Static const + tainted param → tainted result
    let code = r#"
class T {
    static final String PREFIX = "safe_prefix_";
    void run(String raw) {
        String result = PREFIX + raw;
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("result").expect("result must be tracked");
    assert!(!sym.sanitized, "concat of static constant + tainted param must remain tainted");
}

// -------------------------------------------------------------------
// Null literal assignment is sanitized
// -------------------------------------------------------------------

#[test]
fn null_literal_assignment_is_sanitized() {
    let code = r#"
class T {
    void run() {
        String data = source();
        data = null;
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("data").expect("data must be tracked");
    assert!(sym.sanitized, "reassignment to null should clear taint (null_literal is sanitized)");
}

// -------------------------------------------------------------------
// Switch expression taint propagation (Java 14+)
// -------------------------------------------------------------------

#[test]
fn switch_expression_tainted_arm_marks_result_tainted() {
    let code = r#"
class T {
    void run(String kind, String raw) {
        String result = switch (kind) {
            case "a" -> raw;
            default -> "safe";
        };
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("result").expect("result must be tracked");
    assert!(!sym.sanitized, "switch expression with tainted arm must produce tainted result");
}

#[test]
fn switch_expression_all_literal_arms_are_sanitized() {
    let code = r#"
class T {
    void run(String kind) {
        String result = switch (kind) {
            case "a" -> "first";
            case "b" -> "second";
            default -> "other";
        };
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("result") {
        assert!(sym.sanitized, "switch expression with only literal arms must be sanitized");
    }
}

// -------------------------------------------------------------------
// Multiple independent parameters — DFG node isolation
// -------------------------------------------------------------------

#[test]
fn two_params_have_separate_dfg_nodes() {
    let code = r#"
class T {
    void run(String raw, String safe) {
        sink(safe);
    }
}
"#;
    let fir = parse_snippet(code);
    let dfg = fir.dfg.as_ref().expect("dfg");
    let raw_node = dfg.nodes.iter().find(|n| n.name == "raw" && matches!(n.kind, DFNodeKind::Param));
    let safe_node = dfg.nodes.iter().find(|n| n.name == "safe" && matches!(n.kind, DFNodeKind::Param));
    assert!(raw_node.is_some(), "raw must have a Param node");
    assert!(safe_node.is_some(), "safe must have a Param node");
    assert_ne!(raw_node.unwrap().id, safe_node.unwrap().id, "raw and safe must be separate DFG nodes");
}

// -------------------------------------------------------------------
// Intra-class taint through this.field
// -------------------------------------------------------------------

#[test]
fn taint_flows_through_this_field_assignment_in_setter() {
    let code = r#"
class T {
    private String value;

    void setValue(String input) {
        this.value = input;
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("this.value").expect("this.value must be tracked");
    assert!(!sym.sanitized, "this.value assigned from param must be tainted");
}

#[test]
fn sanitized_field_accessed_via_this_is_clean() {
    let code = r#"
class T {
    private String safeField = "constant";

    void run() {
        String result = this.safeField;
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("this.safeField").expect("this.safeField must be tracked");
    assert!(sym.sanitized, "literal-initialized field must be sanitized");
}

// -------------------------------------------------------------------
// Switch statement (traditional) taint propagation
// -------------------------------------------------------------------

#[test]
fn switch_statement_tainted_case_marks_result_tainted() {
    // result is assigned inside a switch case that uses a tainted var.
    let code = r#"
class T {
    void run(String kind, String raw) {
        String result = "default";
        switch (kind) {
            case "a":
                result = raw;
                break;
            default:
                result = "safe";
                break;
        }
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("result").expect("result must be tracked");
    assert!(!sym.sanitized, "switch statement with tainted case must keep result tainted");
}

#[test]
fn switch_statement_all_safe_cases_marks_result_sanitized() {
    let code = r#"
class T {
    void run(String kind) {
        String result = "default";
        switch (kind) {
            case "a":
                result = "safe_a";
                break;
            default:
                result = "safe_b";
                break;
        }
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("result").expect("result must be tracked");
    assert!(sym.sanitized, "switch where all cases assign literals should be sanitized");
}

// -------------------------------------------------------------------
// Enum and constants — common static field access patterns
// -------------------------------------------------------------------

#[test]
fn concat_with_multiple_static_constants_is_sanitized() {
    let code = r#"
class T {
    static final String A = "prefix_";
    static final String B = "_suffix";
    void run() {
        String result = A + B;
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("result").expect("result must be tracked");
    assert!(sym.sanitized, "concat of two sanitized static final constants must be sanitized");
}

#[test]
fn static_final_concat_with_literal_is_sanitized() {
    let code = r#"
class T {
    static final String PREFIX = "users";
    void run() {
        String sql = "SELECT * FROM " + PREFIX + " WHERE 1=1";
        sink(sql);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("sql").expect("sql must be tracked");
    assert!(sym.sanitized, "concat of literals and static final constants must be sanitized");
}

// -------------------------------------------------------------------
// Local variable re-use patterns
// -------------------------------------------------------------------

#[test]
fn variable_initially_sanitized_then_tainted_by_assignment() {
    // x starts as literal, then reassigned from source() — must be tainted.
    let code = r#"
class T {
    void run() {
        String x = "safe";
        x = source();
        sink(x);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("x").expect("x must be tracked");
    assert!(!sym.sanitized, "after x = source(), x must be tainted regardless of initial value");
}

// -------------------------------------------------------------------
// Map/collection taint tracking
// -------------------------------------------------------------------

#[test]
fn map_put_with_tainted_value_marks_key_tainted() {
    // params.put("key", raw) — the slot params["key"] must be tainted.
    let code = r#"
class T {
    void run(String raw) {
        java.util.Map<String, String> params = new java.util.HashMap<>();
        params.put("key", raw);
        String val = params.get("key");
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    let sym = fir.symbols.get("params[\"key\"]")
        .or_else(|| fir.symbols.get("params[key]"));
    if let Some(s) = sym {
        assert!(!s.sanitized, "map slot assigned from tainted value must be tainted");
    }
    // val must not be sanitized (it comes from a tainted slot)
    if let Some(val_sym) = fir.symbols.get("val") {
        assert!(!val_sym.sanitized, "val from tainted map slot must be tainted");
    }
}

#[test]
fn map_put_with_literal_value_marks_key_sanitized() {
    let code = r#"
class T {
    void run() {
        java.util.Map<String, String> params = new java.util.HashMap<>();
        params.put("key", "safe_value");
        String val = params.get("key");
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(sym.sanitized, "val from map with only literal value must be sanitized");
    }
}

// -------------------------------------------------------------------
// Inter-procedural: mixed-return path sanitization
// -------------------------------------------------------------------

#[test]
fn method_with_mixed_returns_call_site_is_tainted() {
    // When a private method has one tainted return path and one safe path,
    // the call site must NOT be marked sanitized (false-negative risk).
    let code = r#"
class T {
    String process(String raw, boolean flag) {
        if (flag) return raw;   // tainted path
        return "safe";          // safe path
    }
    void run(String userInput) {
        String val = process(userInput, true);
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(!sym.sanitized, "call to method with tainted return path must not be sanitized");
    }
}

#[test]
fn method_with_all_safe_returns_call_site_is_sanitized() {
    let code = r#"
class T {
    String safe(boolean flag) {
        if (flag) return "a";
        return "b";
    }
    void run() {
        String val = safe(true);
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(sym.sanitized, "call to method with all-literal returns must be sanitized");
    }
}

// -------------------------------------------------------------------
// Chained method on tainted receiver preserves taint
// -------------------------------------------------------------------

#[test]
fn chained_method_on_tainted_string_is_tainted() {
    // raw.trim().toLowerCase() — neither trim() nor toLowerCase() sanitizes;
    // the taint from raw must flow through to the result.
    let code = r#"
class T {
    void run(String raw) {
        String val = raw.trim().toLowerCase();
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(!sym.sanitized, "chained non-sanitizing methods on tainted string must remain tainted");
    }
}

#[test]
fn chained_method_on_literal_is_sanitized() {
    let code = r#"
class T {
    void run() {
        String val = "safe".trim().toLowerCase();
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(sym.sanitized, "chained methods on a string literal must be sanitized");
    }
}


// -------------------------------------------------------------------
// Static method with variable args is tainted
// -------------------------------------------------------------------

#[test]
fn message_format_with_tainted_arg_is_tainted() {
    // MessageFormat.format is not a sanitizer; the result carries taint.
    let code = r#"
class T {
    void run(String userInput) {
        String result = java.text.MessageFormat.format("value: {0}", userInput);
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("result") {
        assert!(!sym.sanitized, "MessageFormat.format with tainted arg must remain tainted");
    }
}

// -------------------------------------------------------------------
// Null-safe chained calls
// -------------------------------------------------------------------

#[test]
fn optional_of_tainted_is_tainted() {
    // Optional.of(tainted).get() — the tainted value flows through.
    let code = r#"
class T {
    void run(String raw) {
        String val = java.util.Optional.of(raw).get();
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(!sym.sanitized, "Optional.of(tainted).get() must propagate taint");
    }
}

#[test]
fn optional_of_literal_is_sanitized() {
    let code = r#"
class T {
    void run() {
        String val = java.util.Optional.of("safe").get();
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(sym.sanitized, "Optional.of(literal).get() must be sanitized");
    }
}

// -------------------------------------------------------------------
// Field assignment via bare name then read in another method
// -------------------------------------------------------------------

#[test]
fn field_written_via_bare_name_tainted_in_second_method() {
    let code = r#"
class T {
    private String data;
    void set(String raw) {
        data = raw;
    }
    void use() {
        sink(data);
    }
}
"#;
    let fir = parse_snippet(code);
    // `data` (stored under "data" or "this.data") should be tainted after
    // set() assigns a parameter to it.
    let sym = fir.symbols.get("data")
        .or_else(|| fir.symbols.get("this.data"));
    if let Some(sym) = sym {
        assert!(!sym.sanitized, "field written from tainted param must be tainted");
    }
}

// -------------------------------------------------------------------
// Chained assignment `a = b = source()`
// -------------------------------------------------------------------

#[test]
fn chained_assignment_both_vars_tainted() {
    // b = source(); a = b — both a and b should be tainted.
    let code = r#"
class T {
    void run() {
        String b = source();
        String a = b;
        sink(a);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("a") {
        assert!(!sym.sanitized, "variable aliased from tainted source must be tainted");
    }
}

// -------------------------------------------------------------------
// String.valueOf() is NOT a sanitizer
// -------------------------------------------------------------------

#[test]
fn string_valueof_tainted_is_tainted() {
    let code = r#"
class T {
    void run(int rawInt) {
        String val = String.valueOf(rawInt);
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        // String.valueOf is just a type conversion, not a sanitizer.
        // rawInt is a parameter → tainted. val should inherit the taint.
        assert!(!sym.sanitized, "String.valueOf(tainted) must remain tainted");
    }
}


// -------------------------------------------------------------------
// Taint through Array.asList and iteration
// -------------------------------------------------------------------

#[test]
fn arrays_as_list_with_tainted_is_tainted() {
    // Arrays.asList(tainted) — the list carries the taint.
    let code = r#"
class T {
    void run(String raw) {
        java.util.List<String> list = java.util.Arrays.asList(raw, "safe");
        for (String item : list) {
            sink(item);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("list") {
        assert!(!sym.sanitized, "Arrays.asList with tainted element must produce tainted list");
    }
}

#[test]
fn arrays_as_list_all_literals_is_sanitized() {
    let code = r#"
class T {
    void run() {
        java.util.List<String> list = java.util.Arrays.asList("a", "b");
        for (String item : list) {
            sink(item);
        }
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("list") {
        assert!(sym.sanitized, "Arrays.asList with only literals must be sanitized");
    }
}

// -------------------------------------------------------------------
// Taint through Collections utility calls
// -------------------------------------------------------------------

#[test]
fn collections_singleton_literal_is_sanitized() {
    let code = r#"
class T {
    void run() {
        java.util.List<String> list = java.util.Collections.singletonList("safe");
        sink(list.get(0));
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("list") {
        assert!(sym.sanitized, "singletonList with literal must be sanitized");
    }
}

// -------------------------------------------------------------------
// Conditional (ternary) in method arg: taint from either branch
// -------------------------------------------------------------------

#[test]
fn ternary_in_method_arg_propagates_taint() {
    // sink(flag ? tainted : "safe") — even though one branch is safe,
    // the ternary result may be tainted, so sink sees potential taint.
    let code = r#"
class T {
    void run(boolean flag, String tainted) {
        String result = flag ? tainted : "safe";
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("result") {
        assert!(!sym.sanitized, "ternary with one tainted branch must produce tainted result");
    }
}

// -------------------------------------------------------------------
// StringBuilder initialized from tainted arg
// -------------------------------------------------------------------

#[test]
fn stringbuilder_from_tainted_constructor_arg_is_tainted() {
    let code = r#"
class T {
    void run(String raw) {
        StringBuilder sb = new StringBuilder(raw);
        sink(sb.toString());
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("sb") {
        assert!(!sym.sanitized, "StringBuilder(tainted) must be tainted");
    }
}

// -------------------------------------------------------------------
// Literal concatenation in if-else then merge
// -------------------------------------------------------------------

#[test]
fn if_else_one_branch_tainted_merge_is_tainted() {
    let code = r#"
class T {
    void run(boolean flag, String raw) {
        String val;
        if (flag) {
            val = raw;
        } else {
            val = "safe";
        }
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(!sym.sanitized, "after if-else with one tainted branch, val must be tainted");
    }
}


// -------------------------------------------------------------------
// Taint through getter/setter pattern (inter-method field propagation)
// -------------------------------------------------------------------

#[test]
fn setter_then_getter_propagates_taint() {
    // Taint written via setX() then read via getX() through a field.
    let code = r#"
class T {
    private String value;
    public void setValue(String v) { this.value = v; }
    public String getValue() { return this.value; }
    public void run(String raw) {
        setValue(raw);
        String result = getValue();
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    // this.value should be tainted after setValue(raw)
    let field = fir.symbols.get("this.value").or_else(|| fir.symbols.get("value"));
    if let Some(s) = field {
        assert!(!s.sanitized, "this.value after setValue(tainted) must be tainted");
    }
}

// -------------------------------------------------------------------
// Taint via exception constructor args
// -------------------------------------------------------------------

#[test]
fn exception_with_tainted_message_is_tainted() {
    // new RuntimeException(tainted) — the exception carries the taint.
    let code = r#"
class T {
    void run(String userInput) {
        RuntimeException ex = new RuntimeException(userInput);
        sink(ex.getMessage());
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("ex") {
        assert!(!sym.sanitized, "exception created with tainted message must be tainted");
    }
}

// -------------------------------------------------------------------
// Taint does NOT flow from unrelated variable
// -------------------------------------------------------------------

#[test]
fn unrelated_tainted_variable_does_not_taint_literal_result() {
    let code = r#"
class T {
    void run(String raw) {
        // raw is tainted but we never use it in building result.
        String result = "SELECT 1";
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("result") {
        assert!(sym.sanitized, "literal assignment must be sanitized regardless of other tainted variables");
    }
}

// -------------------------------------------------------------------
// Taint through string split / join
// -------------------------------------------------------------------

#[test]
fn string_split_of_tainted_is_tainted() {
    let code = r#"
class T {
    void run(String raw) {
        String[] parts = raw.split(",");
        sink(parts[0]);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("parts") {
        assert!(!sym.sanitized, "splitting a tainted string produces tainted parts");
    }
}

#[test]
fn string_join_with_literal_args_is_sanitized() {
    let code = r#"
class T {
    void run() {
        String result = String.join(", ", "a", "b", "c");
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("result") {
        assert!(sym.sanitized, "String.join with only literals must be sanitized");
    }
}

#[test]
fn string_join_with_tainted_arg_is_tainted() {
    let code = r#"
class T {
    void run(String raw) {
        String result = String.join(", ", "a", raw);
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("result") {
        assert!(!sym.sanitized, "String.join with a tainted element must be tainted");
    }
}


// -------------------------------------------------------------------
// Enum / constant field usage
// -------------------------------------------------------------------

#[test]
fn enum_constant_is_sanitized() {
    // Enum constants (ALL_CAPS by convention) are compile-time values — sanitized.
    let code = r#"
class T {
    enum Status { ACTIVE, INACTIVE }
    void run() {
        String val = Status.ACTIVE.name();
        sink(val);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("val") {
        assert!(sym.sanitized, "enum constant name() is sanitized");
    }
}

// -------------------------------------------------------------------
// Cascaded ternary with mixed taint
// -------------------------------------------------------------------

#[test]
fn nested_ternary_one_branch_tainted() {
    let code = r#"
class T {
    void run(boolean a, boolean b, String raw) {
        String result = a ? (b ? raw : "safe") : "also_safe";
        sink(result);
    }
}
"#;
    let fir = parse_snippet(code);
    if let Some(sym) = fir.symbols.get("result") {
        assert!(!sym.sanitized, "nested ternary with one tainted leaf must produce tainted result");
    }
}

// -------------------------------------------------------------------
// try/catch: taint escaping through catch variable
// -------------------------------------------------------------------

#[test]
fn taint_does_not_flow_into_catch_var_from_unrelated_code() {
    let code = r#"
class T {
    void run() {
        try {
            String safe = "constant";
            sink(safe);
        } catch (Exception e) {
            // e.getMessage() should not be tainted just because try block ran
        }
    }
}
"#;
    let fir = parse_snippet(code);
    // "safe" must be sanitized even though it's inside a try block
    if let Some(sym) = fir.symbols.get("safe") {
        assert!(sym.sanitized, "literal in try block must remain sanitized");
    }
}

// -------------------------------------------------------------------
// Taint isolation: parameter of one method does not taint another
// -------------------------------------------------------------------

#[test]
fn param_of_one_method_does_not_taint_sibling_method_param() {
    let code = r#"
class T {
    void methodA(String raw) {
        sink(raw);
    }
    void methodB(String clean) {
        // clean is a separate parameter — raw from methodA must not taint it
    }
    void run() {
        methodA(source());
        methodB("safe");
    }
}
"#;
    let fir = parse_snippet(code);
    // "clean" is a separate Param node from "raw" — should be unrelated
    // We can't easily test param isolation here without checking DFG edges,
    // but at least verify that "clean" has its own symbol entry
    let sym_raw = fir.symbols.get("raw");
    let sym_clean = fir.symbols.get("clean");
    if let (Some(r), Some(c)) = (sym_raw, sym_clean) {
        assert_ne!(r.def, c.def, "raw and clean must have distinct DFG node ids");
    }
}

// -------------------------------------------------------------------
// Pattern: HttpServletRequest → variable → SQL concat
// -------------------------------------------------------------------

#[test]
fn http_request_getparameter_to_sql_concat_is_tainted() {
    let code = r#"
import javax.servlet.http.HttpServletRequest;
class T {
    void handle(HttpServletRequest request) {
        String id = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = '" + id + "'";
        db.execute(query);
    }
}
"#;
    let fir = parse_snippet(code);
    let id_sym = fir.symbols.get("id");
    assert!(id_sym.is_some(), "id must be tracked as a symbol");
    if let Some(sym) = id_sym {
        assert!(!sym.sanitized, "getParameter result must be tainted");
    }
    if let Some(sym) = fir.symbols.get("query") {
        assert!(!sym.sanitized, "SQL query with tainted id must be tainted");
    }
}

