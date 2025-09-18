use super::*;
use loader::{AstPattern, MetaVar};
use std::collections::HashMap;
use std::path::PathBuf;

fn load_fixture(name: &str) -> FileIR {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../examples/fixtures/python/ast_pattern/{name}.py"
    ));
    if !path.exists() {
        eprintln!("Skipping {name}: fixture not found at {}", path.display());
        return FileIR::new(path.to_string_lossy().into_owned(), "python".into());
    }
    parsers::parse_file(&path, None, None).unwrap().unwrap()
}

fn build_rule() -> CompiledRule {
    let mut metavars = HashMap::new();
    metavars.insert(
        "$FUNC".into(),
        MetaVar {
            kind: "Call".into(),
            value: Some("eval".into()),
        },
    );
    metavars.insert(
        "$ARG".into(),
        MetaVar {
            kind: "Identifier".into(),
            value: None,
        },
    );
    let pat = AstPattern {
        kind: "Call".into(),
        within: Some("FunctionDefinition".into()),
        metavariables: metavars,
    };
    CompiledRule {
        id: "py.eval.ast".into(),
        severity: Severity::Low,
        category: "ast".into(),
        message: "eval".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::AstPattern(pat),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["python".into()],
    }
}

#[test]
fn match_eval_inside_function() {
    let file = load_fixture("bad");
    let rules = RuleSet {
        rules: vec![build_rule()],
    };
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
}

#[test]
fn ignore_eval_outside_function() {
    let file = load_fixture("fp");
    let rules = RuleSet {
        rules: vec![build_rule()],
    };
    let findings = analyze_file(&file, &rules);
    assert!(findings.is_empty());
}

#[test]
fn ignore_other_calls() {
    let file = load_fixture("good");
    let rules = RuleSet {
        rules: vec![build_rule()],
    };
    let findings = analyze_file(&file, &rules);
    assert!(findings.is_empty());
}
