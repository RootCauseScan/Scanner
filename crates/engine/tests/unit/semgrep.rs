use super::*;
use loader::Severity;
use regex::Regex;
use std::fs;
use tempfile::tempdir;

#[test]
fn pattern_inside_and_not_inside() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.txt");
    fs::write(&path, "bar(foo())\nfoo()\nbaz(foo())\n").unwrap();
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "ctx.rule".into(),
        severity: Severity::Low,
        category: "semgrep".into(),
        message: "ctx".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegexMulti {
            allow: vec![(Regex::new(r"foo\(\)").unwrap().into(), "foo()".into())],
            deny: None,
            inside: vec![Regex::new(r"bar\([^\)]*\)").unwrap()],
            not_inside: vec![Regex::new(r"baz\([^\)]*\)").unwrap()],
        },
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["txt".into()],
    });
    let mut file = FileIR::new(path.to_string_lossy().into_owned(), "txt".into());
    file.source = Some(fs::read_to_string(&path).unwrap());
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 1);
}

#[test]
fn pattern_not_inside_blocks_match() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.txt");
    fs::write(&path, "foo()\nbaz(foo())\n").unwrap();
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "ctx.not".into(),
        severity: Severity::Low,
        category: "semgrep".into(),
        message: "ctx".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegexMulti {
            allow: vec![(Regex::new(r"foo\(\)").unwrap().into(), "foo()".into())],
            deny: None,
            inside: Vec::new(),
            not_inside: vec![Regex::new(r"baz\([^\)]*\)").unwrap()],
        },
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["txt".into()],
    });
    let mut file = FileIR::new(path.to_string_lossy().into_owned(), "txt".into());
    file.source = Some(fs::read_to_string(&path).unwrap());
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 1);
}

#[test]
fn pattern_not_inside_method_signature() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.txt");
    fs::write(&path, "fn safe() {\nfoo()\n}\n\nfn other() {\nfoo()\n}\n").unwrap();
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "ctx.method".into(),
        severity: Severity::Low,
        category: "semgrep".into(),
        message: "ctx".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegexMulti {
            allow: vec![(Regex::new(r"foo\(\)").unwrap().into(), "foo()".into())],
            deny: None,
            inside: Vec::new(),
            not_inside: vec![Regex::new(r"fn safe\(\)").unwrap()],
        },
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["txt".into()],
    });
    let mut file = FileIR::new(path.to_string_lossy().into_owned(), "txt".into());
    file.source = Some(fs::read_to_string(&path).unwrap());
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].line, 6);
}

#[test]
fn pattern_not_inside_wrong_signature_matches_all() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("test.txt");
    fs::write(&path, "fn safe() {\nfoo()\n}\n\nfn other() {\nfoo()\n}\n").unwrap();
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "ctx.missing".into(),
        severity: Severity::Low,
        category: "semgrep".into(),
        message: "ctx".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegexMulti {
            allow: vec![(Regex::new(r"foo\(\)").unwrap().into(), "foo()".into())],
            deny: None,
            inside: Vec::new(),
            not_inside: vec![Regex::new(r"fn missing\(\)").unwrap()],
        },
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["txt".into()],
    });
    let mut file = FileIR::new(path.to_string_lossy().into_owned(), "txt".into());
    file.source = Some(fs::read_to_string(&path).unwrap());
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 2);
}
#[test]
fn pattern_not_inside_method_signature_with_signwith() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("Test.java");
    fs::write(
        &path,
        "class T {\nvoid good() {\nJwts.builder()\n    .signWith(key);\n}\n}\n",
    )
    .unwrap();
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "ctx.jwt".into(),
        severity: Severity::Low,
        category: "semgrep".into(),
        message: "ctx".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegexMulti {
            allow: vec![
                (
                    Regex::new(r"Jwts\\.builder\\(\\)").unwrap().into(),
                    "Jwts.builder()".into(),
                ),
            ],
            deny: None,
            inside: Vec::new(),
            not_inside: vec![Regex::new(r"void good\(\)[^{]*\{[\s\S]*signWith\(").unwrap()],
        },
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["java".into()],
    });
    let mut file = FileIR::new(path.to_string_lossy().into_owned(), "java".into());
    file.source = Some(fs::read_to_string(&path).unwrap());
    let findings = analyze_file(&file, &rules);
    assert!(findings.is_empty());
}

#[test]
fn pattern_regex_handles_braces() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("debug.yaml"),
        r#"rules:
- id: debug-template-tag
  languages: [regex]
  severity: WARNING
  message: debug tag
  pattern-regex: ({% debug %})
"#,
    )
    .unwrap();
    let rs = loader::load_rules(dir.path()).unwrap();
    let mut file = FileIR::new(
        dir.path().join("t.html").to_string_lossy().into_owned(),
        "html".into(),
    );
    file.source = Some("{% debug %}".into());
    let findings = analyze_file(&file, &rs);
    assert_eq!(findings.len(), 1);
}

#[test]
fn pattern_regex_supports_lookaround() {
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("look.yaml"),
        r#"rules:
- id: lookaround
  languages: [regex]
  severity: WARNING
  message: look
  pattern-regex: foo(?=bar)
"#,
    )
    .unwrap();
    let rs = loader::load_rules(dir.path()).unwrap();
    let mut file = FileIR::new(
        dir.path().join("t.txt").to_string_lossy().into_owned(),
        "txt".into(),
    );
    file.source = Some("foobar".into());
    let findings = analyze_file(&file, &rs);
    assert_eq!(findings.len(), 1);
}
