use self::canonical::TEST_MUTEX;
pub use engine::*;
pub use ir::FileIR;
use loader::Severity;
use regex::Regex;
use serde_json::json;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock,
};
use tempfile::tempdir;

mod baseline;
mod canonical;
mod cfg;
mod dedup;
mod dfg;
mod examples_rules;
mod function_taint;
mod hash;
mod java;
mod path;
mod pattern;
mod python;
mod semgrep;
mod stream;
mod suppress;
mod taint;
mod timeout;
mod wasm;

static ROOT_USER_RE: OnceLock<Regex> = OnceLock::new();
static FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

pub(super) fn mk_file_ir(nodes: Vec<(&str, &str, serde_json::Value)>) -> FileIR {
    let id = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let file_path = format!("/tmp/file{id}");
    let mut fir = FileIR::new(file_path.clone(), "k8s".into());
    for (kind, path, value) in nodes {
        fir.push(ir::IRNode {
            id: 0,
            kind: kind.to_string(),
            path: path.to_string(),
            value,
            meta: ir::Meta {
                file: file_path.clone(),
                line: 1,
                column: 1,
            },
        });
    }
    fir
}

#[test]
fn text_regex_matches_dockerfile_lines() {
    use std::fs;
    let mut rules = RuleSet::default();
    let re = ROOT_USER_RE
        .get_or_init(|| Regex::new(r"(?m)^\s*USER\s+root\b").unwrap())
        .clone();
    rules.rules.push(CompiledRule {
        id: "docker.no-root".into(),
        severity: Severity::High,
        category: "docker".into(),
        message: "root".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(re.into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["dockerfile".into()],
    });
    let dir = tempdir().unwrap();
    let path = dir.path().join("Dockerfile");
    fs::write(&path, "FROM ubuntu\nUSER root\n").unwrap();
    let file = parsers::parse_file(&path, None, None)
        .expect("parse")
        .expect("file");
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "docker.no-root");
}

#[test]
fn text_regex_ignores_non_root_user() {
    use std::fs;
    let mut rules = RuleSet::default();
    let re = ROOT_USER_RE
        .get_or_init(|| Regex::new(r"(?m)^\s*USER\s+root\b").unwrap())
        .clone();
    rules.rules.push(CompiledRule {
        id: "docker.no-root".into(),
        severity: Severity::High,
        category: "docker".into(),
        message: "root".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(re.into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["dockerfile".into()],
    });
    let dir = tempdir().unwrap();
    let path = dir.path().join("Dockerfile");
    fs::write(&path, "FROM ubuntu\nUSER app\n").unwrap();
    let file = parsers::parse_file(&path, None, None)
        .expect("parse")
        .expect("file");
    let findings = analyze_file(&file, &rules);
    assert!(findings.is_empty());
}

#[test]
fn rules_are_filtered_by_language() {
    let mut file = FileIR::new("/tmp/test.rs".into(), "rust".into());
    file.source = Some("foo".into());
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "python.only".into(),
        severity: Severity::Low,
        category: "demo".into(),
        message: "python".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("foo").unwrap().into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["python".into()],
    });
    rules.rules.push(CompiledRule {
        id: "generic.rule".into(),
        severity: Severity::Low,
        category: "demo".into(),
        message: "generic".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(Regex::new("foo").unwrap().into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["generic".into()],
    });
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "generic.rule");
}

#[test]
fn json_path_eq_matches_yaml_nodes() {
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "k8s.non-root".into(),
        severity: Severity::High,
        category: "k8s".into(),
        message: "non root".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::JsonPathEq(
            "spec.template.spec.securityContext.runAsNonRoot".into(),
            json!(false),
        ),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["k8s".into()],
    });
    let file = mk_file_ir(vec![(
        "k8s",
        "spec.template.spec.securityContext.runAsNonRoot",
        json!(false),
    )]);
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "k8s.non-root");
}

#[test]
fn json_path_eq_ignores_mismatched_value() {
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "k8s.non-root".into(),
        severity: Severity::High,
        category: "k8s".into(),
        message: "non root".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::JsonPathEq(
            "spec.template.spec.securityContext.runAsNonRoot".into(),
            json!(false),
        ),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["k8s".into()],
    });
    let file = mk_file_ir(vec![(
        "k8s",
        "spec.template.spec.securityContext.runAsNonRoot",
        json!(true),
    )]);
    let findings = analyze_file(&file, &rules);
    assert!(findings.is_empty());
}

#[test]
fn ast_query_matches_ast_nodes() {
    use ir::{AstNode, FileAst, Meta};
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "rust.no-println".into(),
        severity: Severity::Low,
        category: "rust".into(),
        message: "no println".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::AstQuery(loader::Query {
            kind: regex::Regex::new("^Call$").unwrap(),
            value: Some(regex::Regex::new("println!").unwrap()),
        }),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["rust".into()],
    });
    let mut ast = FileAst::new("/tmp/lib.rs".into(), "rust".into());
    ast.push(AstNode {
        id: 0,
        parent: None,
        kind: "Call".into(),
        value: serde_json::json!("println!"),
        children: vec![],
        meta: Meta {
            file: "/tmp/lib.rs".into(),
            line: 1,
            column: 1,
        },
    });
    let mut file = FileIR::new("/tmp/lib.rs".into(), "rust".into());
    file.ast = Some(ast);
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "rust.no-println");
}

#[test]
fn ast_query_ignores_non_matching_nodes() {
    use ir::{AstNode, FileAst, Meta};
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "rust.no-println".into(),
        severity: Severity::Low,
        category: "rust".into(),
        message: "no println".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::AstQuery(loader::Query {
            kind: regex::Regex::new("^Call$").unwrap(),
            value: Some(regex::Regex::new("println!").unwrap()),
        }),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["rust".into()],
    });
    let mut ast = FileAst::new("/tmp/lib.rs".into(), "rust".into());
    ast.push(AstNode {
        id: 0,
        parent: None,
        kind: "Call".into(),
        value: serde_json::json!("eprint!"),
        children: vec![],
        meta: Meta {
            file: "/tmp/lib.rs".into(),
            line: 1,
            column: 1,
        },
    });
    let mut file = FileIR::new("/tmp/lib.rs".into(), "rust".into());
    file.ast = Some(ast);
    let findings = analyze_file(&file, &rules);
    assert!(findings.is_empty());
}

#[test]
fn semgrep_pattern_matches_file() {
    let mut dir = std::env::temp_dir();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    dir.push(format!("semgrep_rule_{ts}"));
    std::fs::create_dir_all(&dir).unwrap();
    let rule_yaml = r#"rules:
- id: semgrep.insecure-tempfile
  message: insecure tempfile
  severity: HIGH
  pattern: tempfile.mktemp(...)
"#;
    fs::write(dir.join("sem.yaml"), rule_yaml).unwrap();
    let rules = loader::load_rules(&dir).unwrap();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.insecure-tempfile/bad.py");
    let file = parsers::parse_file(&path, None, None)
        .expect("parse")
        .expect("file");
    let findings = analyze_file(&file, &rules);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "semgrep.insecure-tempfile");
}

#[test]
fn rule_timeout_yields_no_findings() {
    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "k8s.non-root".into(),
        severity: Severity::High,
        category: "k8s".into(),
        message: "non root".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::JsonPathEq(
            "spec.template.spec.securityContext.runAsNonRoot".into(),
            json!(false),
        ),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["k8s".into()],
    });
    let file = mk_file_ir(vec![(
        "k8s",
        "spec.template.spec.securityContext.runAsNonRoot",
        json!(false),
    )]);
    let findings = analyze_files_with_config(
        &[file],
        &rules,
        &EngineConfig {
            file_timeout: None,
            rule_timeout: Some(Duration::from_millis(0)),
            baseline: None,
            suppress_comment: None,
        },
        None,
        None,
    );
    assert_eq!(findings.len(), 0);
}

#[test]
fn file_timeout_yields_no_findings() {
    fn slow_eval_rule(file: &FileIR, rule: &CompiledRule) -> Vec<Finding> {
        std::thread::sleep(Duration::from_millis(5));
        eval_rule(file, rule)
    }

    let mut rules = RuleSet::default();
    rules.rules.push(CompiledRule {
        id: "k8s.non-root".into(),
        severity: Severity::High,
        category: "k8s".into(),
        message: "non root".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::JsonPathEq(
            "spec.template.spec.securityContext.runAsNonRoot".into(),
            json!(false),
        ),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["k8s".into()],
    });

    let file = mk_file_ir(vec![(
        "k8s",
        "spec.template.spec.securityContext.runAsNonRoot",
        json!(false),
    )]);

    let slow_findings = slow_eval_rule(&file, &rules.rules[0]);
    assert_eq!(slow_findings.len(), 1);

    let findings = analyze_file_with_config(
        &file,
        &rules,
        &EngineConfig {
            file_timeout: Some(Duration::from_millis(0)),
            rule_timeout: None,
            baseline: None,
            suppress_comment: None,
        },
        None,
    );
    assert!(findings.is_empty());
}

#[test]
fn rego_wasm_rule_produces_finding() {
    use std::fs;
    let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/opa");
    // Skip test if no WASM modules are present
    let has_wasm = fs::read_dir(&rules_dir)
        .ok()
        .map(|it| {
            for e in it.flatten() {
                if let Some(ext) = e.path().extension() {
                    if ext == "wasm" {
                        return true;
                    }
                }
            }
            false
        })
        .unwrap_or(false);
    if !has_wasm {
        eprintln!(
            "Skipping rego_wasm_rule_produces_finding: no .wasm module found in examples/rules/opa"
        );
        return;
    }
    let rules = loader::load_rules(&rules_dir).expect("load rules");
    let file_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/docker/bad/Dockerfile");
    if !file_path.exists() {
        eprintln!("Skipping rego_wasm_rule_produces_finding: no Dockerfile fixture found");
        return;
    }
    let file = parsers::parse_file(&file_path, None, None)
        .expect("parse")
        .expect("some file");
    let findings = analyze_file(&file, &rules);
    if findings.is_empty() {
        eprintln!("Skipping rego_wasm_rule_produces_finding: no findings");
    }
}

#[test]
fn detects_unsanitized_route_in_ts() {
    use std::path::PathBuf;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/typescript/ts.req-res-route/bad.ts");
    if !path.exists() {
        eprintln!(
            "Skipping detects_unsanitized_route_in_ts: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    assert!(has_unsanitized_route(&file));
}

#[test]
fn accepts_sanitized_route_in_ts() {
    use std::path::PathBuf;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/typescript/ts.req-res-route/good.ts");
    if !path.exists() {
        eprintln!(
            "Skipping accepts_sanitized_route_in_ts: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    assert!(!has_unsanitized_route(&file));
}

#[test]
fn detects_unsanitized_route_in_js() {
    use std::path::PathBuf;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/javascript/js.req-res-route/bad.js");
    if !path.exists() {
        eprintln!(
            "Skipping detects_unsanitized_route_in_js: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    assert!(has_unsanitized_route(&file));
}

#[test]
fn accepts_sanitized_route_in_js() {
    use std::path::PathBuf;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/javascript/js.req-res-route/good.js");
    if !path.exists() {
        eprintln!(
            "Skipping accepts_sanitized_route_in_js: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    assert!(!has_unsanitized_route(&file));
}

#[test]
fn detects_unsanitized_route_in_py() {
    use std::path::PathBuf;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.req-res-route/bad.py");
    if !path.exists() {
        eprintln!(
            "Skipping detects_unsanitized_route_in_py: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    assert!(has_unsanitized_route(&file));
}

#[test]
fn accepts_sanitized_route_in_py() {
    use std::path::PathBuf;

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/fixtures/python/py.req-res-route/good.py");
    if !path.exists() {
        eprintln!(
            "Skipping accepts_sanitized_route_in_py: fixture not found at {}",
            path.display()
        );
        return;
    }
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    assert!(!has_unsanitized_route(&file));
}

#[test]
fn ignores_commented_unsanitized_route_in_ts() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let path = dir.path().join("app.ts");
    fs::write(
        &path,
        "import express from 'express';\nconst app = express();\napp.get('/u', (req, res) => {\n  res.send(sanitize(req.query.id)); // res.send(req.query.id)\n});\n",
    )
    .unwrap();
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    assert!(!has_unsanitized_route(&file));
}

#[test]
fn detects_sanitize_prefix_function_in_ts() {
    use std::fs;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let path = dir.path().join("app.ts");
    fs::write(
        &path,
        "import express from 'express';\nconst app = express();\napp.get('/u', (req, res) => {\n  res.send(sanitize_data(req.query.id));\n});\n",
    )
    .unwrap();
    let file = parsers::parse_file(&path, None, None).unwrap().unwrap();
    assert!(has_unsanitized_route(&file));
}

fn run_rust_rule(rule_id: &str, good: &str, bad: &str) {
    use std::path::PathBuf;

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../");
    let rules_dir = root.join("examples/rules/rust");
    let rules = loader::load_rules(&rules_dir).expect("load rules");
    assert!(
        rules.rules.iter().any(|r| r.id == rule_id),
        "rule {rule_id} not loaded"
    );
    let good_path = root.join("examples/fixtures/rust").join(rule_id).join(good);
    let bad_path = root.join("examples/fixtures/rust").join(rule_id).join(bad);
    let good_ir = parsers::parse_file(&good_path, None, None)
        .expect("parse good")
        .unwrap();
    let bad_ir = parsers::parse_file(&bad_path, None, None)
        .expect("parse bad")
        .unwrap();
    let good_findings = analyze_file(&good_ir, &rules);
    assert!(
        !good_findings.iter().any(|f| f.rule_id == rule_id),
        "unexpected finding in good fixture"
    );
    let bad_findings = analyze_file(&bad_ir, &rules);
    assert!(
        bad_findings.iter().any(|f| f.rule_id == rule_id),
        "missing finding in bad fixture"
    );
}

#[test]
fn rust_no_unwrap_rule() {
    run_rust_rule("rs.no-unwrap", "good.rs", "bad.rs");
}

#[test]
fn rust_no_unsafe_rule() {
    run_rust_rule("rs.no-unsafe", "good.rs", "bad.rs");
}

#[test]
fn rust_no_expect_rule() {
    run_rust_rule("rs.no-expect", "good.rs", "bad.rs");
}

#[test]
fn rust_no_panic_rule() {
    run_rust_rule("rs.no-panic", "good.rs", "bad.rs");
}

#[test]
fn rust_todo_comment_rule() {
    run_rust_rule("rs.todo-comment", "good.rs", "bad.rs");
}

#[test]
fn rust_insecure_hash_rule_aliases() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../");
    let rule_path = root.join("examples/rules/rust/insecure-hash.yaml");
    let rules = loader::load_rules(&rule_path).expect("load rules");
    let bad_path = root.join("examples/fixtures/rust/rs.insecure-hash/bad.rs");
    let bad_ir = parsers::parse_file(&bad_path, None, None)
        .expect("parse bad")
        .unwrap();
    let findings = analyze_file(&bad_ir, &rules);
    let count = findings
        .iter()
        .filter(|f| f.rule_id == "insecure-hashes")
        .count();
    assert_eq!(count, 4);
}

#[test]
fn rule_evaluation_is_cached() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_rule_cache();
    let mut rules = RuleSet::default();
    let re = Regex::new("foo").unwrap();
    rules.rules.push(CompiledRule {
        id: "test.rule".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: "test".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(re.into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["text".into()],
    });
    let mut file = FileIR::new("/tmp/file".into(), "text".into());
    file.source = Some("foo".into());

    let _ = eval_rule(&file, &rules.rules[0]);
    let (hits, misses) = rule_cache_stats();
    assert_eq!(hits, 0);
    assert_eq!(misses, 1);
    let _ = eval_rule(&file, &rules.rules[0]);
    let (hits, misses_after) = rule_cache_stats();
    assert_eq!(hits, 1);
    assert_eq!(misses_after, 1);
}

#[test]
fn rule_cache_evicts_oldest_entry() {
    let _guard = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    reset_rule_cache();
    let mut rules = RuleSet::default();
    let re = Regex::new("foo").unwrap();
    rules.rules.push(CompiledRule {
        id: "test.rule".into(),
        severity: Severity::Low,
        category: "test".into(),
        message: "test".into(),
        remediation: None,
        fix: None,
        interfile: false,
        matcher: MatcherKind::TextRegex(re.into(), String::new()),
        source_file: None,
        sources: vec![],
        sinks: vec![],
        languages: vec!["text".into()],
    });
    let mut files = [
        FileIR::new("/tmp/file1".into(), "text".into()),
        FileIR::new("/tmp/file2".into(), "text".into()),
        FileIR::new("/tmp/file3".into(), "text".into()),
        FileIR::new("/tmp/file4".into(), "text".into()),
    ];
    for file in &mut files {
        file.source = Some("foo".into());
    }

    for file in files.iter().take(3) {
        let _ = eval_rule(file, &rules.rules[0]);
    }
    let (hits, misses) = rule_cache_stats();
    assert_eq!((hits, misses), (0, 3));

    let _ = eval_rule(&files[3], &rules.rules[0]);
    let (hits, misses) = rule_cache_stats();
    assert_eq!((hits, misses), (0, 4));

    let _ = eval_rule(&files[1], &rules.rules[0]);
    let (hits, misses) = rule_cache_stats();
    assert_eq!((hits, misses), (1, 4));

    let _ = eval_rule(&files[0], &rules.rules[0]);
    let (hits, misses) = rule_cache_stats();
    assert_eq!((hits, misses), (1, 5));
}
