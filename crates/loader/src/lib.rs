//! Loads rules from YAML, JSON or Rego-WASM modules
//! and compiles them to an internal executable representation.

use anyhow::Context;
use serde_json::Value as JsonValue;
use serde_yaml::Value as YamlValue;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tracing::debug;

pub use patterns::{AstPattern, MetaVar};

mod matchers;
mod regex_types;
pub mod schema;
mod walk;

pub use matchers::{MatcherKind, Query, TaintPattern};
pub use regex_types::{regex_ext, AnyCaptures, AnyMatch, AnyRegex};
pub use schema::compiled::{AstQueryRule, CompiledRule, Example, RuleOptions, RuleSet, Severity};
pub use schema::json::{JsonQuery, JsonRule};
pub use schema::semgrep::{
    relax_semgrep_ellipsis, semgrep_to_regex, semgrep_to_regex_exact, MetavariableRegex,
    SemgrepRule,
};
pub use schema::yaml::{Pattern, YamlRule};
pub use walk::visit;

fn process_rule_file(
    path: &Path,
    base_dir: &Path,
    rs: &mut RuleSet,
    seen_ids: &mut HashSet<String>,
) -> anyhow::Result<()> {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.ends_with(".wasm") {
        debug!(file = %path.display(), "Parsing WASM rule");
        schema::compiled::compile_wasm_rule(rs, seen_ids, path, base_dir)
            .with_context(|| format!("Failed to parse WASM rule file: {}", path.display()))?;
    } else if (name.ends_with(".yaml") || name.ends_with(".yml")) && !name.contains(".wasm.") {
        debug!(file = %path.display(), "Parsing YAML rule");
        let data = fs::read_to_string(path)
            .with_context(|| format!("Failed to read rule file: {}", path.display()))?;
        let doc: YamlValue = serde_yaml::from_str(&data)
            .with_context(|| format!("Failed to parse rule file: {}", path.display()))?;
        schema::yaml::load_yaml_rules(rs, seen_ids, &doc, path, base_dir)?;
    } else if name.ends_with(".json") && !name.contains(".wasm.") {
        debug!(file = %path.display(), "Parsing JSON rule");
        let data = fs::read_to_string(path)
            .with_context(|| format!("Failed to read rule file: {}", path.display()))?;
        let doc: JsonValue = serde_json::from_str(&data)
            .with_context(|| format!("Failed to parse rule file: {}", path.display()))?;
        schema::json::load_json_rules(rs, seen_ids, &doc, path, base_dir)?;
    } else {
        debug!(file = %path.display(), "Skipping non-rule file");
    }
    Ok(())
}

/// Recursively reads a directory and compiles the found rules.
///
/// # Example
/// ```no_run
/// use loader::load_rules;
/// let rules = load_rules(std::path::Path::new("rules")).unwrap();
/// assert!(!rules.rules.is_empty());
/// ```
pub fn load_rules(dir: &Path) -> anyhow::Result<RuleSet> {
    let mut rs = RuleSet::default();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let excl = |p: &Path| {
        p.file_name()
            .and_then(|name| name.to_str())
            .map(|name| name == ".git")
            .unwrap_or(false)
    };

    if dir.is_file() {
        let base = dir.parent().unwrap_or(Path::new("."));
        process_rule_file(dir, base, &mut rs, &mut seen_ids)?;
        return Ok(rs);
    }

    visit(dir, &excl, &mut |path| {
        process_rule_file(path, dir, &mut rs, &mut seen_ids)
    })?;
    Ok(rs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::semgrep::{compile_semgrep_rule, extract_patterns, PatternKind};
    use regex::Regex;
    use std::collections::{HashMap, HashSet};
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn loads_wasm_rule_with_metadata() {
        let dir = tempdir().unwrap();
        let wasm = dir.path().join("test.wasm");
        fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();
        let meta = serde_json::json!({
            "id": "wasm.test",
            "severity": "LOW",
            "message": "msg",
            "remediation": "fix",
            "category": "wasm",
        });
        fs::write(
            dir.path().join("test.wasm.json"),
            serde_json::to_string(&meta).unwrap(),
        )
        .unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        let r = &rs.rules[0];
        assert!(matches!(r.matcher, MatcherKind::RegoWasm { .. }));
        assert_eq!(r.id, "wasm.test");
        assert_eq!(r.severity, Severity::Low);
        assert_eq!(r.message, "msg");
        assert_eq!(r.remediation.as_deref(), Some("fix"));
    }

    #[test]
    fn invalid_wasm_fails() {
        let dir = tempdir().unwrap();
        let wasm = dir.path().join("bad.wasm");
        fs::write(&wasm, b"notwasm").unwrap();
        let err = load_rules(dir.path()).unwrap_err();
        assert!(err.to_string().contains("WASM"));
    }

    #[test]
    fn loads_ast_query_rule() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
  - id: rust.no-println
    severity: LOW
    category: rust
    ast_query:
      kind: "Call"
      value: "println!"
    message: no println
"#;
        fs::write(dir.path().join("rules.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::AstQuery(q) => {
                assert!(q.kind.is_match("Call"));
            }
            _ => panic!("expected ast query"),
        }
    }

    #[test]
    fn loads_semgrep_rule() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.sample
  message: semgrep msg
  severity: LOW
  pattern: foo($X)
"#;
        fs::write(dir.path().join("sem.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegex(re, _) => {
                assert!(re.is_match("foo(123)"));
            }
            _ => panic!("expected text regex"),
        }
    }

    #[test]
    fn loads_semgrep_rule_with_context() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.ctx
  message: semgrep ctx
  severity: LOW
  pattern: foo()
  pattern-inside:
    - pattern: bar(...)
  pattern-not-inside:
    - pattern: baz(...)
"#;
        fs::write(dir.path().join("ctx.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegexMulti {
                inside, not_inside, ..
            } => {
                assert_eq!(inside.len(), 1);
                assert_eq!(not_inside.len(), 1);
            }
            _ => panic!("expected TextRegexMulti"),
        }
    }

    #[test]
    fn extract_patterns_recurses_nested() {
        let yaml: YamlValue = serde_yaml::from_str(
            r#"pattern-either:
  - pattern: foo(...)
  - patterns:
      - pattern-inside: bar(...)
      - pattern-not-inside: baz(...)
"#,
        )
        .unwrap();
        let mut acc = Vec::new();
        let mut seen = HashSet::new();
        extract_patterns(&yaml, None, &mut acc, &mut seen);
        assert_eq!(acc.len(), 3);
        assert!(acc.iter().any(|(k, _)| matches!(k, PatternKind::Pattern)));
        assert!(acc.iter().any(|(k, _)| matches!(k, PatternKind::Inside)));
        assert!(acc.iter().any(|(k, _)| matches!(k, PatternKind::NotInside)));
    }

    #[test]
    fn extract_patterns_ignores_scalars() {
        let yaml: YamlValue = serde_yaml::from_str("just a string").unwrap();
        let mut acc = Vec::new();
        let mut seen = HashSet::new();
        extract_patterns(&yaml, None, &mut acc, &mut seen);
        assert!(acc.is_empty());
    }

    #[test]
    fn loads_semgrep_rule_with_nested_patterns() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.nested
  message: nested
  severity: LOW
  patterns:
    - pattern: foo(...)
      pattern-either:
        - pattern-inside: bar(...)
        - pattern-not-inside: baz(...)
"#;
        fs::write(dir.path().join("nested.yml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegexMulti { allow, inside, .. } => {
                assert_eq!(allow.len(), 1);
                assert_eq!(inside.len(), 1);
            }
            _ => panic!("expected TextRegexMulti"),
        }
    }

    #[test]
    fn relax_semgrep_handles_commas() {
        let input = "foo(?, ?, ...)".to_string();
        let output = relax_semgrep_ellipsis(input);
        assert!(output.contains("?:"));
    }

    #[test]
    fn semgrep_to_regex_preserves_braces() {
        let mv = HashMap::new();
        let re = Regex::new(&semgrep_to_regex("{% debug %}", &mv)).unwrap();
        assert!(re.is_match("{% debug %}"));
    }

    #[test]
    fn semgrep_to_regex_exact_preserves_braces() {
        let mv = HashMap::new();
        let re = Regex::new(&semgrep_to_regex_exact("{% debug %}", &mv)).unwrap();
        assert!(re.is_match("{% debug %}"));
    }

    #[test]
    fn metavariable_regex_filters_matches() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.metavar
  message: test
  severity: LOW
  pattern: foo($X)
  metavariable-regex:
    - metavariable: $X
      regex: "^\\d+$"
"#;
        fs::write(dir.path().join("mv.yml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegex(re, _) => {
                assert!(re.is_match("foo(123)"));
                assert!(!re.is_match("foo(bar)"));
            }
            _ => panic!("expected text regex"),
        }
    }

    #[test]
    fn invalid_metavariable_regex_fails() {
        let dir = tempdir().unwrap();
        let bad = "rules:\n- id: bad\n  pattern: foo($X)\n  metavariable-regex: oops\n";
        fs::write(dir.path().join("bad.yml"), bad).unwrap();
        let err = load_rules(dir.path()).unwrap_err();
        assert!(err.downcast_ref::<serde_yaml::Error>().is_some());
    }

    #[test]
    fn loads_semgrep_pattern_regex_rule() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.pattern-regex
  message: regex msg
  severity: LOW
  pattern-regex: "(xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26})"
"#;
        fs::write(dir.path().join("pr.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegex(re, _) => {
                assert!(re.is_match("xoxb-12345678-abcdefghijklmnopqr"));
            }
            _ => panic!("expected text regex"),
        }
    }

    #[test]
    fn loads_semgrep_metavariable_pattern_rule() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: semgrep.metavariable-pattern
  message: double free
  severity: LOW
  patterns:
    - pattern: |
        free($VAR);
        ...
        $FREE($VAR);
    - metavariable-pattern:
        metavariable: $FREE
        pattern: $FREE
  metavariable-regex:
    - metavariable: $FREE
      regex: free|release
"#;
        fs::write(dir.path().join("mvpat.yaml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TextRegexMulti { allow, .. } => {
                let snippet = "free(ptr);\nlog(ptr);\nrelease(ptr);";
                assert!(allow.iter().any(|(re, _)| re.is_match(snippet)));
            }
            _ => panic!("expected TextRegexMulti"),
        }
    }

    #[test]
    fn loads_json_rule() {
        let dir = tempdir().unwrap();
        let rule_json = r#"{
  "rules": {
    "docker": {
      "no-latest": {
        "severity": "HIGH",
        "query": {
          "path": "$.services[*].image",
          "pattern": ":latest$",
          "message": "Evita tags latest",
          "remediation": "Usa versiones fijas"
        }
      }
    }
  }
}"#;
        fs::write(dir.path().join("rule.json"), rule_json).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::JsonPathRegex(path, re) => {
                assert_eq!(path, "$.services[*].image");
                assert!(re.is_match("nginx:latest"));
            }
            _ => panic!("expected json path regex"),
        }
    }

    #[test]
    fn invalid_json_rule_fails() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("bad.json"), "{not json").unwrap();
        let err = load_rules(dir.path()).unwrap_err();
        assert!(err.downcast_ref::<serde_json::Error>().is_some());
    }

    #[test]
    fn loads_java_rules() {
        use std::path::PathBuf;
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/rules/java");
        let rs = load_rules(&dir).expect("load java rules");
        assert!(rs.rules.iter().any(|r| r.id == "java.no-system-exit"));
    }

    #[test]
    fn loads_taint_rule() {
        let dir = tempdir().unwrap();
        let rule_yaml = r#"rules:
- id: example-taint-rule
  message: Example taint rule
  languages: [python]
  severity: error
  mode: taint
  pattern-sources:
    - patterns:
        - pattern: input($X)
  pattern-sinks:
    - patterns:
        - pattern: eval($X)
"#;
        fs::write(dir.path().join("taint.yml"), rule_yaml).unwrap();
        let rs = load_rules(dir.path()).unwrap();
        assert_eq!(rs.rules.len(), 1);
        match &rs.rules[0].matcher {
            MatcherKind::TaintRule {
                sources,
                sanitizers,
                reclass,
                sinks,
            } => {
                assert!(!sources.is_empty());
                assert!(sanitizers.is_empty());
                assert!(reclass.is_empty());
                assert!(!sinks.is_empty());
            }
            _ => panic!("expected taint rule"),
        }
    }

    #[test]
    fn invalid_taint_rule_fails() {
        let dir = tempdir().unwrap();
        let bad = "rules:\n- id: bad\n  pattern-sources: oops\n";
        fs::write(dir.path().join("bad.yml"), bad).unwrap();
        let err = load_rules(dir.path()).unwrap_err();
        assert!(err.downcast_ref::<serde_yaml::Error>().is_some());
    }

    #[test]
    fn taint_rule_propagates_focus() {
        let sr_yaml = r#"id: focus
message: msg
severity: LOW
pattern-sources:
  - patterns:
      - pattern: |
          $VAR = source()
pattern-sinks:
  - patterns:
      - pattern: |
          sink($VAR)
focus-metavariable: $VAR
"#;
        let sr: SemgrepRule = serde_yaml::from_str(sr_yaml).unwrap();
        let mut rs = RuleSet::default();
        let mut seen = HashSet::new();
        let file_path = Path::new("rules/test.yaml");
        let base_dir = Path::new("rules");
        compile_semgrep_rule(&mut rs, &mut seen, sr, file_path, base_dir).unwrap();
        match &rs.rules[0].matcher {
            MatcherKind::TaintRule { sources, .. } => {
                assert_eq!(sources[0].focus.as_deref(), Some("$VAR"));
            }
            _ => panic!("expected taint rule"),
        }
    }

    #[test]
    fn semgrep_to_regex_handles_string_regex() {
        let mut mv = HashMap::new();
        mv.insert("X".to_string(), ".*".to_string());
        let re = semgrep_to_regex("a = \'value\' and b =~/foo/", &mv);
        assert!(Regex::new(&re)
            .unwrap()
            .is_match("a = 'value' and b =\"foo\""));
    }

    #[test]
    fn semgrep_to_regex_exact_handles_string_regex() {
        let mut mv = HashMap::new();
        mv.insert("X".to_string(), ".*".to_string());
        let re = semgrep_to_regex_exact("a = \'value\' and b =~/foo/", &mv);
        assert!(Regex::new(&re)
            .unwrap()
            .is_match("a = 'value' and b =\"foo\""));
    }
}
