use crate::matchers::{MatcherKind, Query};
use crate::schema::compiled::{
    normalize_languages, AstQueryRule, CompiledRule, RuleOptions, RuleSet, Severity,
};
use anyhow::anyhow;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Rule expressed in simplified JSON.
pub struct JsonRule {
    pub description: Option<String>,
    pub severity: Option<String>,
    pub query: Option<JsonQuery>,
    pub ast_query: Option<AstQueryRule>,
    #[serde(rename = "ast-pattern")]
    pub ast_pattern: Option<patterns::AstPattern>,
    #[serde(default, deserialize_with = "crate::schema::deserialize_languages")]
    pub languages: Option<Vec<String>>,
    #[serde(default)]
    pub options: RuleOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// JSONPath query used by [`JsonRule`].
pub struct JsonQuery {
    pub r#type: Option<String>,
    pub path: Option<String>,
    pub value: Option<JsonValue>,
    pub pattern: Option<String>,
    pub message: Option<String>,
    pub remediation: Option<String>,
    pub fix: Option<String>,
}

pub(crate) fn compile_json_rule(
    rs: &mut RuleSet,
    seen: &mut HashSet<String>,
    id: String,
    jr: JsonRule,
    file_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    if !seen.insert(id.clone()) {
        anyhow::bail!("duplicate rule id: {id}");
    }
    let severity: Severity = jr
        .severity
        .as_deref()
        .unwrap_or("MEDIUM")
        .parse()
        .map_err(|e: String| anyhow!(e))?;
    let description = jr.description.clone().unwrap_or_default();
    let inferred_languages = jr.languages.clone().or_else(|| {
        jr.query
            .as_ref()
            .and_then(|q| q.r#type.clone().map(|t| vec![t]))
    });
    let languages = normalize_languages(inferred_languages);
    let source_file = file_path
        .strip_prefix(base_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    if let Some(q) = jr.query {
        if let (Some(path), Some(val)) = (q.path.clone(), q.value.clone()) {
            rs.rules.push(CompiledRule {
                id: id.clone(),
                severity,
                category: "json".into(),
                message: q.message.clone().unwrap_or_else(|| description.clone()),
                remediation: q.remediation.clone(),
                fix: q.fix.clone(),
                interfile: jr.options.interfile,
                matcher: MatcherKind::JsonPathEq(path, val),
                source_file: source_file.clone(),
                sources: Vec::new(),
                sinks: Vec::new(),
                languages: languages.clone(),
            });
        }
        if let (Some(path), Some(pat)) = (q.path, q.pattern) {
            let re = Regex::new(&pat)?;
            rs.rules.push(CompiledRule {
                id: id.clone(),
                severity,
                category: "json".into(),
                message: q.message.unwrap_or_else(|| "".into()),
                remediation: None,
                fix: q.fix.clone(),
                interfile: jr.options.interfile,
                matcher: MatcherKind::JsonPathRegex(path, re),
                source_file: source_file.clone(),
                sources: Vec::new(),
                sinks: Vec::new(),
                languages: languages.clone(),
            });
        }
    }
    if let Some(aq) = jr.ast_query {
        let kind = Regex::new(&aq.kind)?;
        let value = match aq.value {
            Some(v) => Some(Regex::new(&v)?),
            None => None,
        };
        rs.rules.push(CompiledRule {
            id: id.clone(),
            severity,
            category: "ast".into(),
            message: description.clone(),
            remediation: None,
            fix: None,
            interfile: jr.options.interfile,
            matcher: MatcherKind::AstQuery(Query { kind, value }),
            source_file: source_file.clone(),
            sources: Vec::new(),
            sinks: Vec::new(),
            languages: languages.clone(),
        });
    }
    if let Some(ap) = jr.ast_pattern {
        rs.rules.push(CompiledRule {
            id,
            severity,
            category: "ast".into(),
            message: description,
            remediation: None,
            fix: None,
            interfile: jr.options.interfile,
            matcher: MatcherKind::AstPattern(ap),
            source_file,
            sources: Vec::new(),
            sinks: Vec::new(),
            languages,
        });
    }
    Ok(())
}

pub(crate) fn load_json_rules(
    rs: &mut RuleSet,
    seen_ids: &mut HashSet<String>,
    doc: &serde_json::Value,
    file_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    if let Some(obj) = doc.get("rules").and_then(|v| v.as_object()) {
        for (ns, category_obj) in obj {
            if let Some(inner) = category_obj.as_object() {
                for (id, rule_v) in inner {
                    let jr: JsonRule = serde_json::from_value(rule_v.clone())?;
                    compile_json_rule(rs, seen_ids, format!("{ns}.{id}"), jr, file_path, base_dir)?;
                }
            }
        }
    }
    Ok(())
}
