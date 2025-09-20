use crate::matchers::{MatcherKind, TaintPattern};
use crate::regex_types::AnyRegex;
use crate::schema::compiled::{
    log_rule_summary, normalize_languages, CompiledRule, RuleOptions, RuleSet, Severity,
};
use anyhow::{anyhow, bail};
use fancy_regex::Regex as FancyRegex;
use pcre2::bytes::Regex as Pcre2Regex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::{self, Value as YamlValue};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::OnceLock;
use tracing::debug;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Subset of rules compatible con Semgrep.
pub struct SemgrepRule {
    pub id: String,
    pub message: Option<String>,
    pub severity: Option<String>,
    pub mode: Option<String>,
    pub pattern: Option<String>,
    #[serde(rename = "pattern-regex")]
    pub pattern_regex: Option<String>,
    #[serde(rename = "patterns")]
    pub patterns: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-either")]
    pub pattern_either: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-not")]
    pub pattern_not: Option<String>,
    #[serde(rename = "pattern-inside")]
    pub pattern_inside: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-not-inside")]
    pub pattern_not_inside: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-sources")]
    pub pattern_sources: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-sanitizers")]
    pub pattern_sanitizers: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-sinks")]
    pub pattern_sinks: Option<Vec<YamlValue>>,
    #[serde(rename = "pattern-reclass")]
    pub pattern_reclass: Option<Vec<YamlValue>>,
    #[serde(rename = "metavariable-pattern")]
    pub metavariable_pattern: Option<YamlValue>,
    #[serde(rename = "metavariable-regex")]
    pub metavariable_regex: Option<Vec<MetavariableRegex>>,
    #[serde(rename = "focus-metavariable")]
    pub focus_metavariable: Option<String>,
    pub fix: Option<String>,
    #[serde(default, deserialize_with = "crate::schema::deserialize_languages")]
    pub languages: Option<Vec<String>>,
    #[serde(default)]
    pub options: RuleOptions,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetavariableRegex {
    pub metavariable: String,
    pub regex: String,
}

fn normalize_metavariable_regex(raw: &str) -> String {
    raw.replace("\\A", "^")
        .replace("\\Z", "$")
        .replace("\\z", "$")
}

/// Compiles a regex string with PCRE2 support for pattern-regex and metavariable-regex,
/// falling back to FancyRegex for other patterns.
fn compile_regex_with_pcre2_fallback(
    pattern: &str,
    is_pattern_regex: bool,
    rule_id: &str,
    file_path: &str,
) -> anyhow::Result<AnyRegex> {
    let needs_pcre2 = is_pattern_regex
        || pattern.contains("[") && pattern.contains("]")
        || pattern.contains("(?<")
        || pattern.contains("(?=")
        || pattern.contains("(?!");

    if needs_pcre2 {
        match Pcre2Regex::new(pattern) {
            Ok(re) => {
                tracing::debug!(
                    rule_id = %rule_id,
                    file = %file_path,
                    pattern_type = if is_pattern_regex { "pattern-regex" } else { "complex-pattern" },
                    "Successfully compiled with PCRE2"
                );
                return Ok(AnyRegex::Pcre2(re));
            }
            Err(e) => {
                tracing::debug!(
                    rule_id = %rule_id,
                    file = %file_path,
                    pattern_type = if is_pattern_regex { "pattern-regex" } else { "complex-pattern" },
                    pcre2_error = %e,
                    "PCRE2 compilation failed, falling back to FancyRegex"
                );
            }
        }
    }

    match FancyRegex::new(pattern) {
        Ok(re) => {
            tracing::debug!(
                rule_id = %rule_id,
                file = %file_path,
                pattern_type = if is_pattern_regex { "pattern-regex-fallback" } else { "pattern" },
                "Successfully compiled with FancyRegex"
            );
            Ok(AnyRegex::Fancy(re))
        }
        Err(e) => {
            bail!(
                "Failed to compile regex for rule '{}' in file '{}': {}. Pattern: {}",
                rule_id,
                file_path,
                e,
                if pattern.len() > 100 {
                    format!("{}...", &pattern[..100])
                } else {
                    pattern.to_string()
                }
            );
        }
    }
}

fn is_pure_lookaround(re_str: &str) -> bool {
    if !(re_str.starts_with("(?=")
        || re_str.starts_with("(?!")
        || re_str.starts_with("(?<=")
        || re_str.starts_with("(?<!"))
    {
        return false;
    }
    let bytes = re_str.as_bytes();
    let mut depth = 0isize;
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return i == bytes.len() - 1;
            }
        }
        i += 1;
    }
    false
}

pub fn relax_semgrep_ellipsis(segment: String) -> String {
    static TRAILING_COMMA: OnceLock<Regex> = OnceLock::new();
    static LEADING_COMMA: OnceLock<Regex> = OnceLock::new();

    let trailing = TRAILING_COMMA.get_or_init(|| {
        Regex::new(r"(?P<ell>\.\*\?)(?P<comma>,(?:\\s[+*](?:\\?)?|\\s+)?)")
            .expect("valid trailing ellipsis regex")
    });
    let leading = LEADING_COMMA.get_or_init(|| {
        Regex::new(r"(?P<comma>,(?:\\s[+*](?:\\?)?|\\s+)?)?(?P<ell>\.\*\?)")
            .expect("valid leading ellipsis regex")
    });

    let mut normalized = segment.replace("\\.\\.\\.", ".*?");
    if normalized.contains("...") {
        normalized = normalized.replace("...", ".*?");
    }

    let mut result = trailing
        .replace_all(&normalized, "(?:$ell$comma)?")
        .into_owned();
    result = leading.replace_all(&result, "(?:$comma$ell)?").into_owned();

    result = result.replace("(?:)?", "");
    result = result.replace("(?:.*?,\\s+\\)?{", "(?:.*?,\\s+)?{");
    result = result.replace("(?:.*?,\\s+\\)?}", "(?:.*?,\\s+)?}");
    result = result.replace("(?:.*?,\\s+\\)?(", "(?:.*?,\\s+)?(");
    result = result.replace("(?:.*?,\\s+\\)?)", "(?:.*?,\\s+)?)");
    result = result.replace("(?:,\\s+.*?)?\\)", "(?:,\\s+.*?)?");

    if result.contains("dict\\(") && !result.contains("dict\\(.*\\)") {
        if let Some(pos) = result.rfind("dict\\(") {
            let after_dict = &result[pos + 6..];
            if !after_dict.contains("\\).*") {
                result = result.replace(".*", "\\).*");
            }
        }
    }

    result
}

pub fn semgrep_to_regex(pattern: &str, mv: &HashMap<String, String>) -> String {
    fn esc(seg: &str) -> String {
        let mut out = String::new();
        for ch in seg.chars() {
            match ch {
                '{' | '}' | '[' | ']' => {
                    out.push('\\');
                    out.push(ch);
                }
                _ => out.push_str(&regex::escape(&ch.to_string())),
            }
        }
        out
    }

    fn handle_string_regex(seg: &str) -> String {
        if let Some(start) = seg.find("=~/") {
            let mut end_pos = None;
            let search_start = start + 3;
            let mut i = search_start;
            while i < seg.len() {
                if seg.chars().nth(i) == Some('/')
                    && (i == 0 || seg.chars().nth(i - 1) != Some('\\'))
                {
                    end_pos = Some(i);
                }
                i += 1;
            }

            if let Some(end) = end_pos {
                let regex_part = &seg[search_start..end];
                let prefix = seg[..start].trim_end();
                let suffix = &seg[end + 1..];
                let mut out = String::new();
                out.push_str(&esc(prefix));
                out.push_str("\\s*=~?\\s*");
                let quoted_double = regex_part.replace("\"", "\\\"");
                let quoted_single = regex_part.replace("'", "\\'");
                out.push_str(&format!(
                    r#"(?:"{0}"|'{1}'|{2})"#,
                    quoted_double, quoted_single, regex_part
                ));
                out.push_str(&esc(suffix));
                return out;
            }
        }
        esc(seg)
    }
    let metav = Regex::new(r"\$[A-Za-z_][A-Za-z0-9_]*").expect("valid metavariable regex");
    let mut p = String::new();
    let mut last = 0;
    for m in metav.find_iter(pattern) {
        p.push_str(&handle_string_regex(&pattern[last..m.start()]));
        let var = &pattern[m.start() + 1..m.end()];
        if let Some(r) = mv.get(var) {
            let anchored = normalize_metavariable_regex(r);
            let trimmed = anchored.trim_start_matches('^').trim_end_matches('$');
            if is_pure_lookaround(trimmed) {
                p.push_str(&format!("((?:{trimmed})[^\\n]*?)"));
            } else {
                p.push_str(&format!("({trimmed})"));
            }
        } else {
            p.push_str("([^\n]*?)");
        }
        last = m.end();
    }
    p.push_str(&handle_string_regex(&pattern[last..]));
    p = p.replace("\\.\\.\\.", ".*?");
    p = p.replace(" ", "\\s+");
    p = relax_semgrep_ellipsis(p);
    format!("(?s).*{p}.*")
}

pub fn semgrep_to_regex_exact(pattern: &str, mv: &HashMap<String, String>) -> String {
    fn esc(seg: &str) -> String {
        let mut out = String::new();
        for ch in seg.chars() {
            match ch {
                '{' | '}' | '[' | ']' => {
                    out.push('\\');
                    out.push(ch);
                }
                _ => out.push_str(&regex::escape(&ch.to_string())),
            }
        }
        out
    }

    fn handle_string_regex(seg: &str) -> String {
        if let Some(start) = seg.find("=~/") {
            let mut end_pos = None;
            let search_start = start + 3;
            let mut i = search_start;
            while i < seg.len() {
                if seg.chars().nth(i) == Some('/')
                    && (i == 0 || seg.chars().nth(i - 1) != Some('\\'))
                {
                    end_pos = Some(i);
                }
                i += 1;
            }

            if let Some(end) = end_pos {
                let regex_part = &seg[search_start..end];
                let prefix = seg[..start].trim_end();
                let suffix = &seg[end + 1..];
                let mut out = String::new();
                out.push_str(&esc(prefix));
                out.push_str("\\s*=~?\\s*");
                let quoted_double = regex_part.replace("\"", "\\\"");
                let quoted_single = regex_part.replace("'", "\\'");
                out.push_str(&format!(
                    r#"(?:"{0}"|'{1}'|{2})"#,
                    quoted_double, quoted_single, regex_part
                ));
                out.push_str(&esc(suffix));
                return out;
            }
        }
        esc(seg)
    }
    let metav = Regex::new(r"\$[A-Za-z_][A-Za-z0-9_]*").expect("valid metavariable regex");
    let mut p = String::new();
    let mut last = 0;
    for m in metav.find_iter(pattern) {
        p.push_str(&handle_string_regex(&pattern[last..m.start()]));
        let var = &pattern[m.start() + 1..m.end()];
        if let Some(r) = mv.get(var) {
            let anchored = normalize_metavariable_regex(r);
            let trimmed = anchored.trim_start_matches('^').trim_end_matches('$');
            if is_pure_lookaround(trimmed) {
                p.push_str(&format!("((?:{trimmed})[^\\n]*?)"));
            } else {
                p.push_str(&format!("({trimmed})"));
            }
        } else {
            p.push_str("([^\n]*?)");
        }
        last = m.end();
    }
    p.push_str(&handle_string_regex(&pattern[last..]));
    p = p.replace("\\.\\.\\.", ".*?");
    p = p.replace(" ", "\\s+");
    p = relax_semgrep_ellipsis(p);
    format!("(?s){p}")
}

fn collect_metavar_regex(
    value: &YamlValue,
    mv: &mut HashMap<String, String>,
    focus: &mut Option<String>,
) {
    if let Some(node) = value.get("metavariable-regex") {
        if let Some(seq) = node.as_sequence() {
            for item in seq {
                if let (Some(var), Some(re)) = (
                    item.get("metavariable").and_then(|v| v.as_str()),
                    item.get("regex").and_then(|v| v.as_str()),
                ) {
                    mv.insert(var.trim_start_matches('$').to_string(), re.to_string());
                }
            }
        } else if let Some(map) = node.as_mapping() {
            let var = map
                .get("metavariable")
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches('$').to_string());
            let re = map
                .get("regex")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if let (Some(var), Some(re)) = (var, re) {
                mv.insert(var, re);
            }
        }
    }
    if focus.is_none() {
        if let Some(f) = value.get("focus-metavariable").and_then(|v| v.as_str()) {
            *focus = Some(f.to_string());
        }
    }
    if let Some(obj) = value.as_mapping() {
        if let (Some(var), Some(re)) = (
            obj.get(YamlValue::from("metavariable"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim_start_matches('$').to_string()),
            obj.get(YamlValue::from("regex"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        ) {
            mv.insert(var, re);
        }
        for val in obj.values() {
            collect_metavar_regex(val, mv, focus);
        }
    } else if let Some(seq) = value.as_sequence() {
        for val in seq {
            collect_metavar_regex(val, mv, focus);
        }
    }
}

fn collect_pattern_literals(node: &YamlValue, out: &mut HashSet<String>) {
    if let Some(s) = node.as_str() {
        out.insert(s.to_string());
        return;
    }
    if let Some(map) = node.as_mapping() {
        if let Some(pat) = map.get("pattern").and_then(|v| v.as_str()) {
            out.insert(pat.to_string());
        }
        if let Some(seq) = map.get("pattern-either").and_then(|v| v.as_sequence()) {
            for item in seq {
                collect_pattern_literals(item, out);
            }
        }
        if let Some(seq) = map.get("patterns").and_then(|v| v.as_sequence()) {
            for item in seq {
                collect_pattern_literals(item, out);
            }
        }
    } else if let Some(seq) = node.as_sequence() {
        for item in seq {
            collect_pattern_literals(item, out);
        }
    }
}

fn collect_metavar_patterns(value: &YamlValue, mv: &mut HashMap<String, Vec<String>>) {
    if let Some(seq) = value.as_sequence() {
        for item in seq {
            collect_metavar_patterns(item, mv);
        }
        return;
    }
    if let Some(map) = value.as_mapping() {
        for (k, v) in map {
            if k.as_str() == Some("metavariable-pattern") {
                if let Some(inner) = v.as_mapping() {
                    if let Some(var) = inner.get("metavariable").and_then(|v| v.as_str()) {
                        let mut acc = HashSet::new();
                        if let Some(node) = inner.get("pattern") {
                            collect_pattern_literals(node, &mut acc);
                        }
                        if let Some(node) = inner.get("pattern-either") {
                            collect_pattern_literals(node, &mut acc);
                        }
                        if let Some(node) = inner.get("patterns") {
                            collect_pattern_literals(node, &mut acc);
                        }
                        if !acc.is_empty() {
                            let entry = mv
                                .entry(var.trim_start_matches('$').to_string())
                                .or_default();
                            entry.extend(acc.into_iter());
                        }
                    }
                }
            } else {
                collect_metavar_patterns(v, mv);
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum PatternKind {
    Pattern,
    Inside,
    NotInside,
    Not,
    Regex,
}

pub(crate) fn extract_patterns(
    value: &YamlValue,
    kind: Option<PatternKind>,
    out: &mut Vec<(PatternKind, String)>,
    seen: &mut HashSet<usize>,
) {
    let ptr = value as *const _ as usize;
    if !seen.insert(ptr) {
        return;
    }
    if let Some(map) = value.as_mapping() {
        for (k, v) in map {
            if let Some(key) = k.as_str() {
                match key {
                    "pattern" => {
                        let k = kind.unwrap_or(PatternKind::Pattern);
                        if let Some(s) = v.as_str() {
                            out.push((k, s.to_string()));
                        } else {
                            extract_patterns(v, Some(k), out, seen);
                        }
                        continue;
                    }
                    "pattern-regex" => {
                        if let Some(s) = v.as_str() {
                            out.push((PatternKind::Regex, s.to_string()));
                        } else {
                            extract_patterns(v, Some(PatternKind::Regex), out, seen);
                        }
                        continue;
                    }
                    "pattern-inside" => {
                        if let Some(s) = v.as_str() {
                            out.push((PatternKind::Inside, s.to_string()));
                        } else {
                            extract_patterns(v, Some(PatternKind::Inside), out, seen);
                        }
                        continue;
                    }
                    "pattern-not-inside" => {
                        if let Some(s) = v.as_str() {
                            out.push((PatternKind::NotInside, s.to_string()));
                        } else {
                            extract_patterns(v, Some(PatternKind::NotInside), out, seen);
                        }
                        continue;
                    }
                    "pattern-not" => {
                        if let Some(s) = v.as_str() {
                            out.push((PatternKind::Not, s.to_string()));
                        } else {
                            extract_patterns(v, Some(PatternKind::Not), out, seen);
                        }
                        continue;
                    }
                    "metavariable-pattern" => {
                        continue;
                    }
                    "pattern-either" | "patterns" => {
                        extract_patterns(v, kind, out, seen);
                        continue;
                    }
                    _ => {}
                }
            }
            extract_patterns(v, kind, out, seen);
        }
    } else if let Some(seq) = value.as_sequence() {
        for item in seq {
            extract_patterns(item, kind, out, seen);
        }
    } else if let Some(s) = value.as_str() {
        if let Some(k) = kind {
            out.push((k, s.to_string()));
        }
    }
}

fn compile_taint_patterns(
    arr: &[YamlValue],
    mv: &HashMap<String, String>,
    focus: Option<&str>,
) -> anyhow::Result<TaintPattern> {
    fn count_capturing_groups(re_str: &str) -> usize {
        let bytes = re_str.as_bytes();
        let mut count = 0usize;
        let mut i = 0usize;
        let mut in_class = false;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == b'[' {
                in_class = true;
                i += 1;
                continue;
            }
            if b == b']' && in_class {
                in_class = false;
                i += 1;
                continue;
            }
            if b == b'(' && !in_class {
                let next = bytes.get(i + 1).copied();
                if next == Some(b'?') {
                    match bytes.get(i + 2).copied() {
                        Some(b':') | Some(b'=') | Some(b'!') | Some(b'>') | Some(b'#') => {}
                        Some(b'P') => {
                            if let Some(cmd) = bytes.get(i + 3).copied() {
                                if cmd == b'<' || cmd == b'\'' {
                                    count += 1;
                                }
                            }
                        }
                        Some(b'<') => {
                            if let Some(cmd) = bytes.get(i + 3).copied() {
                                if cmd != b'=' && cmd != b'!' {
                                    count += 1;
                                }
                            } else {
                                count += 1;
                            }
                        }
                        Some(_) => {}
                        None => {}
                    }
                } else {
                    count += 1;
                }
            }
            i += 1;
        }
        count
    }

    fn focus_group_index(
        pattern: &str,
        focus: Option<&str>,
        mv: &HashMap<String, String>,
    ) -> Option<usize> {
        let focus = focus?;
        let target = focus.trim_start_matches('$');
        let re = Regex::new(r"\$[A-Za-z_][A-Za-z0-9_]*").expect("valid metavariable regex");
        let mut idx = 1usize;
        for m in re.find_iter(pattern) {
            let name = &pattern[m.start() + 1..m.end()];
            if name == target {
                return Some(idx);
            }
            let captures = if let Some(re_str) = mv.get(name) {
                1 + count_capturing_groups(re_str)
            } else {
                1
            };
            idx += captures;
        }
        None
    }

    fn handle_entry(
        entry: &YamlValue,
        mv: &HashMap<String, String>,
        pattern: &mut TaintPattern,
        focus: Option<&str>,
    ) -> anyhow::Result<()> {
        if let Some(p) = entry.get("pattern").and_then(|v| v.as_str()) {
            let normalized = p
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty())
                .collect::<Vec<_>>()
                .join("\n");
            if !normalized.is_empty() {
                let regex_str = semgrep_to_regex_exact(&normalized, mv);
                let re = compile_regex_with_pcre2_fallback(
                    &regex_str,
                    false,
                    "taint-pattern",
                    "unknown",
                )?;
                pattern.allow.push(re);
                pattern
                    .allow_focus_groups
                    .push(focus_group_index(&normalized, focus, mv));
            }
        }
        if let Some(p) = entry.get("pattern-inside").and_then(|v| v.as_str()) {
            for line in p
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "...")
            {
                let regex_str = semgrep_to_regex_exact(line, mv);
                let re = compile_regex_with_pcre2_fallback(
                    &regex_str,
                    false,
                    "taint-pattern",
                    "unknown",
                )?;
                pattern.inside.push(re);
                pattern
                    .inside_focus_groups
                    .push(focus_group_index(line, focus, mv));
            }
        }
        if let Some(p) = entry.get("pattern-not-inside").and_then(|v| v.as_str()) {
            for line in p
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "...")
            {
                let regex_str = semgrep_to_regex_exact(line, mv);
                let re = compile_regex_with_pcre2_fallback(
                    &regex_str,
                    false,
                    "taint-pattern",
                    "unknown",
                )?;
                pattern.not_inside.push(re);
            }
        }
        if let Some(n) = entry.get("pattern-not").and_then(|v| v.as_str()) {
            let combined: String = n
                .lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && *l != "...")
                .collect::<Vec<_>>()
                .join("\n");
            let regex_str = semgrep_to_regex_exact(&combined, mv);
            let re =
                compile_regex_with_pcre2_fallback(&regex_str, false, "taint-pattern", "unknown")?;
            pattern.deny = Some(re);
        }
        if let Some(arr) = entry.get("pattern-either").and_then(|v| v.as_sequence()) {
            for item in arr {
                handle_entry(item, mv, pattern, focus)?;
            }
        }
        if let Some(arr) = entry.get("patterns").and_then(|v| v.as_sequence()) {
            for item in arr {
                handle_entry(item, mv, pattern, focus)?;
            }
        }
        Ok(())
    }

    let mut pattern = TaintPattern::default();
    for item in arr {
        handle_entry(item, mv, &mut pattern, focus)?;
    }
    Ok(pattern)
}

pub(crate) fn compile_semgrep_rule(
    rs: &mut RuleSet,
    seen: &mut HashSet<String>,
    sr: SemgrepRule,
    file_path: &Path,
    base_dir: &Path,
) -> anyhow::Result<()> {
    if !seen.insert(sr.id.clone()) {
        bail!("duplicate rule id: {}", sr.id);
    }
    debug!(
        "Compiling Semgrep rule: {} from file: {}",
        sr.id,
        file_path.display()
    );
    debug!("Rule mode: {:?}", sr.mode);
    let severity: Severity = sr
        .severity
        .as_deref()
        .unwrap_or("MEDIUM")
        .parse()
        .map_err(|e: String| anyhow!(e))?;
    let message = sr.message.clone().unwrap_or_default();
    let languages = normalize_languages(sr.languages.clone());
    let source_file = file_path
        .strip_prefix(base_dir)
        .ok()
        .map(|p| p.to_string_lossy().to_string());
    let mut mv = HashMap::new();
    let mut focus = sr.focus_metavariable.clone();
    let mut mv_pattern_map: HashMap<String, Vec<String>> = HashMap::new();
    if let Some(arr) = &sr.metavariable_regex {
        for item in arr {
            mv.insert(
                item.metavariable.trim_start_matches('$').to_string(),
                item.regex.clone(),
            );
        }
    }
    let sr_yaml = serde_yaml::to_value(&sr)?;
    collect_metavar_regex(&sr_yaml, &mut mv, &mut focus);
    collect_metavar_patterns(&sr_yaml, &mut mv_pattern_map);
    if !mv_pattern_map.is_empty() {
        let empty_mv: HashMap<String, String> = HashMap::new();
        for (var, patterns) in mv_pattern_map {
            if mv.contains_key(&var) {
                continue;
            }
            let mut parts = Vec::new();
            for pat in patterns {
                let trimmed = pat.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let regex_src = semgrep_to_regex_exact(trimmed, &empty_mv);
                let mut core = regex_src
                    .strip_prefix("(?s)")
                    .unwrap_or(&regex_src)
                    .to_string();
                if core.trim().is_empty() {
                    continue;
                }
                if trimmed.contains("$_") {
                    core.push_str(r"(?:\[[^\]]*\])*");
                }
                parts.push(format!("(?:{core})"));
            }
            if parts.is_empty() {
                continue;
            }
            let union = parts.join("|");
            let final_re = format!("(?s)(?:{})", union);
            mv.insert(var, final_re);
        }
    }

    let mut patterns = Vec::new();
    let mut seen_patterns = HashSet::new();
    extract_patterns(&sr_yaml, None, &mut patterns, &mut seen_patterns);

    let mut sources = Vec::new();
    if let Some(arr) = sr.pattern_sources.clone() {
        for src in arr {
            if let Some(seq) = src.get("patterns").and_then(|v| v.as_sequence()) {
                let mut tp = compile_taint_patterns(seq, &mv, focus.as_deref())?;
                tp.focus = focus.clone();
                sources.push(tp);
            } else if src.get("pattern-either").is_some() || src.get("pattern").is_some() {
                let single_item = vec![src];
                let mut tp = compile_taint_patterns(&single_item, &mv, focus.as_deref())?;
                tp.focus = focus.clone();
                sources.push(tp);
            }
        }
    }

    let mut sanitizers = Vec::new();
    if let Some(arr) = sr.pattern_sanitizers.clone() {
        for san in arr {
            if let Some(seq) = san.get("patterns").and_then(|v| v.as_sequence()) {
                let mut tp = compile_taint_patterns(seq, &mv, focus.as_deref())?;
                tp.focus = focus.clone();
                sanitizers.push(tp);
            } else if san.get("pattern-either").is_some() || san.get("pattern").is_some() {
                let single_item = vec![san];
                let mut tp = compile_taint_patterns(&single_item, &mv, focus.as_deref())?;
                tp.focus = focus.clone();
                sanitizers.push(tp);
            }
        }
    }

    let mut sinks = Vec::new();
    if let Some(arr) = sr.pattern_sinks.clone() {
        for snk in arr {
            if let Some(seq) = snk.get("patterns").and_then(|v| v.as_sequence()) {
                sinks.push(compile_taint_patterns(seq, &mv, focus.as_deref())?);
            } else if snk.get("pattern-either").is_some() || snk.get("pattern").is_some() {
                let single_item = vec![snk];
                sinks.push(compile_taint_patterns(&single_item, &mv, focus.as_deref())?);
            }
        }
    }

    let mut reclass = Vec::new();
    if let Some(arr) = sr.pattern_reclass.clone() {
        for rc in arr {
            if let Some(seq) = rc.get("patterns").and_then(|v| v.as_sequence()) {
                reclass.push(compile_taint_patterns(seq, &mv, focus.as_deref())?);
            } else if rc.get("pattern-either").is_some() || rc.get("pattern").is_some() {
                let single_item = vec![rc];
                reclass.push(compile_taint_patterns(&single_item, &mv, focus.as_deref())?);
            }
        }
    }

    if !sources.is_empty() || !sinks.is_empty() {
        debug!(
            "Creating TaintRule with {} sources and {} sinks",
            sources.len(),
            sinks.len()
        );
        let rule = CompiledRule {
            id: sr.id,
            severity,
            category: "semgrep".into(),
            message,
            remediation: None,
            fix: sr.fix.clone(),
            interfile: sr.options.interfile,
            matcher: MatcherKind::TaintRule {
                sources,
                sanitizers,
                reclass,
                sinks,
            },
            source_file: source_file.clone(),
            sources: Vec::new(),
            sinks: Vec::new(),
            languages: languages.clone(),
        };
        log_rule_summary(&rule);
        rs.rules.push(rule);
        return Ok(());
    }

    let use_multi = sr.patterns.is_some()
        || sr.pattern_inside.is_some()
        || sr.pattern_not_inside.is_some()
        || sr.pattern_either.is_some();

    if use_multi {
        let mut allow: Vec<(AnyRegex, String)> = Vec::new();
        let mut deny_parts: Vec<String> = Vec::new();
        let mut inside = Vec::new();
        let mut not_inside = Vec::new();
        for (kind, pat) in patterns {
            match kind {
                PatternKind::Pattern => {
                    let normalized = pat
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty())
                        .collect::<Vec<_>>()
                        .join("\n");
                    if !normalized.is_empty() {
                        let re_str = semgrep_to_regex_exact(&normalized, &mv);
                        allow.push((FancyRegex::new(&re_str)?.into(), normalized));
                    }
                }
                PatternKind::Inside => {
                    let combined: String = pat
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty())
                        .collect::<Vec<_>>()
                        .join("\n");
                    let mut re = semgrep_to_regex_exact(&combined, &mv);
                    re = re.replacen("(?s)", "(?ms)^", 1);
                    inside.push(FancyRegex::new(&re)?.into());
                }
                PatternKind::NotInside => {
                    let combined: String = pat
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty())
                        .collect::<Vec<_>>()
                        .join("\n");
                    let mut re = semgrep_to_regex_exact(&combined, &mv);
                    re = re.replacen("(?s)", "(?ms)^", 1);
                    not_inside.push(FancyRegex::new(&re)?.into());
                }
                PatternKind::Not => {
                    let combined: String = pat
                        .lines()
                        .map(|l| l.trim())
                        .filter(|l| !l.is_empty() && *l != "...")
                        .collect::<Vec<_>>()
                        .join("\n");
                    deny_parts.push(semgrep_to_regex_exact(&combined, &mv));
                }
                PatternKind::Regex => {
                    let re = compile_regex_with_pcre2_fallback(
                        &pat,
                        true,
                        &sr.id,
                        source_file.as_deref().unwrap_or("unknown"),
                    )?;
                    allow.push((re, pat));
                }
            }
        }
        if !allow.is_empty() {
            let deny = if !deny_parts.is_empty() {
                let cleaned: Vec<String> = deny_parts
                    .into_iter()
                    .map(|s| s.strip_prefix("(?s)").map(|x| x.to_string()).unwrap_or(s))
                    .collect();
                let joined = cleaned.join(")|(?:");
                let big = format!("(?s)(?:{})", joined);
                Some(FancyRegex::new(&big)?.into())
            } else {
                None
            };
            let rule = CompiledRule {
                id: sr.id,
                severity,
                category: "semgrep".into(),
                message,
                remediation: None,
                fix: sr.fix.clone(),
                interfile: sr.options.interfile,
                matcher: MatcherKind::TextRegexMulti {
                    allow,
                    deny,
                    inside,
                    not_inside,
                },
                source_file: source_file.clone(),
                sources: Vec::new(),
                sinks: Vec::new(),
                languages: languages.clone(),
            };
            log_rule_summary(&rule);
            rs.rules.push(rule);
        }
    } else if let Some(p) = sr.pattern {
        let re = compile_regex_with_pcre2_fallback(
            &semgrep_to_regex(&p, &mv),
            false,
            &sr.id,
            source_file.as_deref().unwrap_or("unknown"),
        )?;
        let rule = CompiledRule {
            id: sr.id,
            severity,
            category: "semgrep".into(),
            message,
            remediation: None,
            fix: sr.fix,
            interfile: sr.options.interfile,
            matcher: MatcherKind::TextRegex(re, p),
            source_file,
            sources: Vec::new(),
            sinks: Vec::new(),
            languages: languages.clone(),
        };
        log_rule_summary(&rule);
        rs.rules.push(rule);
    } else if let Some(pr) = sr.pattern_regex {
        let re = compile_regex_with_pcre2_fallback(
            &pr,
            true,
            &sr.id,
            source_file.as_deref().unwrap_or("unknown"),
        )?;
        let rule = CompiledRule {
            id: sr.id,
            severity,
            category: "semgrep".into(),
            message,
            remediation: None,
            fix: sr.fix,
            interfile: sr.options.interfile,
            matcher: MatcherKind::TextRegex(re, pr),
            source_file,
            sources: Vec::new(),
            sinks: Vec::new(),
            languages,
        };
        log_rule_summary(&rule);
        rs.rules.push(rule);
    }

    Ok(())
}
