//! Literal prefilter: a cheap necessary-condition check that skips a rule for a
//! file whose source cannot contain any of the rule's required literals.
//!
//! Building a required-literals set (DNF: OR of AND-clauses) per rule and
//! testing it against the file lets the engine avoid running expensive matchers
//! on files that provably cannot match — without ever dropping a real finding.

use std::sync::atomic::{AtomicBool, Ordering};

use ir::FileIR;
use loader::{CompiledRule, MatcherKind};

static PREFILTER_DISABLED: AtomicBool = AtomicBool::new(false);

/// Disables the literal prefilter (used by `--no-prefilter` for debugging).
///
/// When enabled (the default), a rule is skipped for a file whose source
/// cannot contain any of the rule's required literals — a necessary
/// condition for a match, so this never drops a real finding.
pub fn set_prefilter_disabled(disabled: bool) {
    PREFILTER_DISABLED.store(disabled, Ordering::Relaxed);
}

pub(crate) fn prefilter_disabled() -> bool {
    PREFILTER_DISABLED.load(Ordering::Relaxed)
}

/// Minimum identifier length kept as a required literal. Shorter tokens carry
/// little discriminating power and are often regex fragments; dropping them
/// only makes the prefilter more permissive (still sound).
const PREFILTER_MIN_LITERAL_LEN: usize = 3;

/// Splits a semgrep pattern string into the concrete identifier tokens it
/// requires, or returns empty when the text cannot be reduced soundly.
///
/// Sound for structural `pattern:` text: metavariables (`$X`) and the ellipsis
/// (`...`) are the only variable parts, so every code identifier outside them
/// must appear verbatim in matching source. Two things are *not* safe and so
/// are ignored: string/char-literal interiors (they hold semgrep inline
/// regexes like `"=~/…/"` and exact strings — extracting from them is
/// unnecessary and their `|`/`*` are not code) and character classes `[…]`
/// (ranges, not literals). Raw-regex text is caught by bailing to empty on
/// alternation (`|`), optional (`?`), star (`*`) or `{n,m}` quantifiers that
/// appear *outside* strings/classes — the caller then runs the rule
/// unconditionally, never a false negative.
pub(crate) fn pattern_required_literals(text: &str) -> Vec<String> {
    // Ubiquitous Java tokens carry no discriminating power; dropping them only
    // makes the prefilter more permissive (still sound), and avoids clauses
    // that every file trivially satisfies.
    const COMMON: &[&str] = &[
        "new", "return", "void", "public", "private", "protected", "static", "final", "if", "else",
        "for", "while", "class", "interface", "extends", "implements", "import", "package",
        "throws", "throw", "try", "catch", "String", "int", "long", "boolean", "this", "super",
        "null", "true", "false",
    ];
    let bytes = text.as_bytes();
    let mut literals = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        // String / char literals: their interior is not code, so metacharacters
        // inside must not trigger a bail. An *exact* string is itself a required
        // literal (e.g. `"redirect:"`), but semgrep's inline `"=~/regex/"` form
        // and escaped strings are not safe to require, so those are skipped.
        if c == b'"' || c == b'\'' {
            let quote = c;
            let start = i + 1;
            i += 1;
            let mut escaped = false;
            while i < bytes.len() && bytes[i] != quote {
                if bytes[i] == b'\\' {
                    escaped = true;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let end = i.min(bytes.len());
            i += 1; // past closing quote (or past end)
            if let Some(content) = text.get(start..end) {
                let trimmed = content.trim();
                if !escaped
                    && !trimmed.starts_with("=~")
                    && trimmed.len() >= PREFILTER_MIN_LITERAL_LEN
                    && !literals.iter().any(|t| t == trimmed)
                {
                    literals.push(trimmed.to_string());
                }
            }
            continue;
        }
        // Skip a character-class interior `[...]` (ranges, not literals). In
        // structural code `[` is indexing, whose contents we can also drop.
        if c == b'[' {
            i += 1;
            while i < bytes.len() && bytes[i] != b']' {
                i += 1;
            }
            i += 1;
            continue;
        }
        // Skip an escaped char (`\b`, `\d`, `\|`, …) so raw-regex escapes are
        // neither merged into an identifier nor mistaken for alternation.
        if c == b'\\' {
            i += 2;
            continue;
        }
        // Regex-danger signals in *code* position break the "identifier is
        // required" assumption (alternation / optional / star / quantifier).
        if c == b'|' || c == b'?' || c == b'*' {
            return Vec::new();
        }
        if c == b'{' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit) {
            return Vec::new();
        }
        if c == b'$' {
            // Skip a metavariable ($NAME) whole.
            i += 1;
            while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            continue;
        }
        if c == b'_' || c.is_ascii_alphabetic() {
            let start = i;
            while i < bytes.len() && (bytes[i] == b'_' || bytes[i].is_ascii_alphanumeric()) {
                i += 1;
            }
            let tok = &text[start..i];
            if tok.len() >= PREFILTER_MIN_LITERAL_LEN
                && !COMMON.contains(&tok)
                && !literals.iter().any(|t| t == tok)
            {
                literals.push(tok.to_string());
            }
            continue;
        }
        i += 1;
    }
    literals
}

/// Builds a required-literals prefilter (DNF: OR of clauses, each an AND of
/// substrings) from a compiled rule, or `None` when no sound prefilter can be
/// derived (the rule then always runs).
///
/// A rule can only match if at least one clause is fully present in the file
/// source, so skipping when no clause matches never drops a real finding. If
/// any positive alternative yields no literals, the whole prefilter is dropped
/// to stay conservative.
pub(crate) fn rule_prefilter(rule: &CompiledRule) -> Option<Vec<Vec<String>>> {
    let mut clauses: Vec<Vec<String>> = Vec::new();
    match &rule.matcher {
        MatcherKind::TextRegex(_, text) => {
            let lits = pattern_required_literals(text);
            if lits.is_empty() {
                return None;
            }
            clauses.push(lits);
        }
        MatcherKind::TextRegexMulti { subs } => {
            for sub in subs {
                // Each `allow` alternative is one OR-branch; ignore inside /
                // not_inside / deny (negative or context-only) for soundness.
                for (_, text) in &sub.allow {
                    let lits = pattern_required_literals(text);
                    if lits.is_empty() {
                        return None;
                    }
                    clauses.push(lits);
                }
            }
        }
        MatcherKind::TaintRule { .. } => {
            // A taint finding needs at least one sink to match, so its name must
            // appear. Each sink name is its own single-literal clause.
            for sink in &rule.sinks {
                if sink.is_empty() {
                    return None;
                }
                clauses.push(vec![sink.clone()]);
            }
        }
        // Structural / WASM / JSONPath matchers keep no recoverable literals.
        _ => return None,
    }
    if clauses.is_empty() {
        None
    } else {
        Some(clauses)
    }
}

/// Returns the haystack used for literal membership tests: the raw source when
/// available, else the serialized nodes (mirrors the TextRegex matcher input).
pub(crate) fn prefilter_haystack(file: &FileIR) -> std::borrow::Cow<'_, str> {
    match &file.source {
        Some(s) => std::borrow::Cow::Borrowed(s.as_str()),
        None => std::borrow::Cow::Owned(serde_json::to_string(&file.nodes).unwrap_or_default()),
    }
}

pub(crate) fn prefilter_allows(dnf: &[Vec<String>], haystack: &str) -> bool {
    dnf.iter()
        .any(|clause| clause.iter().all(|lit| haystack.contains(lit.as_str())))
}

#[cfg(test)]
mod tests {
    use super::pattern_required_literals as lits_fn;

    fn lits(text: &str) -> Vec<String> {
        lits_fn(text)
    }

    #[test]
    fn extracts_code_identifiers_ignoring_inline_regex_strings() {
        // permissive-cors shape: `|` and `*` live inside string literals, so
        // they must not trigger a bail; the code identifiers are required.
        let text = "HttpServletResponse $RES = ...;\n...\n$RES.addHeader(\"=~/access-control-allow-origin/i\", \"=~/^\\*|null$/i\");";
        let got = lits(text);
        assert!(got.contains(&"HttpServletResponse".to_string()), "{got:?}");
        assert!(got.contains(&"addHeader".to_string()), "{got:?}");
        assert!(!got.iter().any(|l| l.contains("null") || l.contains("access")));
    }

    #[test]
    fn skips_metavariables_and_short_tokens() {
        let got = lits("$MD.digest(...);");
        assert_eq!(got, vec!["digest".to_string()]);
    }

    #[test]
    fn keeps_exact_string_literals_but_not_inline_regex() {
        // spring-unvalidated-redirect shape: the exact string is the signal.
        let got = lits("return \"redirect:\" + $URL;");
        assert!(got.contains(&"redirect:".to_string()), "{got:?}");
        // An inline `=~/.../` string is a regex, not a required literal.
        let re = lits("$X.foo(\"=~/user|admin/i\");");
        assert!(re.contains(&"foo".to_string()), "{re:?}");
        assert!(!re.iter().any(|l| l.contains("user") || l.contains("admin")));
    }

    #[test]
    fn bails_on_raw_regex_alternation_and_quantifiers() {
        assert!(lits("(xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26})").is_empty());
        assert!(lits("foo|bar").is_empty());
        assert!(lits("value?").is_empty());
    }

    #[test]
    fn regex_escapes_do_not_merge_into_identifiers() {
        // `\b` is a word boundary, not a leading "b" on "word".
        assert_eq!(lits("\\bword\\b"), vec!["word".to_string()]);
    }
}
