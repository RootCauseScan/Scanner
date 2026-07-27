//! Text/regex scanning helpers shared by the matching and taint code.
//!
//! Pure functions over source strings: locating regex match ranges (with the
//! fancy-regex backtracking guard), mapping byte offsets to line/column,
//! extracting variable-like identifiers from sink text, and finding the
//! enclosing `{ … }` block of a position.

use std::sync::OnceLock;
use std::time::Instant;

use loader::AnyRegex;
use regex::Regex;
use tracing::debug;

use crate::FANCY_REGEX_GUARD;

pub(crate) fn regex_ranges_any(source: &str, regs: &[AnyRegex]) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    for re in regs {
        if re.is_fancy() {
            // Context patterns (pattern-inside / not-inside) frequently span
            // lines — e.g. a trailing Semgrep `...` compiled to `(?s).*$`.
            // Scanning line-by-line would truncate those ranges and reject
            // valid allows on later lines. Try a full-source scan first.
            let full: Vec<(usize, usize)> = re.find_iter(source).collect();
            if !full.is_empty() {
                ranges.extend(full);
                continue;
            }
            // Fall back to line-by-line when the full scan finds nothing, to
            // bound catastrophic backtracking on pathological patterns.
            let start_guard = Instant::now();
            let mut offset = 0usize;
            for seg in source.split_inclusive('\n') {
                if start_guard.elapsed() > FANCY_REGEX_GUARD {
                    debug!("regex_ranges_any: Aborting fancy regex scan due to guard timeout");
                    break;
                }
                let mut match_count = 0;
                for (ls, le) in re.find_iter(seg) {
                    match_count += 1;
                    if match_count > 1000 {
                        debug!("regex_ranges_any: Aborting fancy regex scan due to too many matches in segment");
                        break;
                    }
                    if start_guard.elapsed() > FANCY_REGEX_GUARD {
                        debug!("regex_ranges_any: Aborting fancy regex scan due to guard timeout in iterator");
                        break;
                    }
                    let s = offset + ls;
                    let e = offset + le;
                    ranges.push((s, e));
                }
                offset += seg.len();
            }
        } else {
            for (s, e) in re.find_iter(source) {
                ranges.push((s, e));
            }
        }
    }
    ranges
}

pub(crate) fn line_col_at(source: &str, pos: usize) -> (usize, usize) {
    let pos = floor_char_boundary(source, pos);
    let mut line = 1usize;
    let mut line_start = 0usize;
    for (idx, ch) in source[..pos].char_indices() {
        if ch == '\n' {
            line += 1;
            line_start = idx + 1;
        }
    }
    let column = pos - line_start + 1;
    (line, column)
}

pub(crate) fn floor_char_boundary(source: &str, pos: usize) -> usize {
    let mut pos = pos.min(source.len());
    while pos > 0 && !source.is_char_boundary(pos) {
        pos -= 1;
    }
    pos
}

static ASSIGN_LHS_RE: OnceLock<Regex> = OnceLock::new();

pub(crate) fn derive_assignment_lhs(source: &str, pos: usize) -> Option<String> {
    let pos = floor_char_boundary(source, pos);
    let line_start = source[..pos].rfind('\n').map(|idx| idx + 1).unwrap_or(0);
    let prefix = &source[line_start..pos];
    if prefix.is_empty() {
        return None;
    }
    let re = ASSIGN_LHS_RE.get_or_init(|| {
        Regex::new(
            r"(?:(?P<prefix>[$@%&*]+))?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?::[A-Za-z_][A-Za-z0-9_]*)?\s*=\s*$",
        )
            .expect("valid assignment regex")
    });
    re.captures(prefix)
        .and_then(|caps| caps.name("name").map(|m| m.as_str().to_string()))
}

// Common Java/C/JS keywords that should not be treated as variable names.
const LANG_KEYWORDS: &[&str] = &[
    "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class",
    "const", "continue", "default", "do", "double", "else", "enum", "extends", "final",
    "finally", "float", "for", "goto", "if", "implements", "import", "instanceof", "int",
    "interface", "long", "native", "new", "package", "private", "protected", "public",
    "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
    "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false",
    "null", "String", "Object", "var", "let", "const", "function", "typeof", "instanceof",
    "in", "of", "async", "await", "yield",
];

pub(crate) fn extract_sink_variables(text: &str) -> Vec<(String, usize)> {
    let mut vars = Vec::new();
    let mut iter = text.char_indices().peekable();

    while let Some((idx, ch)) = iter.next() {
        if ch == '$' {
            // PHP-style variable: $varName
            let mut var_name = String::new();
            while let Some(&(_, next_ch)) = iter.peek() {
                if next_ch.is_ascii_alphanumeric() || next_ch == '_' {
                    var_name.push(next_ch);
                    iter.next();
                } else {
                    break;
                }
            }
            if !var_name.is_empty() {
                vars.push((var_name, idx));
            }
        } else if ch.is_ascii_alphabetic() || ch == '_' {
            // Java/Python/JS identifier: starts with letter or underscore
            let mut var_name = ch.to_string();
            while let Some(&(_, next_ch)) = iter.peek() {
                if next_ch.is_ascii_alphanumeric() || next_ch == '_' {
                    var_name.push(next_ch);
                    iter.next();
                } else {
                    break;
                }
            }
            if var_name.len() > 1 && !LANG_KEYWORDS.contains(&var_name.as_str()) {
                vars.push((var_name, idx));
            }
        }
    }

    vars
}

pub(crate) fn regex_ranges_with_focus(
    source: &str,
    regs: &[AnyRegex],
    focus_groups: &[Option<usize>],
) -> Vec<(usize, usize, Option<String>)> {
    let mut ranges = Vec::new();
    for (idx, re) in regs.iter().enumerate() {
        let focus_group = focus_groups.get(idx).copied().flatten();
        if re.is_fancy() {
            let start_guard = Instant::now();
            let mut offset = 0usize;
            for seg in source.split_inclusive('\n') {
                if start_guard.elapsed() > FANCY_REGEX_GUARD {
                    debug!(
                        "regex_ranges_with_focus: Aborting fancy regex scan due to guard timeout"
                    );
                    break;
                }
                let mut match_count = 0;
                for (ls, le) in re.find_iter(seg) {
                    match_count += 1;
                    if match_count > 1000 {
                        debug!("regex_ranges_with_focus: Aborting fancy regex scan due to too many matches in segment");
                        break;
                    }
                    if start_guard.elapsed() > FANCY_REGEX_GUARD {
                        debug!("regex_ranges_with_focus: Aborting fancy regex scan due to guard timeout in iterator");
                        break;
                    }

                    let s = offset + ls;
                    let e = offset + le;
                    let captured = focus_group.and_then(|grp| {
                        re.captures(&seg[ls..le])
                            .and_then(|caps| caps.get(grp).map(|m| m.as_str().to_string()))
                    });
                    ranges.push((s, e, captured));
                }
                offset += seg.len();
            }
        } else {
            for (s, e) in re.find_iter(source) {
                let captured = focus_group.and_then(|grp| {
                    re.captures(&source[s..e])
                        .and_then(|caps| caps.get(grp).map(|m| m.as_str().to_string()))
                });
                ranges.push((s, e, captured));
            }
        }
    }
    ranges
}

pub(crate) fn enclosing_block(source: &str, pos: usize) -> Option<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut start = None;
    let mut depth = 0usize;
    for (i, &b) in bytes[..pos].iter().enumerate().rev() {
        match b {
            b'{' => {
                if depth == 0 {
                    let mut line_start = i;
                    while line_start > 0 && bytes[line_start - 1] != b'\n' {
                        line_start -= 1;
                    }
                    // include the method signature line
                    start = Some(line_start);
                    break;
                } else {
                    depth -= 1;
                }
            }
            b'}' => depth += 1,
            _ => {}
        }
    }
    let s = start?;
    depth = 0;
    let mut end = None;
    for (i, &b) in bytes.iter().enumerate().skip(pos) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                if depth == 0 {
                    end = Some(i + 1);
                    break;
                } else {
                    depth -= 1;
                }
            }
            _ => {}
        }
    }
    end.map(|e| (s, e))
}

#[cfg(test)]
mod tests {
    use super::{derive_assignment_lhs, line_col_at};

    #[test]
    fn derive_assignment_lhs_handles_non_char_boundary() {
        let source = "<?php
$foo = 1; —
";
        let em_dash = source.find('—').expect("must include em dash");
        let non_boundary = em_dash + 1;

        assert_eq!(derive_assignment_lhs(source, non_boundary), None);
    }

    #[test]
    fn line_col_at_handles_non_char_boundary() {
        let source = "a
—
";
        let em_dash = source.find('—').expect("must include em dash");
        let non_boundary = em_dash + 1;

        assert_eq!(line_col_at(source, non_boundary), (2, 1));
    }
}
