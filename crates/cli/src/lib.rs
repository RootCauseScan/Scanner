//! Common utilities for the command line interface.
use regex::Regex;
use std::fs;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct IgnorePattern {
    pub regex: Regex,
    pub exclude: bool,
}

pub mod args;
pub mod config;
pub mod output;
pub mod plugins;
pub mod rules;
pub mod scan;
pub mod ui;

/// Default maximum size: 5 MiB.
pub const DEFAULT_MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;

/// Converts a basic glob pattern to a regular expression.
///
/// # Example
///
/// ```
/// use rootcause::glob_to_regex;
/// let re = glob_to_regex("src/*.rs").unwrap();
/// assert!(re.is_match("src/main.rs"));
/// ```
pub fn glob_to_regex(pat: &str) -> Result<Regex, regex::Error> {
    if pat.contains('[') || pat.contains(']') {
        // Caracteres de clase no soportados
        let invalid = "[".to_string();
        return Regex::new(&invalid);
    }
    let mut regex = String::from("^");
    let mut chars = pat.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => {
                if chars.peek() == Some(&'*') {
                    chars.next();
                    regex.push_str(".*");
                } else {
                    regex.push_str("[^/]*");
                }
            }
            '?' => regex.push_str("[^/]"),
            '.' => regex.push_str("\\."),
            '/' => regex.push('/'),
            '(' | ')' | '+' | '|' | '^' | '$' | '[' | ']' | '{' | '}' | '\\' => {
                regex.push('\\');
                regex.push(c);
            }
            _ => regex.push(c),
        }
    }
    regex.push('$');
    Regex::new(&regex)
}

/// Transforms a glob-style exclusion string into [`IgnorePattern`].
/// Accepts trailing slashes and expands to `**` automatically.
///
/// # Example
///
/// ```
/// use rootcause::parse_exclude;
/// let pattern = parse_exclude("target/").unwrap();
/// assert!(pattern.exclude);
/// assert!(pattern.regex.is_match("target/debug/foo"));
/// ```
pub fn parse_exclude(s: &str) -> Result<IgnorePattern, String> {
    let trimmed = s.trim();
    let (exclude, glob_src) = if let Some(rest) = trimmed.strip_prefix('!') {
        if rest.is_empty() {
            return Err("empty exclude pattern".into());
        }
        (false, rest)
    } else {
        (true, trimmed)
    };
    let glob_str = if glob_src.ends_with('/') {
        format!("{glob_src}**")
    } else {
        glob_src.to_string()
    };
    let regex = glob_to_regex(&glob_str).map_err(|e| e.to_string())?;
    Ok(IgnorePattern { regex, exclude })
}

/// Default exclusion patterns.
pub fn default_excludes() -> Vec<IgnorePattern> {
    vec![
        parse_exclude("**/node_modules/**").expect("valid default"),
        parse_exclude("**/.git/**").expect("valid default"),
    ]
}

/// Reads `.gitignore` and `.sastignore` from `root` and converts their
/// valid entries to ordered [`IgnorePattern`] instances.
pub fn load_ignore_patterns(root: &Path) -> Vec<IgnorePattern> {
    let mut patterns = Vec::new();
    for name in [".gitignore", ".sastignore"] {
        let path = root.join(name);
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let (is_negated, rest) = if let Some(stripped) = line.strip_prefix('!') {
                    (true, stripped)
                } else {
                    (false, line)
                };
                let mut pat = rest.trim_start_matches('/').to_string();
                if !pat.starts_with("**/") {
                    pat = format!("**/{pat}");
                }
                if is_negated {
                    pat.insert(0, '!');
                }
                if let Ok(pattern) = parse_exclude(&pat) {
                    patterns.push(pattern);
                }
            }
        }
    }
    patterns
}

/// Indicates whether a path should be omitted according to patterns or size.
/// Separators are normalised to support Windows and Unix.
///
/// # Example
///
/// ```
/// use rootcause::{is_excluded, parse_exclude};
/// use std::path::Path;
/// let patterns = vec![
///     parse_exclude("foo/**").unwrap(),
///     parse_exclude("!foo/.keep").unwrap(),
/// ];
/// assert!(is_excluded(Path::new("foo/bar.txt"), &patterns, 0));
/// assert!(!is_excluded(Path::new("foo/.keep"), &patterns, 0));
/// ```
pub fn is_excluded(path: &Path, patterns: &[IgnorePattern], max_file_size: u64) -> bool {
    let path_str = path.to_string_lossy().replace('\\', "/");
    let mut decision = None;
    for pattern in patterns {
        if pattern.regex.is_match(&path_str) {
            decision = Some(pattern.exclude);
        }
    }
    if decision == Some(true) {
        return true;
    }
    if max_file_size > 0 {
        if let Ok(meta) = fs::metadata(path) {
            if meta.is_file() && meta.len() > max_file_size {
                return true;
            }
        }
    }
    false
}
