//! Common utilities for the command line interface.
use regex::Regex;
use std::fs;
use std::path::Path;

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
            '?' => regex.push('.'),
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

/// Transforms a glob-style exclusion string into [`Regex`].
/// Accepts trailing slashes and expands to `**` automatically.
///
/// # Example
///
/// ```
/// use rootcause::parse_exclude;
/// let re = parse_exclude("target/").unwrap();
/// assert!(re.is_match("target/debug/foo"));
/// ```
pub fn parse_exclude(s: &str) -> Result<Regex, String> {
    let glob_str = if s.ends_with('/') {
        format!("{s}**")
    } else {
        s.to_string()
    };
    glob_to_regex(&glob_str).map_err(|e| e.to_string())
}

/// Default exclusion patterns.
pub fn default_excludes() -> Vec<Regex> {
    vec![
        parse_exclude("**/node_modules/**").expect("valid default"),
        parse_exclude("**/.git/**").expect("valid default"),
    ]
}

/// Reads `.gitignore` and `.sastignore` from `root` and converts their
/// valid entries to regular expressions.
pub fn load_ignore_patterns(root: &Path) -> Vec<Regex> {
    let mut patterns = Vec::new();
    for name in [".gitignore", ".sastignore"] {
        let path = root.join(name);
        if let Ok(content) = fs::read_to_string(path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let mut pat = line.trim_start_matches('/').to_string();
                if !pat.starts_with("**/") {
                    pat = format!("**/{pat}");
                }
                if let Ok(re) = parse_exclude(&pat) {
                    patterns.push(re);
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
/// let patterns = vec![parse_exclude("foo/**").unwrap()];
/// assert!(is_excluded(Path::new("foo/bar.txt"), &patterns, 0));
/// ```
pub fn is_excluded(path: &Path, patterns: &[Regex], max_file_size: u64) -> bool {
    let path_str = path.to_string_lossy().replace('\\', "/");
    if patterns.iter().any(|re| re.is_match(&path_str)) {
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
