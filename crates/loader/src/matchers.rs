use crate::regex_types::AnyRegex;
use patterns::AstPattern;
use regex::Regex;
use serde_json::Value as JsonValue;

#[derive(Debug, Clone)]
/// Expression for AST queries, combining type and value.
pub struct Query {
    pub kind: Regex,
    pub value: Option<Regex>,
}

pub type TaintPattern = patterns::TaintPattern<AnyRegex>;

/// One independent matching group within a TextRegexMulti rule.
///
/// A SubMatcher's `inside` guard only blocks its own `allow` patterns, not
/// patterns in sibling SubMatchers. This preserves Semgrep semantics where a
/// `pattern-inside` nested inside a `patterns:` block only applies to that
/// block's alternatives, not to the whole rule.
#[derive(Debug, Clone)]
pub struct SubMatcher {
    pub allow: Vec<(AnyRegex, String)>,
    pub deny: Option<AnyRegex>,
    pub inside: Vec<AnyRegex>,
    pub not_inside: Vec<AnyRegex>,
}

#[derive(Debug, Clone)]
/// Representation of how a rule matches against inputs.
pub enum MatcherKind {
    /// Regex search in plain text.
    TextRegex(AnyRegex, String /*scope/path*/),
    /// Multiple allow/deny expressions grouped into independent sub-matchers.
    ///
    /// Each SubMatcher has its own inside/not_inside guards so that
    /// `pattern-inside` from a nested `patterns:` block does not accidentally
    /// block sibling alternatives that don't require that context.
    TextRegexMulti {
        subs: Vec<SubMatcher>,
    },
    /// Exact comparison of a JSON value in a path.
    JsonPathEq(String, JsonValue),
    /// Regex evaluation over a JSON value.
    JsonPathRegex(String, Regex),
    /// Query on AST.
    AstQuery(Query),
    /// Structural pattern over AST.
    AstPattern(AstPattern),
    /// Executes a Rego module compiled to WASM.
    RegoWasm {
        wasm_path: String,
        entrypoint: String,
    },
    /// Information flow rules between sources and sinks.
    TaintRule {
        sources: Vec<TaintPattern>,
        sanitizers: Vec<TaintPattern>,
        reclass: Vec<TaintPattern>,
        sinks: Vec<TaintPattern>,
    },
}
