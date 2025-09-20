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

#[derive(Debug, Clone)]
/// Representation of how a rule matches against inputs.
pub enum MatcherKind {
    /// Regex search in plain text.
    TextRegex(AnyRegex, String /*scope/path*/),
    /// Multiple allow/deny expressions evaluated in the same file.
    TextRegexMulti {
        allow: Vec<(AnyRegex, String)>,
        deny: Option<AnyRegex>,
        inside: Vec<AnyRegex>,
        not_inside: Vec<AnyRegex>,
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
