use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstPattern {
    pub kind: String,
    #[serde(default)]
    pub within: Option<String>,
    #[serde(default)]
    pub metavariables: HashMap<String, MetaVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaVar {
    pub kind: String,
    #[serde(default)]
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TaintPattern {
    pub allow: Vec<Regex>,
    pub deny: Option<Regex>,
    pub inside: Vec<Regex>,
    pub not_inside: Vec<Regex>,
    pub focus: Option<String>,
}
