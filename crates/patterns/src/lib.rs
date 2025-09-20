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

#[derive(Debug, Clone)]
pub struct TaintPattern<R> {
    pub allow: Vec<R>,
    pub allow_focus_groups: Vec<Option<usize>>,
    pub deny: Option<R>,
    pub inside: Vec<R>,
    pub inside_focus_groups: Vec<Option<usize>>,
    pub not_inside: Vec<R>,
    pub focus: Option<String>,
}

impl<R> Default for TaintPattern<R> {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            allow_focus_groups: Vec::new(),
            deny: None,
            inside: Vec::new(),
            inside_focus_groups: Vec::new(),
            not_inside: Vec::new(),
            focus: None,
        }
    }
}
