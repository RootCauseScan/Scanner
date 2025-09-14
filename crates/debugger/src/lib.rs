use engine::debug::{DebugEvent, DebugSink};
use serde::Serialize;
use std::path::Path;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
pub enum EventFormat {
    Text,
    Json,
}

#[derive(Clone)]
pub struct FormatterSink {
    format: EventFormat,
    lines: Arc<Mutex<Vec<String>>>,
}

impl FormatterSink {
    pub fn new(format: EventFormat) -> Self {
        Self {
            format,
            lines: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn output(&self) -> String {
        self.lines
            .lock()
            .expect("debug sink lock poisoned")
            .join("\n")
    }
}

#[derive(Serialize, Debug)]
struct SerEvent {
    kind: &'static str,
    path: Option<String>,
    file: Option<String>,
    rule_id: Option<String>,
    matched: Option<bool>,
}

fn name(p: &Path) -> String {
    p.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default()
}

impl From<&DebugEvent> for SerEvent {
    fn from(e: &DebugEvent) -> Self {
        match e {
            DebugEvent::ParseStart { path } => SerEvent {
                kind: "ParseStart",
                path: Some(name(path)),
                file: None,
                rule_id: None,
                matched: None,
            },
            DebugEvent::ParseEnd { path } => SerEvent {
                kind: "ParseEnd",
                path: Some(name(path)),
                file: None,
                rule_id: None,
                matched: None,
            },
            DebugEvent::RuleCompiled { id } => SerEvent {
                kind: "RuleCompiled",
                path: None,
                file: None,
                rule_id: Some(id.clone()),
                matched: None,
            },
            DebugEvent::MatchAttempt { rule_id, file } => SerEvent {
                kind: "MatchAttempt",
                path: None,
                file: Some(name(file)),
                rule_id: Some(rule_id.clone()),
                matched: None,
            },
            DebugEvent::MatchResult {
                rule_id,
                file,
                matched,
            } => SerEvent {
                kind: "MatchResult",
                path: None,
                file: Some(name(file)),
                rule_id: Some(rule_id.clone()),
                matched: Some(*matched),
            },
        }
    }
}

impl DebugSink for FormatterSink {
    fn event(&self, event: DebugEvent) {
        let ser = SerEvent::from(&event);
        let line = match self.format {
            EventFormat::Text => format!("{ser:?}"),
            EventFormat::Json => serde_json::to_string(&ser).expect("serialize debug event"),
        };
        self.lines
            .lock()
            .expect("debug sink lock poisoned")
            .push(line);
    }
}
