use serde::Serialize;
use std::path::PathBuf;
use std::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
pub enum DebugEvent {
    ParseStart {
        path: PathBuf,
    },
    ParseEnd {
        path: PathBuf,
    },
    RuleCompiled {
        id: String,
    },
    MatchAttempt {
        rule_id: String,
        file: PathBuf,
    },
    MatchResult {
        rule_id: String,
        file: PathBuf,
        matched: bool,
    },
}

pub trait DebugSink: Send + Sync {
    fn event(&self, event: DebugEvent);
}

static DEBUG_SINK: RwLock<Option<Box<dyn DebugSink>>> = RwLock::new(None);

pub fn set_debug_sink(sink: Option<Box<dyn DebugSink>>) {
    *DEBUG_SINK.write().expect("debug sink lock poisoned") = sink;
}

pub(crate) fn emit(event: DebugEvent) {
    if let Some(s) = DEBUG_SINK
        .read()
        .expect("debug sink lock poisoned")
        .as_ref()
    {
        s.event(event);
    }
}
