use clap::ValueEnum;
use engine::debug::{DebugEvent, DebugSink};
use serde::Serialize;
use std::fmt::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum PipelineStage {
    Input,
    Parsing,
    RuleCompilation,
    RuleEvaluation,
    Matching,
    Unknown,
}

impl PipelineStage {
    pub fn as_str(self) -> &'static str {
        match self {
            PipelineStage::Input => "input",
            PipelineStage::Parsing => "parsing",
            PipelineStage::RuleCompilation => "rule-compilation",
            PipelineStage::RuleEvaluation => "rule-evaluation",
            PipelineStage::Matching => "matching",
            PipelineStage::Unknown => "unknown",
        }
    }
}

impl fmt::Display for PipelineStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct RecordedEvent {
    pub index: usize,
    pub stage: PipelineStage,
    #[serde(rename = "elapsed_ms")]
    pub elapsed_millis: u128,
    pub description: String,
    pub event: DebugEvent,
}

impl RecordedEvent {
    fn new(index: usize, elapsed: Duration, event: DebugEvent) -> Self {
        let stage = classify_stage(&event);
        let description = describe_event(&event);
        Self {
            index,
            stage,
            elapsed_millis: elapsed.as_millis(),
            description,
            event,
        }
    }

    pub fn elapsed_seconds(&self) -> f64 {
        self.elapsed_millis as f64 / 1_000.0
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct StageSummary {
    pub stage: PipelineStage,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventTimeline {
    pub events: Vec<RecordedEvent>,
}

impl EventTimeline {
    pub fn new(events: Vec<RecordedEvent>) -> Self {
        Self { events }
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for event in &self.events {
            let _ = writeln!(
                out,
                "[+{elapsed:>7.3}s] {stage:<16} {description}",
                elapsed = event.elapsed_seconds(),
                stage = event.stage,
                description = event.description
            );
        }
        out
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string_pretty(&self.events).expect("serialize timeline")
    }

    pub fn to_mermaid(&self) -> String {
        let mut out = String::from("graph TD\n");
        for event in &self.events {
            let node_id = format!("E{}", event.index);
            let label = format!(
                "{}<br/>{}",
                event.stage.as_str(),
                event.description.replace('"', "\\\"")
            );
            let _ = writeln!(out, "    {node_id}[\"{label}\"]");
        }
        for window in self.events.windows(2) {
            if let [prev, next] = window {
                let _ = writeln!(out, "    E{} --> E{}", prev.index, next.index);
            }
        }
        out
    }

    pub fn stage_summary(&self) -> Vec<StageSummary> {
        let mut map = std::collections::BTreeMap::new();
        for event in &self.events {
            *map.entry(event.stage).or_insert(0usize) += 1;
        }
        map.into_iter()
            .map(|(stage, count)| StageSummary { stage, count })
            .collect()
    }
}

#[derive(Clone)]
pub struct TimelineSink {
    inner: Arc<Mutex<TimelineInner>>,
}

impl TimelineSink {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TimelineInner::default())),
        }
    }

    fn push_event(&self, event: DebugEvent) {
        let mut inner = self.inner.lock().expect("timeline sink lock poisoned");
        let now = Instant::now();
        let start = inner.start.get_or_insert(now);
        let elapsed = now.duration_since(*start);
        let index = inner.events.len();
        inner.events.push(RecordedEvent::new(index, elapsed, event));
    }

    pub fn snapshot(&self) -> EventTimeline {
        let inner = self.inner.lock().expect("timeline sink lock poisoned");
        EventTimeline::new(inner.events.clone())
    }

    pub fn reset(&self) {
        let mut inner = self.inner.lock().expect("timeline sink lock poisoned");
        inner.events.clear();
        inner.start = None;
    }
}

impl DebugSink for TimelineSink {
    fn event(&self, event: DebugEvent) {
        self.push_event(event);
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum EventFormat {
    Text,
    Json,
    Mermaid,
}

#[derive(Clone)]
pub struct FormatterSink {
    format: EventFormat,
    timeline: TimelineSink,
}

impl FormatterSink {
    pub fn new(format: EventFormat) -> Self {
        Self {
            format,
            timeline: TimelineSink::new(),
        }
    }

    pub fn output(&self) -> String {
        let timeline = self.timeline.snapshot();
        match self.format {
            EventFormat::Text => timeline.to_text(),
            EventFormat::Json => timeline.to_json_string(),
            EventFormat::Mermaid => timeline.to_mermaid(),
        }
    }

    pub fn timeline(&self) -> EventTimeline {
        self.timeline.snapshot()
    }
}

impl DebugSink for FormatterSink {
    fn event(&self, event: DebugEvent) {
        self.timeline.push_event(event);
    }
}

fn classify_stage(event: &DebugEvent) -> PipelineStage {
    match event {
        DebugEvent::ParseStart { .. } | DebugEvent::ParseEnd { .. } => PipelineStage::Parsing,
        DebugEvent::RuleCompiled { .. } => PipelineStage::RuleCompilation,
        DebugEvent::MatchAttempt { .. } => PipelineStage::RuleEvaluation,
        DebugEvent::MatchResult { .. } => PipelineStage::Matching,
    }
}

fn describe_event(event: &DebugEvent) -> String {
    match event {
        DebugEvent::ParseStart { path } => {
            format!("Parsing started: {}", display_name(path))
        }
        DebugEvent::ParseEnd { path } => {
            format!("Parsing completed: {}", display_name(path))
        }
        DebugEvent::RuleCompiled { id } => {
            format!("Rule compiled: {id}")
        }
        DebugEvent::MatchAttempt { rule_id, file } => {
            format!("Evaluating rule '{rule_id}' on {}", display_name(file))
        }
        DebugEvent::MatchResult {
            rule_id,
            file,
            matched,
        } => {
            let status = if *matched { "matched" } else { "missed" };
            format!("Rule '{rule_id}' {status} for {}", display_name(file))
        }
    }
}

fn display_name(path: &std::path::Path) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

#[derive(Default)]
struct TimelineInner {
    start: Option<Instant>,
    events: Vec<RecordedEvent>,
}
