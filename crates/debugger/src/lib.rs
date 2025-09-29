pub mod callgraph;
pub mod taint;
pub mod visualization;

mod timeline;
mod toolkit;

pub use timeline::{
    EventFormat, EventTimeline, FormatterSink, PipelineStage, RecordedEvent, StageSummary,
};
pub use toolkit::{
    AnalysisSnapshot, DebugScope, DebugToolkit, FileInspection, FileSummary, RuleInspection,
    RuleSummary,
};

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    Dot,
    Mermaid,
    Tree,
}
