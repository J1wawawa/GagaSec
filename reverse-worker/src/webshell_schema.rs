//! Versioned, bounded evidence contract shared by the worker and desktop.
//! Byte spans refer to source_layer_id; the transformed input's parent_id can
//! differ for nested expressions. Neither is hypothetical runtime code.
use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Layer {
    pub id: String,
    pub parent_id: Option<String>,
    pub operation: String,
    pub format: String,
    pub depth: usize,
    pub source_layer_id: String,
    pub source_start: usize,
    pub source_end: usize,
    pub source_line: usize,
    pub source_excerpt: String,
    pub input_sha256: String,
    pub sha256: String,
    pub bytes: usize,
    pub preview: String,
    pub truncated: bool,
    pub finding_ids: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Trace {
    pub layer_id: String,
    pub line: usize,
    pub sources: Vec<String>,
    pub sinks: Vec<String>,
    pub basis: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub title: String,
    pub status: String,
    pub detail: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebshellAnalysis {
    pub version: String,
    pub language: String,
    pub rules_version: String,
    pub input_sha256: String,
    pub layers: Vec<Layer>,
    pub traces: Vec<Trace>,
    pub checks: Vec<Check>,
    pub limits: Vec<String>,
}
