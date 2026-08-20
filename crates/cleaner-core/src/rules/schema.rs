use crate::models::SafetyLevel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    DeleteContents,
    DeleteDirectory,
    DeleteFilesMatching,
    EmptyRecycleBin,
}

impl Default for RuleAction {
    fn default() -> Self {
        RuleAction::DeleteContents
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DiscoveryStrategy {
    #[serde(rename = "config")]
    Config {
        file: String,
        format: String, // e.g. "key-value"
        key: String,
        fallback: Option<String>,
        append: Option<String>, // Path to append after the key value
    },
    #[serde(rename = "glob")]
    Glob {
        pattern: String,
    },
    #[serde(rename = "deep_search")]
    DeepSearch {
        base_paths: Vec<String>,
        target_names: Vec<String>,
        max_depth: Option<usize>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTarget {
    pub path: Option<String>,
    pub action: RuleAction,
    pub pattern: Option<String>,
    pub allowed_root: Option<String>,
    pub discovery: Option<DiscoveryStrategy>,
    #[serde(default)]
    pub exclude: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleRequirements {
    pub process_closed: Option<String>,
    pub requires_admin: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanerRule {
    pub id: String,
    pub name: String,
    pub category: String,
    pub description: String,
    #[serde(default)]
    pub safety: SafetyLevel,
    pub targets: Vec<RuleTarget>,
    #[serde(default)]
    pub requirements: Option<RuleRequirements>,
}
