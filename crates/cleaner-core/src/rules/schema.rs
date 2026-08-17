use crate::models::SafetyLevel;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    DeleteContents,
    DeleteDirectory,
    DeleteFilesMatching,
    EmptyRecycleBin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTarget {
    pub path: String,
    pub action: RuleAction,
    pub pattern: Option<String>,
    pub allowed_root: Option<String>,
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
