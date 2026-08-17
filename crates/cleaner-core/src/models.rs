use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SafetyLevel {
    Safe,
    Review,
    UserData,
    Protected,
}

impl Default for SafetyLevel {
    fn default() -> Self {
        SafetyLevel::Safe
    }
}

impl std::fmt::Display for SafetyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyLevel::Safe => write!(f, "SAFE"),
            SafetyLevel::Review => write!(f, "REVIEW"),
            SafetyLevel::UserData => write!(f, "USER_DATA"),
            SafetyLevel::Protected => write!(f, "PROTECTED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetCandidate {
    pub path: PathBuf,
    pub display_path: String,
    pub size_bytes: u64,
    pub file_count: usize,
    pub is_dir: bool,
    pub safety: SafetyLevel,
    pub is_locked: bool,
    pub is_selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupPlan {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub description: String,
    pub candidates: Vec<TargetCandidate>,
    pub total_bytes: u64,
    pub total_files: usize,
    pub safety: SafetyLevel,
    pub is_selected: bool,
    pub is_blocked_by_process: bool,
    pub blocked_process_name: Option<String>,
    pub requires_admin: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CleanupResult {
    pub rule_id: String,
    pub rule_name: String,
    pub reclaimed_bytes: u64,
    pub files_deleted: usize,
    pub files_skipped: usize,
    pub errors: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub rule_id: String,
    pub rule_name: String,
    pub current_target: String,
    pub scanned_bytes: u64,
    pub scanned_files: usize,
    pub is_complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageItem {
    pub path: PathBuf,
    pub name: String,
    pub size_bytes: u64,
    pub is_dir: bool,
    pub child_count: usize,
    pub category: String,
    pub is_selected: bool,
}
