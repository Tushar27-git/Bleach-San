pub mod cleaner;
pub mod models;
pub mod processes;
pub mod rules;
pub mod safety;
pub mod scanner;
pub mod storage;

pub use cleaner::{calculate_total_selected_bytes, contains_review_items, execute_all_selected, filter_actionable_plans, CleanupExecutor};
pub use models::{CleanupPlan, CleanupResult, SafetyLevel, ScanProgress, StorageItem, TargetCandidate};
pub use processes::ProcessGuard;
pub use rules::{get_embedded_rules, load_rule_from_file, load_rules_from_dir, parse_rule_toml, CleanerRule, RuleAction, RuleRequirements, RuleTarget};
pub use safety::{classify_path_safety, get_protected_paths, is_actionable_automatically, is_exact_protected_path, is_forbidden_from_cleanup, requires_explicit_user_review, validate_target_path, SafetyError};
pub use scanner::{apply_drive_to_path, get_system_drives, matches_simple_pattern, scan_all_rules, scan_directory_bounded, HeuristicDiscoveryEngine, ScanStats, ScanWorker};
pub use storage::StorageAnalyzer;

/// Formats raw bytes into a human-readable string (e.g. 1.25 GB, 450 MB, 12 KB).
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.0} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
