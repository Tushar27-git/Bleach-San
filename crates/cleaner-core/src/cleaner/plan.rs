use crate::models::{CleanupPlan, SafetyLevel};

/// Filters a list of plans to only those approved and eligible for automatic execution.
pub fn filter_actionable_plans(plans: &[CleanupPlan]) -> Vec<CleanupPlan> {
    plans
        .iter()
        .filter(|p| p.is_selected && !p.is_blocked_by_process && p.total_bytes > 0)
        .cloned()
        .collect()
}

/// Calculates the aggregate estimated bytes across all selected plans.
pub fn calculate_total_selected_bytes(plans: &[CleanupPlan]) -> u64 {
    plans
        .iter()
        .filter(|p| p.is_selected && !p.is_blocked_by_process)
        .map(|p| p.total_bytes)
        .sum()
}

/// Checks if any selected plan requires user review before proceeding.
pub fn contains_review_items(plans: &[CleanupPlan]) -> bool {
    plans
        .iter()
        .any(|p| p.is_selected && p.safety == SafetyLevel::Review)
}
