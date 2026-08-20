pub mod executor;
pub mod plan;

pub use executor::{is_active_session_artifact, CleanupExecutor};
pub use plan::{calculate_total_selected_bytes, contains_review_items, filter_actionable_plans};

use crate::models::{CleanupPlan, CleanupResult};

/// Executes a series of validated plans and aggregates all results.
pub fn execute_all_selected(plans: &[CleanupPlan]) -> Vec<CleanupResult> {
    let actionable = filter_actionable_plans(plans);
    actionable
        .iter()
        .map(CleanupExecutor::execute_plan)
        .collect()
}
