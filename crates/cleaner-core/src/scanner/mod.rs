pub mod stream;
pub mod worker;

pub use stream::{matches_simple_pattern, scan_directory_bounded, ScanStats};
pub use worker::ScanWorker;

use crate::models::{CleanupPlan, ScanProgress};
use crate::rules::schema::CleanerRule;
use crossbeam_channel::Sender;
use rayon::prelude::*;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Scans a collection of cleaner rules in parallel with bounded Rayon concurrency.
pub fn scan_all_rules(
    rules: &[CleanerRule],
    target_drive: Option<&str>,
    progress_tx: Option<Sender<ScanProgress>>,
    cancel_flag: Arc<AtomicBool>,
) -> Vec<CleanupPlan> {
    let plans: Vec<CleanupPlan> = rules
        .par_iter()
        .map(|rule| {
            ScanWorker::scan_rule(rule, target_drive, progress_tx.as_ref(), &cancel_flag)
        })
        .collect();

    plans
}
