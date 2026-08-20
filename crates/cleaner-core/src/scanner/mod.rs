pub mod heuristic;
pub mod stream;
pub mod worker;

pub use heuristic::{DiscoveredCache, HeuristicDiscoveryEngine};
pub use stream::{matches_simple_pattern, scan_directory_bounded, ScanStats};
pub use worker::{apply_drive_to_path, get_system_drives, ScanWorker};

use crate::models::{CleanupPlan, ScanProgress};
use crate::rules::schema::CleanerRule;
use crossbeam_channel::Sender;
use rayon::prelude::*;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// Scans a collection of cleaner rules in parallel with bounded Rayon concurrency,
/// and runs the Heuristic Discovery Engine for dynamic secondary drive cache discovery.
pub fn scan_all_rules(
    rules: &[CleanerRule],
    target_drive: Option<&str>,
    progress_tx: Option<Sender<ScanProgress>>,
    cancel_flag: Arc<AtomicBool>,
) -> Vec<CleanupPlan> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .unwrap_or_else(|_| rayon::ThreadPoolBuilder::new().build().unwrap());

    let mut plans: Vec<CleanupPlan> = pool.install(|| {
        rules
            .par_iter()
            .map(|rule| {
                ScanWorker::scan_rule(rule, target_drive, progress_tx.as_ref(), &cancel_flag)
            })
            .collect()
    });

    // Run dynamic heuristic discovery for the targeted drive (e.g. F:\, D:\, or All Drives)
    let drive_str = target_drive.unwrap_or("All Drives");
    let heuristic_plans = HeuristicDiscoveryEngine::discover_drive_caches(drive_str, &cancel_flag);

    // Merge heuristic items avoiding duplicates with curated rules
    for h_plan in heuristic_plans {
        if !plans.iter().any(|p| {
            p.candidates.iter().any(|c| {
                h_plan.candidates.iter().any(|hc| hc.path == c.path)
            })
        }) {
            plans.push(h_plan);
        }
    }

    plans
}
