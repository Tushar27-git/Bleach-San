use crate::models::{CleanupPlan, SafetyLevel, ScanProgress, TargetCandidate};
use crate::processes::ProcessGuard;
use crate::rules::env_resolver::resolve_env_vars;
use crate::rules::schema::{CleanerRule, RuleAction};
use crate::safety::validator::{classify_path_safety, validate_target_path};
use crate::scanner::stream::scan_directory_bounded;
use cleaner_platform_windows::recycle_bin::get_recycle_bin_info;
use crossbeam_channel::Sender;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct ScanWorker;

impl ScanWorker {
    /// Scans a single cleaner rule and produces a structured CleanupPlan.
    pub fn scan_rule(
        rule: &CleanerRule,
        progress_tx: Option<&Sender<ScanProgress>>,
        cancel_flag: &Arc<AtomicBool>,
    ) -> CleanupPlan {
        let mut candidates = Vec::new();
        let mut total_bytes: u64 = 0;
        let mut total_files: usize = 0;
        let mut warnings = Vec::new();

        // 1. Process Check
        let blocked_process_name = rule
            .requirements
            .as_ref()
            .and_then(|r| ProcessGuard::check_blocking_process(r.process_closed.as_deref()));

        let is_blocked_by_process = blocked_process_name.is_some();
        if let Some(ref proc_name) = blocked_process_name {
            warnings.push(format!(
                "Application is currently running ({proc_name}). Close it before cleaning."
            ));
        }

        // 2. Scan Targets
        for target in &rule.targets {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }

            // Check if special target (Recycle Bin)
            if target.path == "SPECIAL:RECYCLE_BIN" {
                if let Ok((bytes, count)) = get_recycle_bin_info(None) {
                    if bytes > 0 || count > 0 {
                        total_bytes += bytes;
                        total_files += count as usize;
                        candidates.push(TargetCandidate {
                            path: std::path::PathBuf::from("SPECIAL:RECYCLE_BIN"),
                            display_path: "Recycle Bin".to_string(),
                            size_bytes: bytes,
                            file_count: count as usize,
                            is_dir: true,
                            safety: rule.safety,
                            is_locked: false,
                            is_selected: true,
                        });
                    }
                }
                continue;
            }

            // Resolve environment variables
            let resolved_path = match resolve_env_vars(&target.path) {
                Ok(p) => p,
                Err(e) => {
                    warnings.push(format!("Failed to resolve path '{}': {}", target.path, e));
                    continue;
                }
            };

            let resolved_root = target
                .allowed_root
                .as_ref()
                .and_then(|r| resolve_env_vars(r).ok());

            // Validate path safety & confinement
            let validated_path = match validate_target_path(&resolved_path, resolved_root.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!("Path validation skipped '{:?}': {}", resolved_path, e);
                    continue;
                }
            };

            if !validated_path.exists() {
                continue;
            }

            if let Some(tx) = progress_tx {
                let _ = tx.send(ScanProgress {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    current_target: validated_path.to_string_lossy().to_string(),
                    scanned_bytes: total_bytes,
                    scanned_files: total_files,
                    is_complete: false,
                });
            }

            let safety = classify_path_safety(&validated_path, rule.safety);

            let stats = match target.action {
                RuleAction::DeleteContents | RuleAction::DeleteDirectory => {
                    scan_directory_bounded(&validated_path, None, cancel_flag, 50)
                }
                RuleAction::DeleteFilesMatching => {
                    let pat = target.pattern.as_deref().unwrap_or("*");
                    scan_directory_bounded(&validated_path, Some(pat), cancel_flag, 50)
                }
                RuleAction::EmptyRecycleBin => scan_directory_bounded(&validated_path, None, cancel_flag, 50),
            };

            if stats.total_bytes > 0 || stats.file_count > 0 {
                total_bytes += stats.total_bytes;
                total_files += stats.file_count;

                candidates.push(TargetCandidate {
                    path: validated_path.clone(),
                    display_path: validated_path.to_string_lossy().to_string(),
                    size_bytes: stats.total_bytes,
                    file_count: stats.file_count,
                    is_dir: validated_path.is_dir(),
                    safety,
                    is_locked: false,
                    is_selected: !is_blocked_by_process && safety == SafetyLevel::Safe,
                });
            }
        }

        let requires_admin = rule
            .requirements
            .as_ref()
            .and_then(|r| r.requires_admin)
            .unwrap_or(false);

        CleanupPlan {
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            category: rule.category.clone(),
            description: rule.description.clone(),
            candidates,
            total_bytes,
            total_files,
            safety: rule.safety,
            is_selected: !is_blocked_by_process && rule.safety == SafetyLevel::Safe && total_bytes > 0,
            is_blocked_by_process,
            blocked_process_name,
            requires_admin,
            warnings,
        }
    }
}
