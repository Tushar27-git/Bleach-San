use crate::models::{CleanupPlan, SafetyLevel, ScanProgress, TargetCandidate};
use crate::processes::ProcessGuard;
use crate::rules::env_resolver::resolve_env_vars;
use crate::rules::schema::{CleanerRule, RuleAction};
use crate::safety::validator::{classify_path_safety, validate_target_path};
use crate::scanner::stream::scan_directory_bounded;
use cleaner_platform_windows::recycle_bin::get_recycle_bin_info;
use crossbeam_channel::Sender;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Returns all available root drives (e.g. ["C:\\", "D:\\", "E:\\"]).
pub fn get_system_drives() -> Vec<String> {
    let mut drives = Vec::new();
    for c in b'C'..=b'Z' {
        let drive = format!("{}:\\", c as char);
        if std::path::Path::new(&drive).exists() {
            drives.push(drive);
        }
    }
    if drives.is_empty() {
        drives.push("C:\\".to_string());
    }
    drives
}

/// Rewrites a path's drive letter (e.g. from C:\... to D:\...) if target_drive is a specific drive letter.
pub fn apply_drive_to_path(path: &Path, target_drive: &str) -> PathBuf {
    if target_drive.eq_ignore_ascii_case("All Drives") || target_drive.is_empty() {
        return path.to_path_buf();
    }
    let clean_drv = target_drive.trim_end_matches('\\');
    let path_str = path.to_string_lossy();
    if path_str.len() >= 3 && &path_str[1..3] == ":\\" {
        let current_drive = &path_str[0..1];
        let target_letter = &clean_drv[0..1];
        if !current_drive.eq_ignore_ascii_case(target_letter) {
            let remainder = &path_str[2..];
            return PathBuf::from(format!("{}{}", clean_drv, remainder));
        }
    }
    path.to_path_buf()
}

pub struct ScanWorker;

impl ScanWorker {
    /// Scans a single cleaner rule and produces a structured CleanupPlan.
    pub fn scan_rule(
        rule: &CleanerRule,
        target_drive: Option<&str>,
        progress_tx: Option<&Sender<ScanProgress>>,
        cancel_flag: &Arc<AtomicBool>,
    ) -> CleanupPlan {
        let is_all_drives = match target_drive {
            Some(d) => d.eq_ignore_ascii_case("All Drives"),
            None => true,
        };

        if is_all_drives {
            let drives = get_system_drives();
            let mut combined_candidates = Vec::new();
            let mut total_bytes: u64 = 0;
            let mut total_files: usize = 0;
            let mut combined_warnings = Vec::new();

            for drive in &drives {
                if cancel_flag.load(Ordering::Relaxed) {
                    break;
                }
                let plan = Self::scan_rule_for_drive(rule, Some(drive), progress_tx, cancel_flag);
                for cand in plan.candidates {
                    if !combined_candidates.iter().any(|c: &TargetCandidate| c.path == cand.path) {
                        total_bytes += cand.size_bytes;
                        total_files += cand.file_count;
                        combined_candidates.push(cand);
                    }
                }
                for w in plan.warnings {
                    if !combined_warnings.contains(&w) {
                        combined_warnings.push(w);
                    }
                }
            }

            let blocked_process_name = rule
                .requirements
                .as_ref()
                .and_then(|r| ProcessGuard::check_blocking_process(r.process_closed.as_deref()));
            let is_blocked_by_process = blocked_process_name.is_some();
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
                candidates: combined_candidates,
                total_bytes,
                total_files,
                safety: rule.safety,
                is_selected: !is_blocked_by_process && rule.safety == SafetyLevel::Safe && total_bytes > 0,
                is_blocked_by_process,
                blocked_process_name,
                requires_admin,
                warnings: combined_warnings,
            }
        } else {
            Self::scan_rule_for_drive(rule, target_drive, progress_tx, cancel_flag)
        }
    }

    /// Scans a single cleaner rule for a specific drive (e.g. "C:\\" or "D:\\").
    fn scan_rule_for_drive(
        rule: &CleanerRule,
        target_drive: Option<&str>,
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
            if target.path.as_deref() == Some("SPECIAL:RECYCLE_BIN") {
                let rb_drive = target_drive.filter(|d| !d.eq_ignore_ascii_case("All Drives"));
                if let Ok((bytes, count)) = get_recycle_bin_info(rb_drive) {
                    if bytes > 0 || count > 0 {
                        let display_name = match rb_drive {
                            Some(d) => format!("Recycle Bin ({})", d.trim_end_matches('\\')),
                            None => "Recycle Bin".to_string(),
                        };
                        total_bytes += bytes;
                        total_files += count as usize;
                        candidates.push(TargetCandidate {
                            path: PathBuf::from(format!("SPECIAL:RECYCLE_BIN:{}", rb_drive.unwrap_or("ALL"))),
                            display_path: display_name,
                            size_bytes: bytes,
                            file_count: count as usize,
                            is_dir: true,
                            safety: rule.safety,
                            is_locked: false,
                            is_selected: true,
                            action: RuleAction::EmptyRecycleBin,
                            pattern: None,
                            exclude: Vec::new(),
                        });
                    }
                }
                continue;
            }

            // Resolve target paths (handles config files, glob patterns, or static path)
            let resolved_paths = crate::rules::discovery_resolver::resolve_target_paths(target, target_drive);
            if resolved_paths.is_empty() {
                continue;
            }

            for path_str in resolved_paths {
                let mut resolved_path = match resolve_env_vars(&path_str) {
                    Ok(p) => p,
                    Err(e) => {
                        warnings.push(format!("Failed to resolve path '{}': {}", path_str, e));
                        continue;
                    }
                };

                let mut resolved_root = target
                    .allowed_root
                    .as_ref()
                    .and_then(|r| resolve_env_vars(r).ok());
                    
                if let Some(target_drv) = target_drive {
                    if !target_drv.eq_ignore_ascii_case("All Drives") {
                        resolved_path = apply_drive_to_path(&resolved_path, target_drv);
                        if let Some(ref mut root_path) = resolved_root {
                            *root_path = apply_drive_to_path(root_path, target_drv);
                        }
                    }
                }

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

                let mut effective_exclude = target.exclude.clone().unwrap_or_default();
                let val_path_str = validated_path.to_string_lossy();
                if val_path_str.ends_with(r"\Microsoft\Windows\Recent") || val_path_str.ends_with(r"/Microsoft/Windows/Recent") {
                    if !effective_exclude.iter().any(|e| e.eq_ignore_ascii_case("AutomaticDestinations")) {
                        effective_exclude.push("AutomaticDestinations".to_string());
                    }
                    if !effective_exclude.iter().any(|e| e.eq_ignore_ascii_case("CustomDestinations")) {
                        effective_exclude.push("CustomDestinations".to_string());
                    }
                }

                let stats = match target.action {
                    RuleAction::DeleteContents | RuleAction::DeleteDirectory => {
                        scan_directory_bounded(&validated_path, None, &effective_exclude, cancel_flag, 50)
                    }
                    RuleAction::DeleteFilesMatching => {
                        let pat = target.pattern.as_deref().unwrap_or("*");
                        scan_directory_bounded(&validated_path, Some(pat), &effective_exclude, cancel_flag, 50)
                    }
                    RuleAction::EmptyRecycleBin => scan_directory_bounded(&validated_path, None, &effective_exclude, cancel_flag, 50),
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
                        action: target.action,
                        pattern: target.pattern.clone(),
                        exclude: effective_exclude,
                    });
                }
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
