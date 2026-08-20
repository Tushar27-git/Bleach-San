use crate::models::{CleanupPlan, CleanupResult};
use crate::rules::schema::RuleAction;
use crate::safety::blocklist::is_forbidden_from_cleanup as is_forbidden_path;
use crate::safety::levels::is_forbidden_from_cleanup;
use crate::scanner::matches_simple_pattern;
use cleaner_platform_windows::filesystem::{
    delete_dir_safely, delete_file_safely, is_junction_or_symlink,
};
use cleaner_platform_windows::recycle_bin::empty_recycle_bin;
use std::fs;
use std::path::Path;
use std::time::Instant;

pub struct CleanupExecutor;

impl CleanupExecutor {
    /// Executes the destructive operations outlined in a single validated CleanupPlan.
    pub fn execute_plan(plan: &CleanupPlan) -> CleanupResult {
        let start_time = Instant::now();
        let mut result = CleanupResult {
            rule_id: plan.rule_id.clone(),
            rule_name: plan.rule_name.clone(),
            reclaimed_bytes: 0,
            files_deleted: 0,
            files_skipped: 0,
            errors: Vec::new(),
            duration_ms: 0,
        };

        // Strict Safety Check: Never clean USER_DATA or PROTECTED targets
        if is_forbidden_from_cleanup(plan.safety) {
            result.errors.push(format!(
                "Execution aborted: Rule '{}' has safety level '{}' which is strictly forbidden from deletion.",
                plan.rule_id, plan.safety
            ));
            result.duration_ms = start_time.elapsed().as_millis() as u64;
            return result;
        }

        for candidate in &plan.candidates {
            if !candidate.is_selected {
                continue;
            }

            // Hardcoded Driver & Kernel Safety Shield: Never delete active drivers or core registry
            if is_forbidden_path(&candidate.path) {
                result.errors.push(format!(
                    "Critical Safety Violation: Candidate path '{:?}' is a protected Windows driver or system kernel path. Skipped.",
                    candidate.path
                ));
                result.files_skipped += 1;
                continue;
            }

            // Special handling: Recycle Bin
            let path_str = candidate.path.to_string_lossy();
            if candidate.action == RuleAction::EmptyRecycleBin
                || path_str.starts_with("SPECIAL:RECYCLE_BIN")
            {
                let target_drive = path_str
                    .strip_prefix("SPECIAL:RECYCLE_BIN:")
                    .filter(|d| *d != "ALL" && !d.is_empty());

                match empty_recycle_bin(target_drive) {
                    Ok(_) => {
                        result.reclaimed_bytes += candidate.size_bytes;
                        result.files_deleted += candidate.file_count;
                    }
                    Err(e) => {
                        result.errors.push(format!("Failed to empty Recycle Bin: {}", e));
                    }
                }
                continue;
            }

            if !candidate.path.exists() {
                // Already deleted or moved
                continue;
            }

            if candidate.is_dir {
                match candidate.action {
                    RuleAction::DeleteFilesMatching => {
                        let pat = candidate.pattern.as_deref().unwrap_or("*");
                        Self::clean_matching_files(&candidate.path, pat, &candidate.exclude, &mut result);
                    }
                    RuleAction::DeleteContents => {
                        Self::clean_directory_contents(&candidate.path, &candidate.exclude, &mut result);
                    }
                    RuleAction::DeleteDirectory => {
                        Self::clean_directory(&candidate.path, &mut result);
                    }
                    RuleAction::EmptyRecycleBin => {}
                }
            } else {
                // Single file deletion
                Self::clean_single_file(&candidate.path, &mut result);
            }
        }

        result.duration_ms = start_time.elapsed().as_millis() as u64;
        result
    }

    /// Recursively cleans files inside a folder matching a pattern, while leaving directories and non-matching files untouched.
    fn clean_matching_files(dir: &Path, pattern: &str, exclude: &[String], result: &mut CleanupResult) {
        if is_junction_or_symlink(dir).unwrap_or(false) {
            return;
        }

        let read_dir = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => {
                result.errors.push(format!("Inaccessible dir {:?}: {}", dir, e));
                result.files_skipped += 1;
                return;
            }
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            let is_symlink = is_junction_or_symlink(&path).unwrap_or(false);

            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if exclude.iter().any(|ex| ex.eq_ignore_ascii_case(name)) {
                    continue;
                }

                if let Ok(meta) = entry.metadata() {
                    let size = meta.len();
                    if meta.is_dir() && !is_symlink {
                        // Recursively search subdirectories for matching files, but NEVER delete subdirectories
                        Self::clean_matching_files(&path, pattern, exclude, result);
                    } else if !meta.is_dir() {
                        if matches_simple_pattern(name, pattern) {
                            match delete_file_safely(&path) {
                                Ok(_) => {
                                    result.reclaimed_bytes += size;
                                    result.files_deleted += 1;
                                }
                                Err(e) => {
                                    result.errors.push(format!("Failed to delete file {:?}: {}", path, e));
                                    result.files_skipped += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Recursively cleans contents inside a folder without deleting the root folder itself.
    fn clean_directory_contents(dir: &Path, exclude: &[String], result: &mut CleanupResult) {
        if is_junction_or_symlink(dir).unwrap_or(false) {
            // Do not traverse into junction mounts
            return;
        }

        let read_dir = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => {
                result.errors.push(format!("Inaccessible dir {:?}: {}", dir, e));
                result.files_skipped += 1;
                return;
            }
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            let is_symlink = is_junction_or_symlink(&path).unwrap_or(false);

            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                // Hard protection: never delete Quick Access pinned destinations or custom destinations
                if name.eq_ignore_ascii_case("AutomaticDestinations") || name.eq_ignore_ascii_case("CustomDestinations") {
                    continue;
                }

                if exclude.iter().any(|ex| ex.eq_ignore_ascii_case(name)) {
                    continue;
                }

                if let Ok(meta) = entry.metadata() {
                    let size = meta.len();
                    if meta.is_dir() && !is_symlink {
                        match delete_dir_safely(&path) {
                            Ok(_) => {
                                result.reclaimed_bytes += size;
                                result.files_deleted += 1;
                            }
                            Err(e) => {
                                result.errors.push(format!("Failed to delete dir {:?}: {}", path, e));
                                result.files_skipped += 1;
                            }
                        }
                    } else {
                        match delete_file_safely(&path) {
                            Ok(_) => {
                                result.reclaimed_bytes += size;
                                result.files_deleted += 1;
                            }
                            Err(e) => {
                                result.errors.push(format!("Failed to delete file {:?}: {}", path, e));
                                result.files_skipped += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Deletes an entire directory safely.
    fn clean_directory(path: &Path, result: &mut CleanupResult) {
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        match delete_dir_safely(path) {
            Ok(_) => {
                result.reclaimed_bytes += size;
                result.files_deleted += 1;
            }
            Err(e) => {
                result.errors.push(format!("Failed to delete dir {:?}: {}", path, e));
                result.files_skipped += 1;
            }
        }
    }

    /// Cleans a single file target safely.
    fn clean_single_file(path: &Path, result: &mut CleanupResult) {
        let size = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        match delete_file_safely(path) {
            Ok(_) => {
                result.reclaimed_bytes += size;
                result.files_deleted += 1;
            }
            Err(e) => {
                result.errors.push(format!("Failed to delete {:?}: {}", path, e));
                result.files_skipped += 1;
            }
        }
    }
}
