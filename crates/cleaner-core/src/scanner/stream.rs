use cleaner_platform_windows::filesystem::is_junction_or_symlink;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use jwalk::WalkDir;

pub struct ScanStats {
    pub total_bytes: u64,
    pub file_count: usize,
    pub items: Vec<PathBuf>,
}

/// Recursively scans a directory aggregating total size and file count without retaining millions of metadata objects in memory.
pub fn scan_directory_bounded(
    dir: &Path,
    pattern: Option<&str>,
    cancel_flag: &Arc<AtomicBool>,
    max_items_to_record: usize,
) -> ScanStats {
    let mut stats = ScanStats {
        total_bytes: 0,
        file_count: 0,
        items: Vec::new(),
    };

    if !dir.exists() {
        return stats;
    }

    // Never follow junctions / symlinks into arbitrary disk targets
    if is_junction_or_symlink(dir).unwrap_or(false) {
        if let Ok(meta) = fs::symlink_metadata(dir) {
            stats.total_bytes += meta.len();
            stats.file_count += 1;
            stats.items.push(dir.to_path_buf());
        }
        return stats;
    }

    for entry in WalkDir::new(dir).skip_hidden(false).follow_links(false) {
        if cancel_flag.load(Ordering::Relaxed) {
            break;
        }

        if let Ok(dir_entry) = entry {
            let path = dir_entry.path();
            if path == dir {
                continue;
            }

            // check symlink logic explicitly if needed
            let is_symlink = is_junction_or_symlink(&path).unwrap_or(false);
            if is_symlink {
                continue;
            }

            if !dir_entry.file_type.is_dir() {
                if let Ok(meta) = dir_entry.metadata() {
                    let file_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("");

                    let matches_pattern = match pattern {
                        Some(pat) => matches_simple_pattern(file_name, pat),
                        None => true,
                    };

                    if matches_pattern {
                        stats.total_bytes += meta.len();
                        stats.file_count += 1;
                        if stats.items.len() < max_items_to_record {
                            stats.items.push(path);
                        }
                    }
                }
            }
        }
    }

    stats
}

/// Simple glob-style pattern matcher for rules (supports prefix*, *suffix, *contains*, or exact match).
pub fn matches_simple_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern.is_empty() {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if let Some(core) = prefix.strip_prefix('*') {
            return name.contains(core);
        }
        return name.starts_with(prefix);
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        return name.ends_with(suffix);
    }
    name.eq_ignore_ascii_case(pattern)
}
