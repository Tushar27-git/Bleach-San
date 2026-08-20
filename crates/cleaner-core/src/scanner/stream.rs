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
    exclude: &[String],
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

    let exclude_owned: Vec<String> = exclude.to_vec();

    for entry in WalkDir::new(dir)
        .skip_hidden(false)
        .follow_links(false)
        .parallelism(jwalk::Parallelism::RayonNewPool(1))
        .process_read_dir(move |_, _, _, children| {
            for dir_entry_result in children.iter_mut() {
                if let Ok(dir_entry) = dir_entry_result {
                    let entry_path = dir_entry.path();
                    if is_junction_or_symlink(&entry_path).unwrap_or(false) {
                        dir_entry.read_children_path = None;
                        continue;
                    }
                    if let Some(file_name) = entry_path.file_name().and_then(|n| n.to_str()) {
                        if exclude_owned.iter().any(|ex| ex.eq_ignore_ascii_case(file_name)) {
                            dir_entry.read_children_path = None;
                        }
                    }
                }
            }
        })
    {
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

            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");

            if exclude.iter().any(|ex| ex.eq_ignore_ascii_case(file_name)) {
                continue;
            }

            if !dir_entry.file_type.is_dir() {
                if let Ok(meta) = dir_entry.metadata() {
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

/// Simple glob-style pattern matcher for rules (supports wildcards like thumbcache_*.db, *.lnk, *contains*, or exact match).
pub fn matches_simple_pattern(name: &str, pattern: &str) -> bool {
    if pattern == "*" || pattern.is_empty() {
        return true;
    }
    let lower_name = name.to_lowercase();
    let lower_pat = pattern.to_lowercase();

    if let Ok(glob_pat) = glob::Pattern::new(&lower_pat) {
        glob_pat.matches(&lower_name)
    } else if let Some((prefix, suffix)) = lower_pat.split_once('*') {
        lower_name.len() >= prefix.len() + suffix.len()
            && lower_name.starts_with(prefix)
            && lower_name.ends_with(suffix)
    } else {
        lower_name == lower_pat
    }
}
