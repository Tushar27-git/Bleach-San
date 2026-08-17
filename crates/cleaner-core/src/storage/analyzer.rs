use crate::models::StorageItem;
use cleaner_platform_windows::filesystem::is_junction_or_symlink;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct StorageAnalyzer;

impl StorageAnalyzer {
    /// Analyzes the direct subdirectories and files of a given root folder in parallel and calculates their total sizes.
    pub fn analyze_directory(
        root: &Path,
        cancel_flag: &Arc<AtomicBool>,
        max_results: usize,
    ) -> Vec<StorageItem> {
        if !root.exists() || !root.is_dir() {
            return Vec::new();
        }

        let read_dir = match fs::read_dir(root) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        let entries: Vec<_> = read_dir.flatten().collect();

        let mut items: Vec<StorageItem> = entries
            .par_iter()
            .filter_map(|entry| {
                if cancel_flag.load(Ordering::Relaxed) {
                    return None;
                }

                let path = entry.path();
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Unknown")
                    .to_string();

                let is_symlink = is_junction_or_symlink(&path).unwrap_or(false);

                if let Ok(meta) = entry.metadata() {
                    if meta.is_dir() && !is_symlink {
                        let (size, count) = Self::calculate_folder_size(&path, cancel_flag);
                        let category = Self::categorize_folder(&name);
                        Some(StorageItem {
                            path,
                            name,
                            size_bytes: size,
                            is_dir: true,
                            child_count: count,
                            category,
                            is_selected: false,
                        })
                    } else {
                        let category = Self::categorize_file(&name);
                        Some(StorageItem {
                            path,
                            name,
                            size_bytes: meta.len(),
                            is_dir: false,
                            child_count: 0,
                            category,
                            is_selected: false,
                        })
                    }
                } else {
                    None
                }
            })
            .collect();

        // Sort descending by size
        items.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        items.truncate(max_results);
        items
    }

    /// Recursively calculates the byte size and file count of a folder.
    fn calculate_folder_size(dir: &Path, cancel_flag: &Arc<AtomicBool>) -> (u64, usize) {
        let mut total_bytes = 0;
        let mut file_count = 0;
        let mut stack = vec![dir.to_path_buf()];

        while let Some(current) = stack.pop() {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }

            let read = match fs::read_dir(&current) {
                Ok(r) => r,
                Err(_) => continue,
            };

            for entry in read.flatten() {
                if cancel_flag.load(Ordering::Relaxed) {
                    break;
                }

                let path = entry.path();
                let is_symlink = is_junction_or_symlink(&path).unwrap_or(false);

                if let Ok(meta) = entry.metadata() {
                    if meta.is_dir() && !is_symlink {
                        stack.push(path);
                    } else {
                        total_bytes += meta.len();
                        file_count += 1;
                    }
                }
            }
        }

        (total_bytes, file_count)
    }

    fn categorize_folder(name: &str) -> String {
        let lower = name.to_lowercase();
        if lower.contains("windows") || lower.contains("system") {
            "System".to_string()
        } else if lower.contains("node_modules")
            || lower.contains("cargo")
            || lower.contains(".git")
            || lower.contains("target")
        {
            "Developer".to_string()
        } else if lower.contains("appdata") || lower.contains("program") {
            "Applications".to_string()
        } else {
            "User Data".to_string()
        }
    }

    fn categorize_file(name: &str) -> String {
        let lower = name.to_lowercase();
        if lower.ends_with(".exe") || lower.ends_with(".msi") || lower.ends_with(".dll") {
            "Binary".to_string()
        } else if lower.ends_with(".zip") || lower.ends_with(".tar") || lower.ends_with(".7z") {
            "Archive".to_string()
        } else if lower.ends_with(".mp4") || lower.ends_with(".mkv") || lower.ends_with(".png") {
            "Media".to_string()
        } else {
            "Document".to_string()
        }
    }

    /// Scans user directories for large junk files (e.g. >50MB) with specific extensions.
    pub fn analyze_large_junk_files(cancel_flag: &Arc<AtomicBool>) -> Vec<StorageItem> {
        let mut target_dirs = Vec::new();
        if let Ok(home) = std::env::var("USERPROFILE") {
            let home_path = Path::new(&home);
            target_dirs.push(home_path.join("Downloads"));
            target_dirs.push(home_path.join("Documents"));
            target_dirs.push(home_path.join("Desktop"));
        }
        if let Ok(temp) = std::env::var("TEMP") {
            target_dirs.push(PathBuf::from(temp));
        }

        let junk_extensions = vec!["log", "tmp", "dmp", "old", "bak", "iso", "zip", "mp4", "cab"];
        let size_threshold = 50 * 1024 * 1024; // 50 MB

        let mut items = Vec::new();
        for dir in target_dirs {
            if !dir.exists() || !dir.is_dir() {
                continue;
            }
            let mut stack = vec![dir];

            while let Some(current) = stack.pop() {
                if cancel_flag.load(Ordering::Relaxed) {
                    break;
                }
                let read = match fs::read_dir(&current) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                for entry in read.flatten() {
                    if cancel_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let path = entry.path();
                    let is_symlink = is_junction_or_symlink(&path).unwrap_or(false);

                    if let Ok(meta) = entry.metadata() {
                        if meta.is_dir() && !is_symlink {
                            stack.push(path);
                        } else if !is_symlink {
                            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
                            let is_large = meta.len() > size_threshold;
                            
                            // Include if it matches junk extensions AND is large, or if it's REALLY large (> 250MB) regardless of extension
                            if (junk_extensions.contains(&ext.as_str()) && is_large) || meta.len() > 250 * 1024 * 1024 {
                                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("Unknown").to_string();
                                items.push(StorageItem {
                                    path,
                                    name: name.clone(),
                                    size_bytes: meta.len(),
                                    is_dir: false,
                                    child_count: 0,
                                    category: Self::categorize_file(&name),
                                    is_selected: false,
                                });
                            }
                        }
                    }
                }
            }
        }

        items.sort_by(|a, b| b.size_bytes.cmp(&a.size_bytes));
        items.truncate(100);
        items
    }

    /// Deletes the provided StorageItems and returns the total bytes reclaimed.
    pub fn delete_storage_items(items: &[StorageItem]) -> u64 {
        let mut reclaimed = 0;
        for item in items {
            if item.is_selected && item.path.exists() {
                if item.is_dir {
                    if fs::remove_dir_all(&item.path).is_ok() {
                        reclaimed += item.size_bytes;
                    }
                } else {
                    if fs::remove_file(&item.path).is_ok() {
                        reclaimed += item.size_bytes;
                    }
                }
            }
        }
        reclaimed
    }
}
