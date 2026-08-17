use crate::rules::env_resolver::resolve_env_vars;
use crate::rules::schema::{DiscoveryStrategy, RuleTarget};
use glob::glob;
use std::fs;
use std::path::PathBuf;
use jwalk::WalkDir;

/// Resolves a RuleTarget into a list of absolute paths based on its discovery strategy.
pub fn resolve_target_paths(target: &RuleTarget, target_drive: Option<&str>) -> Vec<String> {
    let mut resolved_paths = Vec::new();
    
    if let Some(strategy) = &target.discovery {
        match strategy {
            DiscoveryStrategy::Config {
                file,
                format,
                key,
                fallback,
                append,
            } => {
                if let Ok(resolved_file) = resolve_env_vars(file) {
                    if let Ok(content) = fs::read_to_string(&resolved_file) {
                        if format == "key-value" || format == "prefs" {
                            for line in content.lines() {
                                let line = line.trim();
                                if line.starts_with(key) {
                                    if let Some((_, mut val)) = line.split_once('=') {
                                        val = val.trim().trim_matches('"');
                                        
                                        // Unescape quotes and slashes if any
                                        let unescaped = val.replace("\\\\", "\\").replace("\\\"", "\"");
                                        let mut base_path = PathBuf::from(unescaped);
                                        
                                        if let Some(append_path) = append {
                                            base_path.push(append_path);
                                        }
                                        
                                        
                                        let path_str = base_path.to_string_lossy().to_string();
                                        resolved_paths.push(path_str);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }

                // If config parsing fails, try fallback
                if resolved_paths.is_empty() {
                    if let Some(fb) = fallback {
                        resolved_paths.push(fb.clone());
                    }
                }
            }
            DiscoveryStrategy::Glob { pattern } => {
                if let Ok(resolved_pattern) = resolve_env_vars(pattern) {
                    if let Some(pattern_str) = resolved_pattern.to_str() {
                        if let Ok(entries) = glob(pattern_str) {
                            for entry in entries {
                                if let Ok(path) = entry {
                                    resolved_paths.push(path.to_string_lossy().to_string());
                                }
                            }
                        }
                    }
                }
            }
            DiscoveryStrategy::DeepSearch {
                base_paths,
                target_names,
                max_depth,
            } => {
                let limit = max_depth.unwrap_or(4); // default limit to prevent infinite scanning

                for base in base_paths {
                    if let Ok(resolved_base) = resolve_env_vars(base) {
                        for entry in WalkDir::new(&resolved_base)
                            .max_depth(limit)
                            .skip_hidden(false)
                            .follow_links(false)
                        {
                            if let Ok(dir_entry) = entry {
                                if dir_entry.file_type.is_dir() {
                                    let path = dir_entry.path();
                                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                                        if target_names.iter().any(|target| name.eq_ignore_ascii_case(target)) {
                                            resolved_paths.push(path.to_string_lossy().to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Default to the static path if no discovery or if discovery failed
    if resolved_paths.is_empty() {
        if let Some(path) = &target.path {
            resolved_paths.push(path.clone());
        }
    }
    
    // Apply drive substitution if requested
    if let Some(target_drv) = target_drive {
        let clean_drv = target_drv.trim_end_matches('\\'); // e.g., "D:"
        for path in &mut resolved_paths {
            if path.len() >= 3 && &path[1..3] == ":\\" {
                let current_drive = &path[0..1];
                let target_letter = &clean_drv[0..1];
                if !current_drive.eq_ignore_ascii_case(target_letter) {
                    let remainder = &path[2..];
                    *path = format!("{}{}", clean_drv, remainder);
                }
            }
        }
    }
    
    resolved_paths
}
