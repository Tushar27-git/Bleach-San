use crate::rules::env_resolver::resolve_env_vars;
use crate::rules::schema::{DiscoveryStrategy, RuleTarget};
use glob::glob;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolves a RuleTarget into a list of absolute paths based on its discovery strategy.
pub fn resolve_target_paths(target: &RuleTarget) -> Vec<String> {
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
                                        
                                        return vec![base_path.to_string_lossy().to_string()];
                                    }
                                }
                            }
                        }
                    }
                }

                // If config parsing fails, try fallback
                if let Some(fb) = fallback {
                    return vec![fb.clone()];
                }
            }
            DiscoveryStrategy::Glob { pattern } => {
                if let Ok(resolved_pattern) = resolve_env_vars(pattern) {
                    let mut paths = Vec::new();
                    if let Some(pattern_str) = resolved_pattern.to_str() {
                        if let Ok(entries) = glob(pattern_str) {
                            for entry in entries {
                                if let Ok(path) = entry {
                                    paths.push(path.to_string_lossy().to_string());
                                }
                            }
                        }
                    }
                    if !paths.is_empty() {
                        return paths;
                    }
                }
            }
        }
    }

    // Default to the static path if no discovery or if discovery failed
    if let Some(path) = &target.path {
        vec![path.clone()]
    } else {
        vec![]
    }
}
