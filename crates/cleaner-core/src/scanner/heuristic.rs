use crate::models::{CleanupPlan, SafetyLevel, TargetCandidate};
use crate::rules::schema::RuleAction;
use crate::safety::blocklist::is_exact_protected_path;
use crate::safety::validator::validate_target_path;
use crate::scanner::stream::scan_directory_bounded;
use jwalk::WalkDir;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct HeuristicDiscoveryEngine;

#[derive(Debug, Clone)]
pub struct DiscoveredCache {
    pub path: PathBuf,
    pub name: String,
    pub category: String,
    pub description: String,
    pub safety: SafetyLevel,
    pub action: RuleAction,
}

impl HeuristicDiscoveryEngine {
    /// Scans a given drive (or path) and discovers active caches, scratch disks, build artifacts, and junk.
    pub fn discover_drive_caches(
        drive_str: &str,
        cancel_flag: &Arc<AtomicBool>,
    ) -> Vec<CleanupPlan> {
        let drives_to_scan: Vec<String> = if drive_str.eq_ignore_ascii_case("All Drives") {
            crate::scanner::worker::get_system_drives()
        } else {
            vec![drive_str.to_string()]
        };

        let mut discovered_plans = Vec::new();
        let mut seen_paths = std::collections::HashSet::new();

        for drv in &drives_to_scan {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }

            let root_path = PathBuf::from(drv);
            if !root_path.exists() {
                continue;
            }

            let (discovered_items, loose_junk_files) = Self::crawl_drive_for_caches(&root_path, cancel_flag);

            // 1. Process individual discovered cache directories
            for item in discovered_items {
                if cancel_flag.load(Ordering::Relaxed) {
                    break;
                }

                let path_str = item.path.to_string_lossy().to_string();
                if seen_paths.contains(&path_str) {
                    continue;
                }
                seen_paths.insert(path_str.clone());

                let validated_path = match validate_target_path(&item.path, None) {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::debug!("Heuristic discovery skipped protected '{:?}': {}", item.path, e);
                        continue;
                    }
                };

                if !validated_path.exists() {
                    continue;
                }

                let stats = scan_directory_bounded(&validated_path, None, &[], cancel_flag, 50);
                if stats.total_bytes == 0 && stats.file_count == 0 {
                    continue;
                }

                let candidate = TargetCandidate {
                    path: validated_path.clone(),
                    display_path: validated_path.to_string_lossy().to_string(),
                    size_bytes: stats.total_bytes,
                    file_count: stats.file_count,
                    is_dir: validated_path.is_dir(),
                    safety: item.safety,
                    is_locked: false,
                    is_selected: item.safety == SafetyLevel::Safe,
                    action: item.action,
                    pattern: None,
                    exclude: Vec::new(),
                };

                let rule_id = format!(
                    "heuristic_{}_{}",
                    item.category.to_lowercase(),
                    Self::generate_short_hash(&path_str)
                );

                discovered_plans.push(CleanupPlan {
                    rule_id,
                    rule_name: item.name,
                    category: item.category,
                    description: item.description,
                    candidates: vec![candidate],
                    total_bytes: stats.total_bytes,
                    total_files: stats.file_count,
                    safety: item.safety,
                    is_selected: item.safety == SafetyLevel::Safe && stats.total_bytes > 0,
                    is_blocked_by_process: false,
                    blocked_process_name: None,
                    requires_admin: false,
                    warnings: Vec::new(),
                });
            }

            // 2. Aggregate loose junk files (e.g. *.tmp, *.dmp, *.log, Thumbs.db) into consolidated drive junk plans
            if !loose_junk_files.is_empty() {
                let total_junk_bytes: u64 = loose_junk_files.iter().map(|(_, sz)| *sz).sum();
                let total_junk_count = loose_junk_files.len();

                if total_junk_bytes > 0 {
                    let mut candidates = Vec::new();
                    for (fpath, fsize) in &loose_junk_files {
                        candidates.push(TargetCandidate {
                            path: fpath.clone(),
                            display_path: fpath.to_string_lossy().to_string(),
                            size_bytes: *fsize,
                            file_count: 1,
                            is_dir: false,
                            safety: SafetyLevel::Safe,
                            is_locked: false,
                            is_selected: true,
                            action: RuleAction::DeleteContents,
                            pattern: None,
                            exclude: Vec::new(),
                        });
                    }

                    discovered_plans.push(CleanupPlan {
                        rule_id: format!("heuristic_junk_{}", drv.trim_end_matches('\\').to_lowercase()),
                        rule_name: format!("Drive File Junk & Thumbs ({})", drv.trim_end_matches('\\')),
                        category: "SYSTEM".to_string(),
                        description: format!("Discovered loose .tmp, .log, .dmp, and Thumbs.db files on {}", drv),
                        candidates,
                        total_bytes: total_junk_bytes,
                        total_files: total_junk_count,
                        safety: SafetyLevel::Safe,
                        is_selected: true,
                        is_blocked_by_process: false,
                        blocked_process_name: None,
                        requires_admin: false,
                        warnings: Vec::new(),
                    });
                }
            }
        }

        discovered_plans
    }

    /// Crawls the drive up to depth 7 looking for cache directories and loose junk files.
    fn crawl_drive_for_caches(
        root_path: &Path,
        cancel_flag: &Arc<AtomicBool>,
    ) -> (Vec<DiscoveredCache>, Vec<(PathBuf, u64)>) {
        let mut items = Vec::new();
        let mut loose_junk = Vec::new();

        for entry in WalkDir::new(root_path)
            .max_depth(7)
            .skip_hidden(false)
            .follow_links(false)
            .parallelism(jwalk::Parallelism::RayonNewPool(2))
            .process_read_dir(|_, _, _, children| {
                for dir_entry_result in children.iter_mut() {
                    if let Ok(dir_entry) = dir_entry_result {
                        let p = dir_entry.path();
                        // Skip symlinks and junctions to avoid infinite loops
                        if cleaner_platform_windows::filesystem::is_junction_or_symlink(&p).unwrap_or(false) {
                            dir_entry.read_children_path = None;
                            continue;
                        }
                        // Skip protected system root folders from descending
                        if is_exact_protected_path(&p) {
                            dir_entry.read_children_path = None;
                            continue;
                        }
                        let name_lower = dir_entry
                            .file_name
                            .to_string_lossy()
                            .to_lowercase();
                        // Skip system core directories
                        if name_lower == "system volume information"
                            || name_lower == "$recycle.bin"
                            || name_lower == "windows"
                            || name_lower == "winsxs"
                            || name_lower == "system32"
                            || name_lower == "syswow64"
                            || name_lower == "recovery"
                        {
                            dir_entry.read_children_path = None;
                        }
                    }
                }
            })
        {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }

            let dir_entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = dir_entry.path();

            // 1. Directory Checks
            if dir_entry.file_type.is_dir() {
                if let Some(folder_name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(matched) = Self::classify_folder_signature(&path, folder_name) {
                        items.push(matched);
                    }
                }
            } else {
                // 2. File Checks: detect loose junk files (*.tmp, *.dmp, *.log, *.bak, *.old, Thumbs.db) with zero-copy checks
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    // Early skip for large non-cache binaries and video files to reduce I/O overhead
                    if file_name.ends_with(".mp4")
                        || file_name.ends_with(".mkv")
                        || file_name.ends_with(".iso")
                        || file_name.ends_with(".zip")
                        || file_name.ends_with(".vmdk")
                        || file_name.ends_with(".exe")
                        || file_name.ends_with(".dll")
                        || file_name.ends_with(".7z")
                    {
                        continue;
                    }

                    let is_junk = file_name.eq_ignore_ascii_case("thumbs.db")
                        || file_name.eq_ignore_ascii_case("dxgi.log")
                        || file_name.ends_with(".tmp")
                        || file_name.ends_with(".dmp")
                        || file_name.ends_with(".log")
                        || file_name.ends_with(".bak")
                        || file_name.ends_with(".old")
                        || file_name.ends_with(".chk")
                        || file_name.ends_with(".crdownload")
                        || file_name.ends_with(".blend1")
                        || file_name.ends_with(".blend2")
                        || file_name.ends_with(".sfk")
                        || file_name.ends_with(".sfl");

                    if is_junk {
                        if let Ok(meta) = dir_entry.metadata() {
                            loose_junk.push((path, meta.len()));
                        }
                    }
                }
            }
        }

        (items, loose_junk)
    }

    /// Classifies a folder by its signature into a DiscoveredCache item with zero-copy comparisons.
    fn classify_folder_signature(
        path: &Path,
        original_name: &str,
    ) -> Option<DiscoveredCache> {
        let path_str = path.to_string_lossy();

        // 1. Game Shaders, Logs, Crashes & Engine Caches
        if original_name.eq_ignore_ascii_case("shadercache")
            || original_name.eq_ignore_ascii_case("dxcache")
            || original_name.eq_ignore_ascii_case("glcache")
            || original_name.eq_ignore_ascii_case("d3dscache")
            || original_name.eq_ignore_ascii_case("vulkan_cache")
            || original_name.eq_ignore_ascii_case("dx11_cache")
            || original_name.eq_ignore_ascii_case("dx12_cache")
        {
            let parent_desc = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Game");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Game Shader Cache ({})", parent_desc),
                category: "GAMES".to_string(),
                description: format!("Precompiled graphics shaders in {}", path_str),
                safety: SafetyLevel::Review,
                action: RuleAction::DeleteContents,
            });
        }

        // Unreal Engine Game Saved / Logs / Crashes / DerivedDataCache
        if original_name.eq_ignore_ascii_case("deriveddatacache") {
            let parent_desc = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Game");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Unreal Engine Derived Data ({})", parent_desc),
                category: "GAMES".to_string(),
                description: format!("Unreal Engine asset derivation cache in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        // Game Saved Logs & Crashes (e.g. Fortnite/Valorant/Hogwarts/Unreal games)
        let path_lower = path_str.to_lowercase();
        if (original_name.eq_ignore_ascii_case("logs")
            || original_name.eq_ignore_ascii_case("crashes")
            || original_name.eq_ignore_ascii_case("crashreports")
            || original_name.eq_ignore_ascii_case("crashdumps"))
            && (path_lower.contains("saved") || path_lower.contains("games") || path_lower.contains("steam") || path_lower.contains("riot") || path_lower.contains("epic"))
        {
            let game_desc = path.parent().and_then(|p| p.parent()).and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Game");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Game Logs & Crashes ({})", game_desc),
                category: "GAMES".to_string(),
                description: format!("Gameplay diagnostics and crash logs in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        // Unity Game & Project Caches (webCaches, ShaderCache, ArtifactDB)
        if original_name.eq_ignore_ascii_case("webcaches") || original_name.eq_ignore_ascii_case("webcache2") || (original_name.eq_ignore_ascii_case("webcache") && path_lower.contains("game")) {
            let game_desc = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Game");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Game Embedded Web Cache ({})", game_desc),
                category: "GAMES".to_string(),
                description: format!("In-game embedded browser and event cache in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        if (original_name.eq_ignore_ascii_case("shadercache") || original_name.eq_ignore_ascii_case("artifactdb") || original_name.eq_ignore_ascii_case("packagecache")) && path_lower.contains("library") {
            let proj_desc = path.parent().and_then(|p| p.parent()).and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Unity Project");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Unity Project Cache ({})", proj_desc),
                category: "DEVELOPER".to_string(),
                description: format!("Unity compiler and artifact database in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        // Launcher Download and Temp Chunks
        if original_name.eq_ignore_ascii_case("downloading") || original_name.eq_ignore_ascii_case("vaultcache") || (original_name.eq_ignore_ascii_case("temp") && path_lower.contains("steamapps")) {
            let parent_desc = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Game Launcher");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Game Download & Vault Chunks ({})", parent_desc),
                category: "GAMES".to_string(),
                description: format!("Temporary installer and download depot chunks in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        // 2. Media, Video & Creative Content Creation Scratch Disks
        if original_name.eq_ignore_ascii_case("cacheclip") || path_lower.contains("cacheclip") || original_name.eq_ignore_ascii_case("optimizedmedia") || original_name.eq_ignore_ascii_case("proxymedia") {
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: "DaVinci Resolve Render Cache".to_string(),
                category: "MEDIA".to_string(),
                description: format!("Optimized media, proxies, and render cache in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        if original_name.eq_ignore_ascii_case("media cache files") || original_name.eq_ignore_ascii_case("media cache") || original_name.eq_ignore_ascii_case("peak files") {
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: "Adobe Media Cache & Waveform Peak Files".to_string(),
                category: "MEDIA".to_string(),
                description: format!("Adobe Premiere Pro / After Effects media cache in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        if original_name.starts_with("blend_cache") || original_name.eq_ignore_ascii_case("render_cache") {
            let parent_desc = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("3D Project");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Blender & 3D Render Cache ({})", parent_desc),
                category: "MEDIA".to_string(),
                description: format!("Baked physics, simulations, and frame renders in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        // 3. Developer & Compiler Build Caches
        if original_name.eq_ignore_ascii_case("target") {
            // Check if parent contains Cargo.toml or contains debug/release subfolders
            let is_rust = path.join("debug").exists()
                || path.join("release").exists()
                || path.join("CACHEDIR.TAG").exists()
                || path.parent().map(|p| p.join("Cargo.toml").exists()).unwrap_or(false);

            if is_rust {
                let proj_name = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Rust Project");
                return Some(DiscoveredCache {
                    path: path.to_path_buf(),
                    name: format!("Rust Build Target ({})", proj_name),
                    category: "DEVELOPER".to_string(),
                    description: format!("Compiled compiler binaries and incremental artifacts in {}", path_str),
                    safety: SafetyLevel::Safe,
                    action: RuleAction::DeleteContents,
                });
            }
        }

        if original_name.eq_ignore_ascii_case(".cache") || original_name.eq_ignore_ascii_case(".turbo") || original_name.eq_ignore_ascii_case(".parcel-cache") || original_name.eq_ignore_ascii_case(".next") {
            let parent_desc = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Web Project");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Web & Node Build Cache ({})", parent_desc),
                category: "DEVELOPER".to_string(),
                description: format!("Webpack, Vite, Next.js, and Turbo build caches in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        if original_name.eq_ignore_ascii_case("__pycache__") || original_name.eq_ignore_ascii_case(".pytest_cache") || original_name.eq_ignore_ascii_case(".mypy_cache") || original_name.eq_ignore_ascii_case(".ruff_cache") {
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: "Python Bytecode & Test Cache".to_string(),
                category: "DEVELOPER".to_string(),
                description: format!("Compiled Python bytecode and test cache in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        if original_name.eq_ignore_ascii_case(".vs") || original_name.eq_ignore_ascii_case("cmakefiles") || original_name.eq_ignore_ascii_case("intermediates") {
            let parent_desc = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("Workspace");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("IDE & Compiler Intermediate Cache ({})", parent_desc),
                category: "DEVELOPER".to_string(),
                description: format!("Visual Studio browsing database and CMake build files in {}", path_str),
                safety: SafetyLevel::Safe,
                action: RuleAction::DeleteContents,
            });
        }

        // 4. Web & Embedded Application Caches (Review safety to prevent terminating active apps)
        if original_name.eq_ignore_ascii_case("gpucache") || original_name.eq_ignore_ascii_case("code cache") || original_name.eq_ignore_ascii_case("webcache") || original_name.eq_ignore_ascii_case("cache_data") {
            let app_desc = path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("App");
            return Some(DiscoveredCache {
                path: path.to_path_buf(),
                name: format!("Application Web Cache ({})", app_desc),
                category: "APPLICATIONS".to_string(),
                description: format!("Embedded CEF/Chromium web cache in {}", path_str),
                safety: SafetyLevel::Review,
                action: RuleAction::DeleteContents,
            });
        }

        // 5. Drive Root Temporary Folders
        if original_name.eq_ignore_ascii_case("temp") || original_name.eq_ignore_ascii_case("tmp") || original_name.eq_ignore_ascii_case("temporary") {
            if path.components().count() <= 3 {
                return Some(DiscoveredCache {
                    path: path.to_path_buf(),
                    name: format!("Drive Root Temp ({})", original_name),
                    category: "SYSTEM".to_string(),
                    description: format!("Temporary scratch directory on drive in {}", path_str),
                    safety: SafetyLevel::Safe,
                    action: RuleAction::DeleteContents,
                });
            }
        }

        None
    }

    /// Generates a short 6-char hex hash from a path string for deterministic IDs.
    fn generate_short_hash(input: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        format!("{:06x}", hasher.finish() & 0xFFFFFF)
    }
}
