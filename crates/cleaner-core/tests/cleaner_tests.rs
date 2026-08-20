use cleaner_core::cleaner::CleanupExecutor;
use cleaner_core::models::{CleanupPlan, SafetyLevel, TargetCandidate};
use cleaner_core::rules::schema::RuleAction;
use std::fs::{self, File};
use std::io::Write;

#[test]
fn test_sandbox_clean_execution() {
    let temp_root = std::env::temp_dir().join("bleachsan_test_sandbox");
    let test_dir = temp_root.join("cache_data");
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&test_dir).expect("Failed to create test dir");

    // Create 3 dummy files
    let file1 = test_dir.join("temp1.dat");
    let file2 = test_dir.join("temp2.dat");
    let file3 = test_dir.join("temp3.log");

    let mut f1 = File::create(&file1).unwrap();
    f1.write_all(b"Hello World 1234567890").unwrap();

    let mut f2 = File::create(&file2).unwrap();
    f2.write_all(b"Test Content Data").unwrap();

    let mut f3 = File::create(&file3).unwrap();
    f3.write_all(b"Log Entry Line").unwrap();

    let size1 = fs::metadata(&file1).unwrap().len();
    let size2 = fs::metadata(&file2).unwrap().len();
    let size3 = fs::metadata(&file3).unwrap().len();
    let total_expected_bytes = size1 + size2 + size3;

    let candidate = TargetCandidate {
        path: test_dir.clone(),
        display_path: test_dir.to_string_lossy().to_string(),
        size_bytes: total_expected_bytes,
        file_count: 3,
        is_dir: true,
        safety: SafetyLevel::Safe,
        is_locked: false,
        is_selected: true,
        action: RuleAction::DeleteContents,
        pattern: None,
        exclude: Vec::new(),
    };

    let plan = CleanupPlan {
        rule_id: "test_sandbox".to_string(),
        rule_name: "Test Sandbox".to_string(),
        category: "test".to_string(),
        description: "Sandbox test rule".to_string(),
        candidates: vec![candidate],
        total_bytes: total_expected_bytes,
        total_files: 3,
        safety: SafetyLevel::Safe,
        is_selected: true,
        is_blocked_by_process: false,
        blocked_process_name: None,
        requires_admin: false,
        warnings: Vec::new(),
    };

    let result = CleanupExecutor::execute_plan(&plan);

    assert_eq!(result.files_deleted, 3);
    assert_eq!(result.reclaimed_bytes, total_expected_bytes);
    assert_eq!(result.files_skipped, 0);
    assert!(result.errors.is_empty());

    // Verify files were removed
    assert!(!file1.exists());
    assert!(!file2.exists());
    assert!(!file3.exists());

    // Root directory should still exist
    assert!(test_dir.exists());

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_delete_files_matching_preserves_subdirectories_and_other_files() {
    let temp_root = std::env::temp_dir().join("bleachsan_test_matching");
    let test_dir = temp_root.join("explorer_mock");
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&test_dir).expect("Failed to create test dir");

    // Create thumbnail cache files
    let thumb1 = test_dir.join("thumbcache_32.db");
    let thumb2 = test_dir.join("thumbcache_256.db");
    // Create non-matching icon and state files
    let icon1 = test_dir.join("iconcache_32.db");
    let state1 = test_dir.join("ExplorerStartupLog.etl");
    // Create subfolder
    let subfolder = test_dir.join("PinnedFoldersCache");
    fs::create_dir_all(&subfolder).unwrap();
    let subfile = subfolder.join("data.bin");

    File::create(&thumb1).unwrap().write_all(b"thumb32data").unwrap();
    File::create(&thumb2).unwrap().write_all(b"thumb256data").unwrap();
    File::create(&icon1).unwrap().write_all(b"icon32data").unwrap();
    File::create(&state1).unwrap().write_all(b"statelog").unwrap();
    File::create(&subfile).unwrap().write_all(b"pinned").unwrap();

    let thumb1_size = fs::metadata(&thumb1).unwrap().len();
    let thumb2_size = fs::metadata(&thumb2).unwrap().len();

    let candidate = TargetCandidate {
        path: test_dir.clone(),
        display_path: test_dir.to_string_lossy().to_string(),
        size_bytes: thumb1_size + thumb2_size,
        file_count: 2,
        is_dir: true,
        safety: SafetyLevel::Safe,
        is_locked: false,
        is_selected: true,
        action: RuleAction::DeleteFilesMatching,
        pattern: Some("thumbcache_*.db".to_string()),
        exclude: Vec::new(),
    };

    let plan = CleanupPlan {
        rule_id: "test_thumbnail".to_string(),
        rule_name: "Test Thumbnail Cache".to_string(),
        category: "test".to_string(),
        description: "Test pattern matching deletion".to_string(),
        candidates: vec![candidate],
        total_bytes: thumb1_size + thumb2_size,
        total_files: 2,
        safety: SafetyLevel::Safe,
        is_selected: true,
        is_blocked_by_process: false,
        blocked_process_name: None,
        requires_admin: false,
        warnings: Vec::new(),
    };

    let result = CleanupExecutor::execute_plan(&plan);

    assert_eq!(result.files_deleted, 2);
    assert_eq!(result.reclaimed_bytes, thumb1_size + thumb2_size);

    // Matching files should be deleted
    assert!(!thumb1.exists());
    assert!(!thumb2.exists());

    // Non-matching files and subfolders MUST be preserved
    assert!(icon1.exists(), "iconcache_*.db must NOT be deleted!");
    assert!(state1.exists(), "Explorer state must NOT be deleted!");
    assert!(subfolder.exists(), "Subfolders must NOT be deleted!");
    assert!(subfile.exists(), "Files inside subfolders must NOT be deleted!");

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_recent_items_safety_preserves_pinned_automatic_destinations() {
    let temp_root = std::env::temp_dir().join("bleachsan_test_recent");
    let recent_dir = temp_root.join("Recent");
    let auto_dest = recent_dir.join("AutomaticDestinations");
    let custom_dest = recent_dir.join("CustomDestinations");
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&auto_dest).expect("Failed to create auto dest dir");
    fs::create_dir_all(&custom_dest).expect("Failed to create custom dest dir");

    // Loose recent shortcut
    let lnk1 = recent_dir.join("MyDocument.docx.lnk");
    let lnk2 = recent_dir.join("ProjectCode.lnk");
    // Pinned quick access item
    let pinned_qa = auto_dest.join("f0156403e5093079.automaticDestinations-ms");
    let custom_qa = custom_dest.join("custom_app.customDestinations-ms");

    File::create(&lnk1).unwrap().write_all(b"lnk1").unwrap();
    File::create(&lnk2).unwrap().write_all(b"lnk2").unwrap();
    File::create(&pinned_qa).unwrap().write_all(b"pinned quick access folders data").unwrap();
    File::create(&custom_qa).unwrap().write_all(b"custom destinations data").unwrap();

    let lnk1_size = fs::metadata(&lnk1).unwrap().len();
    let lnk2_size = fs::metadata(&lnk2).unwrap().len();

    let candidate = TargetCandidate {
        path: recent_dir.clone(),
        display_path: recent_dir.to_string_lossy().to_string(),
        size_bytes: lnk1_size + lnk2_size,
        file_count: 2,
        is_dir: true,
        safety: SafetyLevel::Safe,
        is_locked: false,
        is_selected: true,
        action: RuleAction::DeleteFilesMatching,
        pattern: Some("*.lnk".to_string()),
        exclude: vec!["AutomaticDestinations".to_string(), "CustomDestinations".to_string()],
    };

    let plan = CleanupPlan {
        rule_id: "recent_items".to_string(),
        rule_name: "Recent Items".to_string(),
        category: "system".to_string(),
        description: "Recent files shortcuts".to_string(),
        candidates: vec![candidate],
        total_bytes: lnk1_size + lnk2_size,
        total_files: 2,
        safety: SafetyLevel::Safe,
        is_selected: true,
        is_blocked_by_process: false,
        blocked_process_name: None,
        requires_admin: false,
        warnings: Vec::new(),
    };

    let result = CleanupExecutor::execute_plan(&plan);

    assert_eq!(result.files_deleted, 2);
    assert!(!lnk1.exists());
    assert!(!lnk2.exists());

    // CRITICAL: Pinned folders and AutomaticDestinations must still exist and be intact!
    assert!(auto_dest.exists(), "AutomaticDestinations folder must be preserved!");
    assert!(pinned_qa.exists(), "f0156403e5093079.automaticDestinations-ms (Pinned Folders) must be preserved!");
    assert!(custom_dest.exists(), "CustomDestinations folder must be preserved!");
    assert!(custom_qa.exists(), "Custom destinations files must be preserved!");

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_apply_drive_to_path() {
    use cleaner_core::scanner::apply_drive_to_path;
    use std::path::Path;

    let p1 = Path::new(r"C:\SteamLibrary\steamapps\shadercache");
    let p_d = apply_drive_to_path(p1, "D:\\");
    assert_eq!(p_d.to_string_lossy(), r"D:\SteamLibrary\steamapps\shadercache");

    let p_e = apply_drive_to_path(p1, "E:");
    assert_eq!(p_e.to_string_lossy(), r"E:\SteamLibrary\steamapps\shadercache");

    // All Drives should leave path untouched
    let p_all = apply_drive_to_path(p1, "All Drives");
    assert_eq!(p_all.to_string_lossy(), r"C:\SteamLibrary\steamapps\shadercache");
}

#[test]
fn test_multi_drive_sandbox_clean_execution() {
    let temp_root = std::env::temp_dir().join("bleachsan_test_multidrive");
    let mock_drive_d = temp_root.join("drive_d");
    let steam_shader = mock_drive_d.join("SteamLibrary").join("steamapps").join("shadercache");
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&steam_shader).expect("Failed to create mock steam shader dir");

    let shader1 = steam_shader.join("dx11_cache.bin");
    let shader2 = steam_shader.join("vk_pipeline.bin");
    File::create(&shader1).unwrap().write_all(b"DirectX 11 compiled shaders data").unwrap();
    File::create(&shader2).unwrap().write_all(b"Vulkan precompiled pipeline cache").unwrap();

    let s1_size = fs::metadata(&shader1).unwrap().len();
    let s2_size = fs::metadata(&shader2).unwrap().len();

    let candidate = TargetCandidate {
        path: steam_shader.clone(),
        display_path: steam_shader.to_string_lossy().to_string(),
        size_bytes: s1_size + s2_size,
        file_count: 2,
        is_dir: true,
        safety: SafetyLevel::Safe,
        is_locked: false,
        is_selected: true,
        action: RuleAction::DeleteContents,
        pattern: None,
        exclude: Vec::new(),
    };

    let plan = CleanupPlan {
        rule_id: "steam".to_string(),
        rule_name: "Steam Web & Shader Cache".to_string(),
        category: "applications".to_string(),
        description: "Steam client embedded browser cache and shader cache".to_string(),
        candidates: vec![candidate],
        total_bytes: s1_size + s2_size,
        total_files: 2,
        safety: SafetyLevel::Safe,
        is_selected: true,
        is_blocked_by_process: false,
        blocked_process_name: None,
        requires_admin: false,
        warnings: Vec::new(),
    };

    let result = CleanupExecutor::execute_plan(&plan);

    assert_eq!(result.files_deleted, 2);
    assert_eq!(result.reclaimed_bytes, s1_size + s2_size);
    assert!(!shader1.exists());
    assert!(!shader2.exists());
    assert!(steam_shader.exists());

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_heuristic_discovery_engine_finds_caches() {
    use cleaner_core::scanner::HeuristicDiscoveryEngine;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    let temp_root = std::env::temp_dir().join("bleachsan_test_heuristic");
    let _ = fs::remove_dir_all(&temp_root);

    // 1. Mock Game Shader Cache & Game Logs (depth 6)
    let game_shader = temp_root.join("Games").join("Steam").join("steamapps").join("common").join("RPGGame").join("shadercache");
    fs::create_dir_all(&game_shader).unwrap();
    File::create(game_shader.join("shader.bin")).unwrap().write_all(b"shader bytes data").unwrap();

    let game_logs = temp_root.join("Games").join("Steam").join("steamapps").join("common").join("RPGGame").join("Saved").join("Logs");
    fs::create_dir_all(&game_logs).unwrap();
    File::create(game_logs.join("gameplay.log")).unwrap().write_all(b"gameplay log lines").unwrap();

    // 2. Mock DaVinci CacheClip
    let davinci_cache = temp_root.join("VideoProjects").join("DaVinciProject").join("CacheClip");
    fs::create_dir_all(&davinci_cache).unwrap();
    File::create(davinci_cache.join("render1.dvcc")).unwrap().write_all(b"davinci render data bytes").unwrap();

    // 3. Mock Rust target with Cargo.toml
    let rust_proj = temp_root.join("Workspace").join("RustApp");
    let rust_target = rust_proj.join("target");
    fs::create_dir_all(&rust_target).unwrap();
    File::create(rust_proj.join("Cargo.toml")).unwrap().write_all(b"[package]\nname=\"rustapp\"\n").unwrap();
    File::create(rust_target.join("output.exe")).unwrap().write_all(b"compiled bin data").unwrap();

    // 4. Mock Loose File Junk & Thumbs.db
    let junk_folder = temp_root.join("Downloads");
    fs::create_dir_all(&junk_folder).unwrap();
    File::create(junk_folder.join("Thumbs.db")).unwrap().write_all(b"thumbs database cache").unwrap();
    File::create(junk_folder.join("install_temp.tmp")).unwrap().write_all(b"temp install data").unwrap();

    let cancel = Arc::new(AtomicBool::new(false));
    let discovered = HeuristicDiscoveryEngine::discover_drive_caches(&temp_root.to_string_lossy(), &cancel);

    assert!(discovered.len() >= 4, "Expected at least 4 heuristic caches to be discovered, found {}", discovered.len());

    let has_shader = discovered.iter().any(|d| d.category == "GAMES" && d.rule_name.contains("Game Shader Cache"));
    let has_logs = discovered.iter().any(|d| d.category == "GAMES" && d.rule_name.contains("Game Logs"));
    let has_media = discovered.iter().any(|d| d.category == "MEDIA" && d.rule_name.contains("DaVinci Resolve"));
    let has_dev = discovered.iter().any(|d| d.category == "DEVELOPER" && d.rule_name.contains("Rust Build Target"));
    let has_junk = discovered.iter().any(|d| d.category == "SYSTEM" && d.rule_name.contains("Drive File Junk"));

    assert!(has_shader, "Game shader cache was not discovered");
    assert!(has_logs, "Game saved logs were not discovered");
    assert!(has_media, "DaVinci render cache was not discovered");
    assert!(has_dev, "Rust target build was not discovered");
    assert!(has_junk, "Drive loose junk and Thumbs.db was not discovered");

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_blocked_by_process_skips_plan_execution() {
    let temp_root = std::env::temp_dir().join("bleachsan_test_process_block");
    let test_dir = temp_root.join("discord_cache");
    let _ = fs::remove_dir_all(&temp_root);
    fs::create_dir_all(&test_dir).unwrap();

    let dummy_file = test_dir.join("cache.dat");
    File::create(&dummy_file).unwrap().write_all(b"Discord active cache data").unwrap();

    let candidate = TargetCandidate {
        path: test_dir.clone(),
        display_path: test_dir.to_string_lossy().to_string(),
        size_bytes: 25,
        file_count: 1,
        is_dir: true,
        safety: SafetyLevel::Safe,
        is_locked: false,
        is_selected: true,
        action: RuleAction::DeleteContents,
        pattern: None,
        exclude: Vec::new(),
    };

    let plan = CleanupPlan {
        rule_id: "discord".to_string(),
        rule_name: "Discord Cache".to_string(),
        category: "applications".to_string(),
        description: "Discord cache".to_string(),
        candidates: vec![candidate],
        total_bytes: 25,
        total_files: 1,
        safety: SafetyLevel::Safe,
        is_selected: false,
        is_blocked_by_process: true,
        blocked_process_name: Some("Discord.exe".to_string()),
        requires_admin: false,
        warnings: vec!["Application is currently running (Discord.exe).".to_string()],
    };

    let result = CleanupExecutor::execute_plan(&plan);

    assert_eq!(result.files_deleted, 0);
    assert_eq!(result.reclaimed_bytes, 0);
    assert!(result.errors.iter().any(|e| e.contains("Execution skipped: Required application")));
    assert!(dummy_file.exists(), "Dummy file should NOT be deleted if process is running");

    let _ = fs::remove_dir_all(&temp_root);
}

#[test]
fn test_active_session_artifact_protection() {
    use cleaner_core::cleaner::is_active_session_artifact;
    use std::path::Path;

    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\scoped_dir1234_5678")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\crashpad_handler.pipe")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\SingletonLock")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\SingletonSocket")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\etilqs_abc123")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\ipc.sock")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\app.lock")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Code\\GPUCache\\data_0")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Code\\GPUCache\\data_1")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Code\\GPUCache\\index")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Roaming\\Antigravity IDE\\code.lock")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\discord\\GPUCache\\gpu_metrics.bin")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\discord\\blob_storage")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\discord\\LOCK")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\discord\\CURRENT")));
    assert!(is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\discord\\MANIFEST-000001")));

    assert!(!is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\old_installer.log")));
    assert!(!is_active_session_artifact(Path::new("C:\\Users\\test\\AppData\\Local\\Temp\\update_cache.dat")));
}

#[test]
fn test_process_guard_normalization_and_aliases() {
    use cleaner_core::processes::ProcessGuard;

    // Check with dummy / empty process string
    assert_eq!(ProcessGuard::check_blocking_process(None), None);
    assert_eq!(ProcessGuard::check_blocking_process(Some("")), None);
    assert_eq!(ProcessGuard::check_blocking_process(Some("   ")), None);

    // If Antigravity IDE is currently running in this test environment, check that antigravity matches it
    let res = ProcessGuard::check_blocking_process(Some("Antigravity IDE.exe"));
    // If running on user's machine with Antigravity open, it returns Some(...)
    if cleaner_platform_windows::process::is_process_running("Antigravity IDE.exe").unwrap_or(false) {
        assert!(res.is_some());
        assert!(ProcessGuard::check_blocking_process(Some("antigravity.exe")).is_some());
        assert!(ProcessGuard::check_blocking_process(Some("Code.exe")).is_some());
    }
}


