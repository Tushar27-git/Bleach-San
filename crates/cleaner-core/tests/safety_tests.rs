use cleaner_core::models::SafetyLevel;
use cleaner_core::safety::blocklist::is_exact_protected_path;
use cleaner_core::safety::validator::{classify_path_safety, validate_target_path, SafetyError};
use std::path::{Path, PathBuf};

#[test]
fn test_path_traversal_rejection() {
    let bad_path = Path::new("C:\\Users\\tusha\\AppData\\Local\\..\\..\\Windows\\System32");
    let res = validate_target_path(bad_path, None);
    assert_eq!(res.unwrap_err(), SafetyError::PathTraversalDetected);
}

#[test]
fn test_drive_root_protection() {
    let drive_root = Path::new("C:\\");
    assert!(is_exact_protected_path(drive_root));
    assert_eq!(
        classify_path_safety(drive_root, SafetyLevel::Safe),
        SafetyLevel::Protected
    );
}

#[test]
fn test_allowed_root_confinement() {
    let target = Path::new("C:\\Users\\tusha\\AppData\\Local\\OtherApp\\Cache");
    let allowed_root = Path::new("C:\\Users\\tusha\\AppData\\Local\\Spotify");

    let res = validate_target_path(target, Some(allowed_root));
    assert!(matches!(res, Err(SafetyError::AllowedRootEscape(_, _))));
}

#[test]
fn test_user_data_classification() {
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let docs = PathBuf::from(userprofile).join("Documents\\MySecret.docx");
        let level = classify_path_safety(&docs, SafetyLevel::Safe);
        assert_eq!(level, SafetyLevel::UserData);
    }
}

#[test]
fn test_active_driver_and_system32_protection() {
    // 1. Active Windows Driver binaries must be strictly rejected
    let active_driver = Path::new("C:\\Windows\\System32\\drivers\\etc");
    assert!(validate_target_path(active_driver, None).is_err());

    let driverstore_repo = Path::new("C:\\Windows\\System32\\DriverStore\\FileRepository\\nv_dispi.inf_amd64_1234");
    assert!(validate_target_path(driverstore_repo, None).is_err());

    // 2. System registry config hives must be strictly rejected
    let registry_hive = Path::new("C:\\Windows\\System32\\config\\SYSTEM");
    assert!(validate_target_path(registry_hive, None).is_err());

    // 3. WinSxS component store must be strictly rejected
    let winsxs_path = Path::new("C:\\Windows\\WinSxS\\amd64_microsoft-windows-kernel_123");
    assert!(validate_target_path(winsxs_path, None).is_err());
}

#[test]
fn test_cleanup_executor_aborts_active_driver_paths() {
    use cleaner_core::cleaner::CleanupExecutor;
    use cleaner_core::models::{CleanupPlan, TargetCandidate};
    use cleaner_core::rules::schema::RuleAction;

    let driver_candidate = TargetCandidate {
        path: PathBuf::from(r"C:\Windows\System32\drivers\pci.sys"),
        display_path: r"C:\Windows\System32\drivers\pci.sys".to_string(),
        size_bytes: 1024,
        file_count: 1,
        is_dir: false,
        safety: SafetyLevel::Safe,
        is_locked: false,
        is_selected: true,
        action: RuleAction::DeleteContents,
        pattern: None,
        exclude: Vec::new(),
    };

    let plan = CleanupPlan {
        rule_id: "test_evil_driver".to_string(),
        rule_name: "Test Evil Driver Rule".to_string(),
        category: "system".to_string(),
        description: "Must be blocked by executor".to_string(),
        candidates: vec![driver_candidate],
        total_bytes: 1024,
        total_files: 1,
        safety: SafetyLevel::Safe,
        is_selected: true,
        is_blocked_by_process: false,
        blocked_process_name: None,
        requires_admin: true,
        warnings: Vec::new(),
    };

    let res = CleanupExecutor::execute_plan(&plan);
    assert_eq!(res.files_deleted, 0, "No files should be deleted!");
    assert_eq!(res.files_skipped, 1, "Candidate must be skipped!");
    assert!(!res.errors.is_empty(), "Executor must record safety violation error");
    assert!(res.errors[0].contains("Critical Safety Violation"));
}

#[test]
fn test_security_credentials_and_git_protection() {
    use cleaner_core::safety::blocklist::is_forbidden_from_cleanup;
    
    assert!(is_forbidden_from_cleanup(Path::new("C:\\Users\\test\\.ssh\\id_rsa")));
    assert!(is_forbidden_from_cleanup(Path::new("C:\\Users\\test\\.gnupg\\pubring.kbx")));
    assert!(is_forbidden_from_cleanup(Path::new("C:\\Users\\test\\.aws\\credentials")));
    assert!(is_forbidden_from_cleanup(Path::new("C:\\Users\\test\\.kube\\config")));
    assert!(is_forbidden_from_cleanup(Path::new("D:\\Projects\\BleachSan\\.git\\HEAD")));
    assert!(is_forbidden_from_cleanup(Path::new("C:\\System Volume Information")));
}
