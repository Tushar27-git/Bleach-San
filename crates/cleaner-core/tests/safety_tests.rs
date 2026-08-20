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
