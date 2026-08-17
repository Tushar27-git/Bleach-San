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
