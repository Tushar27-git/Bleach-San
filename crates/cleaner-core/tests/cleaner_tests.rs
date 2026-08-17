use cleaner_core::cleaner::CleanupExecutor;
use cleaner_core::models::{CleanupPlan, SafetyLevel, TargetCandidate};
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
