use crate::models::SafetyLevel;
use crate::safety::blocklist::is_exact_protected_path;
use cleaner_platform_windows::filesystem::{is_junction_or_symlink, normalize_path};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SafetyError {
    #[error("Target path contains path traversal components (..)")]
    PathTraversalDetected,
    #[error("Target path is a protected Windows or user directory: {0}")]
    ProtectedPathViolation(String),
    #[error("Target path '{0}' escapes the allowed root '{1}'")]
    AllowedRootEscape(String, String),
    #[error("Target path is an unsafe reparse point (junction/symlink)")]
    UnsafeReparsePoint,
    #[error("Target path is empty or invalid")]
    InvalidPath,
}

/// Validates a target path against all safety invariants using Fail-Closed semantics.
pub fn validate_target_path(
    raw_path: &Path,
    allowed_root: Option<&Path>,
) -> Result<PathBuf, SafetyError> {
    // 1. Check for empty path
    if raw_path.as_os_str().is_empty() {
        return Err(SafetyError::InvalidPath);
    }

    // 2. Reject path traversal components (..)
    for comp in raw_path.components() {
        if let Component::ParentDir = comp {
            return Err(SafetyError::PathTraversalDetected);
        }
    }

    // 3. Normalize path (strip UNC \\?\)
    let normalized = normalize_path(raw_path);

    // 4. Reject exact protected roots (C:\, C:\Windows, C:\Program Files, etc.)
    if is_exact_protected_path(&normalized) {
        return Err(SafetyError::ProtectedPathViolation(
            normalized.to_string_lossy().to_string(),
        ));
    }

    // 5. Allowed root containment check
    if let Some(root) = allowed_root {
        let normalized_root = normalize_path(root);
        if !normalized.starts_with(&normalized_root) {
            return Err(SafetyError::AllowedRootEscape(
                normalized.to_string_lossy().to_string(),
                normalized_root.to_string_lossy().to_string(),
            ));
        }
    }

    // 6. Check if the path itself is an active reparse point pointing outside
    if normalized.exists() && is_junction_or_symlink(&normalized).unwrap_or(false) {
        return Err(SafetyError::UnsafeReparsePoint);
    }

    Ok(normalized)
}

/// Classifies a target's safety level based on path properties.
pub fn classify_path_safety(path: &Path, declared_level: SafetyLevel) -> SafetyLevel {
    if is_exact_protected_path(path) {
        return SafetyLevel::Protected;
    }

    // User libraries are always classified as USER_DATA
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let up = PathBuf::from(userprofile);
        let user_dirs = [
            up.join("Documents"),
            up.join("Desktop"),
            up.join("Downloads"),
            up.join("Pictures"),
            up.join("Videos"),
            up.join("Music"),
        ];

        for u_dir in &user_dirs {
            if path.starts_with(u_dir) {
                return SafetyLevel::UserData;
            }
        }
    }

    declared_level
}
