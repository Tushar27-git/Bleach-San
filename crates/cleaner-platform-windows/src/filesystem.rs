use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Storage::FileSystem::{
    GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
};

/// Normalizes a Windows path by stripping the UNC prefix `\\?\` if present.
pub fn normalize_path(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

/// Converts a Path to a null-terminated UTF-16 wide string vector.
fn to_wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

use std::os::windows::ffi::OsStrExt;

/// Checks if a file or directory is a Windows reparse point (junction, symlink, mount point).
pub fn is_reparse_point(path: &Path) -> io::Result<bool> {
    if !path.exists() && !path.is_symlink() {
        return Ok(false);
    }
    let wide = to_wide_path(path);
    unsafe {
        let attrs = GetFileAttributesW(PCWSTR(wide.as_ptr()));
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Err(io::Error::last_os_error());
        }
        Ok((attrs & FILE_ATTRIBUTE_REPARSE_POINT.0) != 0)
    }
}

/// Checks if a path is a junction or symlink.
pub fn is_junction_or_symlink(path: &Path) -> io::Result<bool> {
    if path.is_symlink() {
        return Ok(true);
    }
    is_reparse_point(path)
}

/// Removes the read-only attribute from a file or directory so it can be safely removed.
pub fn remove_readonly_flag(path: &Path) -> io::Result<()> {
    let wide = to_wide_path(path);
    unsafe {
        let attrs = GetFileAttributesW(PCWSTR(wide.as_ptr()));
        if attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_READONLY.0) != 0 {
            let new_attrs = attrs & !FILE_ATTRIBUTE_READONLY.0;
            let result = SetFileAttributesW(PCWSTR(wide.as_ptr()), windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(new_attrs));
            if let Err(e) = result {
                return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
            }
        }
    }
    Ok(())
}

/// Safely removes a file, clearing read-only attributes if needed.
/// If the file is locked or in use by an active process, it returns an error rather than forcing truncation.
pub fn delete_file_safely(path: &Path) -> io::Result<()> {
    if is_junction_or_symlink(path)? {
        // Remove symlink without following
        return fs::remove_file(path);
    }

    match fs::remove_file(path) {
        Ok(_) => Ok(()),
        Err(e) => {
            // Try removing read-only attribute and re-attempting deletion
            let _ = remove_readonly_flag(path);
            fs::remove_file(path).map_err(|_| e)
        }
    }
}

/// Safely removes an empty or populated directory with granular fallback for locked children.
pub fn delete_dir_safely(path: &Path) -> io::Result<()> {
    if is_junction_or_symlink(path)? {
        // If it's a junction/symlink directory, remove directory handle only, do not recurse into target!
        return fs::remove_dir(path);
    }

    // Try direct removal first
    if let Ok(()) = fs::remove_dir_all(path) {
        return Ok(());
    }

    // Clear read-only flags recursively if needed
    let _ = remove_readonly_flag(path);
    if let Ok(entries) = walkdir(path) {
        for entry in &entries {
            let _ = remove_readonly_flag(entry);
        }
    }

    if let Ok(()) = fs::remove_dir_all(path) {
        return Ok(());
    }

    // Granular fallback: delete all unlocked files and subdirectories individually
    delete_dir_contents_granular(path)?;
    let _ = fs::remove_dir(path);
    Ok(())
}

/// Recursively deletes all unlocked files and subdirectories within a folder.
fn delete_dir_contents_granular(dir: &Path) -> io::Result<()> {
    if let Ok(read_dir) = fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let p = entry.path();
            let _ = remove_readonly_flag(&p);
            if p.is_dir() && !is_junction_or_symlink(&p).unwrap_or(false) {
                let _ = delete_dir_contents_granular(&p);
                let _ = fs::remove_dir(&p);
            } else {
                let _ = fs::remove_file(&p);
            }
        }
    }
    Ok(())
}

/// Simple non-following directory contents collector for attribute reset.
fn walkdir(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut results = Vec::new();
    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            results.push(path.clone());
            if path.is_dir() && !is_junction_or_symlink(&path).unwrap_or(false) {
                if let Ok(mut sub) = walkdir(&path) {
                    results.append(&mut sub);
                }
            }
        }
    }
    Ok(results)
}
