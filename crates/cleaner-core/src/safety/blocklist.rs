use std::path::{Path, PathBuf};

/// Returns the set of absolute directories that are strictly protected from deletion.
pub fn get_protected_paths() -> Vec<PathBuf> {
    let mut protected = Vec::new();

    // Windows system paths
    if let Ok(sysroot) = std::env::var("SYSTEMROOT") {
        let p = PathBuf::from(sysroot);
        protected.push(p.clone());
        protected.push(p.join("System32"));
        protected.push(p.join("SysWOW64"));
        protected.push(p.join("WinSxS"));
        protected.push(p.join("Boot"));
    }

    // Program Files
    if let Ok(pf) = std::env::var("ProgramFiles") {
        protected.push(PathBuf::from(pf));
    }
    if let Ok(pfx86) = std::env::var("ProgramFiles(x86)") {
        protected.push(PathBuf::from(pfx86));
    }

    // User profile roots & user data libraries
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        let up = PathBuf::from(userprofile);
        protected.push(up.clone());
        protected.push(up.join("Desktop"));
        protected.push(up.join("Documents"));
        protected.push(up.join("Pictures"));
        protected.push(up.join("Music"));
        protected.push(up.join("Videos"));
        protected.push(up.join("Saved Games"));
        protected.push(up.join("Contacts"));
        protected.push(up.join("Links"));
        protected.push(up.join("Favorites"));
    }

    protected
}

/// Checks if a given path is an exact match for a protected root or a drive root (e.g. `C:\`).
pub fn is_exact_protected_path(path: &Path) -> bool {
    // Check drive root (e.g. C:\ or C:)
    let path_str = path.to_string_lossy();
    if path_str.len() <= 3 && path_str.ends_with(":\\") || path_str.ends_with(':') {
        return true;
    }

    let protected = get_protected_paths();
    for p in protected {
        if path == p {
            return true;
        }
    }
    false
}
