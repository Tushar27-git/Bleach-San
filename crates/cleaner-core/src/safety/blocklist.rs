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
        protected.push(p.join("INF"));
        // Critical driver and kernel stores
        protected.push(p.join("System32").join("drivers"));
        protected.push(p.join("System32").join("DriverStore").join("FileRepository"));
        protected.push(p.join("System32").join("config"));
        protected.push(p.join("System32").join("catroot"));
        protected.push(p.join("System32").join("catroot2"));
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
        protected.push(up.join("Downloads"));
        protected.push(up.join("Saved Games"));
        protected.push(up.join("Contacts"));
        protected.push(up.join("Links"));
        protected.push(up.join("Favorites"));
        protected.push(up.join(".ssh"));
        protected.push(up.join(".gnupg"));
        protected.push(up.join(".aws"));
        protected.push(up.join(".azure"));
        protected.push(up.join(".kube"));
    }

    protected
}

/// Checks if a path is inside any forbidden system kernel, active driver repository, or security credential directory.
pub fn is_forbidden_from_cleanup(path: &Path) -> bool {
    let path_lower = path.to_string_lossy().to_lowercase();
    
    // Strict blocklist for active Windows drivers, core registry, system volume, security keys, and git repositories
    if path_lower.contains("system32\\drivers")
        || path_lower.contains("driverstore\\filerepository")
        || path_lower.contains("system32\\config")
        || path_lower.contains("system32\\catroot")
        || path_lower.contains("system32\\winevt\\logs")
        || path_lower.contains("winsxs")
        || path_lower.contains("system volume information")
        || path_lower.ends_with("\\.git")
        || path_lower.contains("\\.git\\")
        || path_lower.ends_with("\\.ssh")
        || path_lower.contains("\\.ssh\\")
        || path_lower.ends_with("\\.gnupg")
        || path_lower.contains("\\.gnupg\\")
        || path_lower.ends_with("\\.aws")
        || path_lower.contains("\\.aws\\")
        || path_lower.ends_with("\\.kube")
        || path_lower.contains("\\.kube\\")
    {
        return true;
    }

    false
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
