use cleaner_platform_windows::process::get_running_processes;
use std::collections::HashSet;

pub struct ProcessGuard;

impl ProcessGuard {
    /// Checks if any required process for a rule is currently running.
    /// Supports comma, pipe, or semicolon separated process names and automatically
    /// resolves known IDE/editor and browser ecosystem variants.
    /// Returns Some(active_process_name) if running, None if closed or not specified.
    pub fn check_blocking_process(required_closed: Option<&str>) -> Option<String> {
        let req = match required_closed {
            Some(r) if !r.trim().is_empty() => r,
            _ => return None,
        };

        let running_list = get_running_processes().unwrap_or_default();
        let running_set: HashSet<String> = running_list.into_iter().map(|p| p.to_lowercase()).collect();

        // Split multiple listed executables (e.g. "Code.exe, antigravity.exe" or "ms-teams.exe|Teams.exe")
        for token in req.split([',', '|', ';']) {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }

            let lower_token = trimmed.to_lowercase();
            let lower_exe = if lower_token.ends_with(".exe") {
                lower_token
            } else {
                format!("{}.exe", lower_token)
            };

            // Check direct process name
            if running_set.contains(&lower_exe) {
                return Some(trimmed.to_string());
            }

            // Check well-known family aliases
            let aliases = match lower_exe.as_str() {
                "code.exe" => vec![
                    "code.exe",
                    "antigravity.exe",
                    "cursor.exe",
                    "vscodium.exe",
                    "windsurf.exe",
                ],
                "discord.exe" => vec![
                    "discord.exe",
                    "discordcanary.exe",
                    "discordptb.exe",
                    "discorddevelopment.exe",
                ],
                "teams.exe" | "ms-teams.exe" => vec![
                    "teams.exe",
                    "ms-teams.exe",
                    "msteams.exe",
                ],
                _ => vec![],
            };

            for alias in aliases {
                if running_set.contains(alias) {
                    return Some(alias.to_string());
                }
            }
        }

        None
    }
}
