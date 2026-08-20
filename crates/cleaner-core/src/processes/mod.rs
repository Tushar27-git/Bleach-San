use cleaner_platform_windows::process::get_running_processes;
use std::collections::HashSet;

pub struct ProcessGuard;

impl ProcessGuard {
    /// Normalizes a process name by removing .exe, spaces, hyphens, and underscores for resilient comparison.
    fn normalize_proc_name(name: &str) -> String {
        name.to_lowercase()
            .trim_end_matches(".exe")
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect()
    }

    /// Checks if any required process for a rule is currently running.
    /// Supports comma, pipe, or semicolon separated process names and automatically
    /// resolves known IDE/editor, browser, launcher, and communication ecosystem variants.
    /// Returns Some(active_process_name) if running, None if closed or not specified.
    pub fn check_blocking_process(required_closed: Option<&str>) -> Option<String> {
        let req = match required_closed {
            Some(r) if !r.trim().is_empty() => r,
            _ => return None,
        };

        let running_list = get_running_processes().unwrap_or_default();
        if running_list.is_empty() {
            return None;
        }

        let running_exact: HashSet<String> = running_list.iter().map(|p| p.to_lowercase()).collect();
        let running_normalized: Vec<(String, String)> = running_list
            .iter()
            .map(|orig| (Self::normalize_proc_name(orig), orig.clone()))
            .collect();

        // Split multiple listed executables (e.g. "Code.exe, antigravity.exe" or "ms-teams.exe|Teams.exe")
        for token in req.split([',', '|', ';']) {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }

            let lower_token = trimmed.to_lowercase();
            let lower_exe = if lower_token.ends_with(".exe") {
                lower_token.clone()
            } else {
                format!("{}.exe", lower_token)
            };

            // 1. Direct exact case-insensitive match
            if running_exact.contains(&lower_exe) {
                return Some(trimmed.to_string());
            }

            let norm_token = Self::normalize_proc_name(trimmed);

            // 2. Direct normalized match (e.g. "Antigravity IDE" vs "antigravityide.exe")
            for (norm_running, orig_running) in &running_normalized {
                if *norm_running == norm_token {
                    return Some(orig_running.clone());
                }
            }

            // 3. Substring match for key IDE / application identifiers
            if norm_token == "antigravity" || norm_token == "antigravityide" {
                for (norm_running, orig_running) in &running_normalized {
                    if norm_running.contains("antigravity") {
                        return Some(orig_running.clone());
                    }
                }
            }

            // 4. Well-known ecosystem family aliases
            let aliases: Vec<&str> = match lower_exe.as_str() {
                "code.exe" | "vscode.exe" => vec![
                    "code.exe",
                    "code - insiders.exe",
                    "code-insiders.exe",
                    "antigravity ide.exe",
                    "antigravity.exe",
                    "antigravity-ide.exe",
                    "cursor.exe",
                    "vscodium.exe",
                    "codium.exe",
                    "windsurf.exe",
                ],
                "antigravity.exe" | "antigravity ide.exe" | "antigravity-ide.exe" => vec![
                    "antigravity ide.exe",
                    "antigravity.exe",
                    "antigravity-ide.exe",
                ],
                "discord.exe" => vec![
                    "discord.exe",
                    "discordcanary.exe",
                    "discordptb.exe",
                    "discorddevelopment.exe",
                    "discordsystemhelper.exe",
                ],
                "chrome.exe" => vec![
                    "chrome.exe",
                    "googlecrashhandler.exe",
                    "googlecrashhandler64.exe",
                ],
                "msedge.exe" | "microsoftedge.exe" => vec![
                    "msedge.exe",
                    "msedgewebview2.exe",
                    "microsoftedge.exe",
                    "microsoftedgecp.exe",
                ],
                "brave.exe" => vec![
                    "brave.exe",
                    "bravecrashhandler.exe",
                    "bravecrashhandler64.exe",
                ],
                "firefox.exe" => vec![
                    "firefox.exe",
                    "zen.exe",
                    "floorp.exe",
                    "waterfox.exe",
                ],
                "spotify.exe" => vec![
                    "spotify.exe",
                ],
                "steam.exe" => vec![
                    "steam.exe",
                    "steamwebhelper.exe",
                    "steamservice.exe",
                ],
                "epicgameslauncher.exe" => vec![
                    "epicgameslauncher.exe",
                    "epicwebhelper.exe",
                ],
                "teams.exe" | "ms-teams.exe" | "msteams.exe" => vec![
                    "teams.exe",
                    "ms-teams.exe",
                    "msteams.exe",
                    "ms-teamsupdate.exe",
                ],
                "whatsapp.exe" => vec![
                    "whatsapp.exe",
                    "whatsapp.root.exe",
                ],
                "zoom.exe" => vec![
                    "zoom.exe",
                    "airhost.exe",
                    "cptemp.exe",
                ],
                "applemusic.exe" | "itunes.exe" => vec![
                    "applemusic.exe",
                    "applemusicwin.exe",
                    "itunes.exe",
                ],
                "amazon music.exe" | "amazonmusic.exe" => vec![
                    "amazon music.exe",
                    "amazonmusic.exe",
                ],
                "photoshop.exe" | "adobe desktop service.exe" => vec![
                    "photoshop.exe",
                    "premiere pro.exe",
                    "afterfx.exe",
                    "illustrator.exe",
                    "adobe desktop service.exe",
                    "creative cloud.exe",
                    "ccxprocess.exe",
                    "coresync.exe",
                    "adobe cef helper.exe",
                ],
                "onedrive.exe" => vec![
                    "onedrive.exe",
                    "filesyncconfig.exe",
                ],
                "robloxplayerbeta.exe" => vec![
                    "robloxplayerbeta.exe",
                    "robloxstudiobeta.exe",
                    "robloxcrashtracker.exe",
                ],
                "nvidia app.exe" | "nvidia geforce experience.exe" => vec![
                    "nvidia app.exe",
                    "nvidia geforce experience.exe",
                    "nvcplui.exe",
                    "nvcontainer.exe",
                ],
                "figma.exe" => vec![
                    "figma.exe",
                    "figmaagent.exe",
                ],
                _ => vec![],
            };

            for alias in aliases {
                if running_exact.contains(alias) {
                    return Some(alias.to_string());
                }
                let norm_alias = Self::normalize_proc_name(alias);
                for (norm_running, orig_running) in &running_normalized {
                    if *norm_running == norm_alias {
                        return Some(orig_running.clone());
                    }
                }
            }
        }

        None
    }
}
