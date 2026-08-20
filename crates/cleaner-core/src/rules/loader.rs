use crate::rules::schema::CleanerRule;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuleLoadError {
    #[error("IO error while reading rule: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML syntax error in rule '{0}': {1}")]
    Toml(String, #[source] toml::de::Error),
}

/// Loads a single cleaner rule from a TOML string.
pub fn parse_rule_toml(toml_str: &str, identifier: &str) -> Result<CleanerRule, RuleLoadError> {
    toml::from_str::<CleanerRule>(toml_str)
        .map_err(|e| RuleLoadError::Toml(identifier.to_string(), e))
}

/// Loads a cleaner rule from a TOML file path.
pub fn load_rule_from_file(path: &Path) -> Result<CleanerRule, RuleLoadError> {
    let content = fs::read_to_string(path)?;
    let identifier = path.to_string_lossy().to_string();
    parse_rule_toml(&content, &identifier)
}

/// Recursively scans a directory for `.toml` files and parses all cleaner rules.
pub fn load_rules_from_dir(dir: &Path) -> Result<Vec<CleanerRule>, RuleLoadError> {
    let mut rules = Vec::new();
    if !dir.exists() || !dir.is_dir() {
        return Ok(rules);
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let mut sub_rules = load_rules_from_dir(&path)?;
            rules.append(&mut sub_rules);
        } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            match load_rule_from_file(&path) {
                Ok(rule) => rules.push(rule),
                Err(e) => tracing::warn!("Failed to load rule at {:?}: {}", path, e),
            }
        }
    }

    Ok(rules)
}

/// Returns the embedded default rules compiled into the binary.
pub fn get_embedded_rules() -> Vec<CleanerRule> {
    let raw_rules = [
        ("user_temp", include_str!("../../../../rules/system/user_temp.toml")),
        ("windows_temp", include_str!("../../../../rules/system/windows_temp.toml")),
        ("thumbnail_cache", include_str!("../../../../rules/system/thumbnail_cache.toml")),
        ("crash_dumps", include_str!("../../../../rules/system/crash_dumps.toml")),
        ("recycle_bin", include_str!("../../../../rules/system/recycle_bin.toml")),
        ("directx_shader", include_str!("../../../../rules/system/directx_shader.toml")),
        ("wer", include_str!("../../../../rules/system/wer.toml")),
        ("delivery_optimization", include_str!("../../../../rules/system/delivery_optimization.toml")),
        ("spotify", include_str!("../../../../rules/applications/spotify.toml")),
        ("discord", include_str!("../../../../rules/applications/discord.toml")),
        ("vscode", include_str!("../../../../rules/applications/vscode.toml")),
        ("chrome", include_str!("../../../../rules/applications/chrome.toml")),
        ("edge", include_str!("../../../../rules/applications/edge.toml")),
        ("steam", include_str!("../../../../rules/applications/steam.toml")),
        ("brave", include_str!("../../../../rules/applications/brave.toml")),
        ("whatsapp", include_str!("../../../../rules/applications/whatsapp.toml")),
        ("npm_cache", include_str!("../../../../rules/developer/npm_cache.toml")),
        ("pip_cache", include_str!("../../../../rules/developer/pip_cache.toml")),
        ("cargo_cache", include_str!("../../../../rules/developer/cargo_cache.toml")),
        ("gradle_cache", include_str!("../../../../rules/developer/gradle_cache.toml")),
        ("slack_cache", include_str!("../../../../rules/applications/slack.toml")),
        ("teams_cache", include_str!("../../../../rules/applications/teams.toml")),
        ("adobe_cache", include_str!("../../../../rules/applications/adobe.toml")),
        ("epic_games", include_str!("../../../../rules/applications/epic_games.toml")),
        ("windows_logs", include_str!("../../../../rules/system/windows_logs.toml")),
        ("windows_old", include_str!("../../../../rules/system/windows_old.toml")),
        ("nvidia", include_str!("../../../../rules/applications/nvidia.toml")),
        ("roblox", include_str!("../../../../rules/applications/roblox.toml")),
        ("onedrive", include_str!("../../../../rules/applications/onedrive.toml")),
        ("zoom", include_str!("../../../../rules/applications/zoom.toml")),
        ("widgets", include_str!("../../../../rules/system/widgets.toml")),
        ("defender_cache", include_str!("../../../../rules/system/defender_cache.toml")),
        ("inet_cache", include_str!("../../../../rules/system/inet_cache.toml")),
        ("recent_items", include_str!("../../../../rules/system/recent_items.toml")),
        ("file_junk", include_str!("../../../../rules/system/file_junk.toml")),
        ("windows_update", include_str!("../../../../rules/system/windows_update.toml")),
        ("drive_junk", include_str!("../../../../rules/system/drive_junk.toml")),
        ("rust_target", include_str!("../../../../rules/developer/rust_target.toml")),
        ("node_build_cache", include_str!("../../../../rules/developer/node_build_cache.toml")),
        ("python_cache", include_str!("../../../../rules/developer/python_cache.toml")),
        ("visual_studio_cache", include_str!("../../../../rules/developer/visual_studio_cache.toml")),
        ("game_shader_cache", include_str!("../../../../rules/applications/game_shader_cache.toml")),
        ("device_drivers", include_str!("../../../../rules/system/device_drivers.toml")),
        ("firefox", include_str!("../../../../rules/applications/firefox.toml")),
        ("music_streaming", include_str!("../../../../rules/applications/music_streaming.toml")),
        ("browser_extensions", include_str!("../../../../rules/applications/browser_extensions.toml")),
        ("telemetry_logs", include_str!("../../../../rules/system/telemetry_logs.toml")),
        ("nuget_cache", include_str!("../../../../rules/developer/nuget_cache.toml")),
    ];

    let mut rules = Vec::new();
    for (id, content) in raw_rules {
        if let Ok(rule) = parse_rule_toml(content, id) {
            rules.push(rule);
        }
    }
    rules
}
