use crate::rules::schema::CleanerRule;
use include_dir::{include_dir, Dir};
use std::fs;
use std::path::Path;
use thiserror::Error;

static RULES_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/../../rules");

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
    let mut rules = Vec::new();
    
    fn collect_rules(dir: &Dir, rules: &mut Vec<CleanerRule>) {
        for file in dir.files() {
            if file.path().extension().and_then(|e| e.to_str()) == Some("toml") {
                if let Some(content) = file.contents_utf8() {
                    let identifier = file.path().to_string_lossy().to_string();
                    match parse_rule_toml(content, &identifier) {
                        Ok(rule) => rules.push(rule),
                        Err(e) => tracing::error!("Failed to parse embedded rule '{}': {}", identifier, e),
                    }
                }
            }
        }
        for sub_dir in dir.dirs() {
            collect_rules(sub_dir, rules);
        }
    }

    collect_rules(&RULES_DIR, &mut rules);
    rules
}
