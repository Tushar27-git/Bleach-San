use cleaner_core::rules::env_resolver::resolve_env_vars;
use cleaner_core::rules::loader::get_embedded_rules;

#[test]
fn test_embedded_rules_validity() {
    let rules = get_embedded_rules();
    assert!(!rules.is_empty(), "Embedded rules must not be empty");

    for rule in &rules {
        assert!(!rule.id.is_empty(), "Rule ID must not be empty");
        assert!(!rule.name.is_empty(), "Rule name must not be empty");
        assert!(!rule.targets.is_empty(), "Rule '{}' must have targets", rule.id);

        for target in &rule.targets {
            if let Some(path) = &target.path {
                let res = resolve_env_vars(path);
                assert!(
                    res.is_ok(),
                    "Target path '{}' in rule '{}' failed to resolve env vars: {:?}",
                    path,
                    rule.id,
                    res.err()
                );
            }
        }
    }

    // Verify all new advanced cleaning modules are loaded
    let required_ids = ["device_drivers", "windows_update", "firefox", "music_streaming", "browser_extensions", "telemetry_logs"];
    for id in &required_ids {
        assert!(rules.iter().any(|r| r.id == *id), "Required rule '{}' was not found in embedded rules", id);
    }
}

#[test]
fn test_env_resolution() {
    let raw = "%LOCALAPPDATA%\\TestFolder\\Cache";
    let res = resolve_env_vars(raw).expect("Failed to resolve LOCALAPPDATA");
    let res_str = res.to_string_lossy();
    assert!(!res_str.contains('%'), "Resolved path should contain no % symbols");
    assert!(res_str.contains("AppData") || res_str.contains("Local"));
}
