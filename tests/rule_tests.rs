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
            let res = resolve_env_vars(&target.path);
            assert!(
                res.is_ok(),
                "Target path '{}' in rule '{}' failed to resolve env vars: {:?}",
                target.path,
                rule.id,
                res.err()
            );
        }
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
