use cleaner_core::format_bytes;
use cleaner_core::models::{CleanupPlan, StorageItem};

// Slint generated types
slint::include_modules!();

pub fn plan_to_ui_item(plan: &CleanupPlan) -> UICleanerItem {
    UICleanerItem {
        id: plan.rule_id.clone().into(),
        name: plan.rule_name.clone().into(),
        category: plan.category.to_uppercase().into(),
        description: plan.description.clone().into(),
        size_formatted: format_bytes(plan.total_bytes).into(),
        file_count: plan.total_files as i32,
        safety_level: plan.safety.to_string().into(),
        is_selected: plan.is_selected,
        is_blocked: plan.is_blocked_by_process,
        blocked_process: plan
            .blocked_process_name
            .clone()
            .unwrap_or_default()
            .into(),
    }
}

pub fn storage_to_ui_item(item: &StorageItem) -> UIStorageItem {
    UIStorageItem {
        name: item.name.clone().into(),
        path_display: item.path.to_string_lossy().to_string().into(),
        size_formatted: format_bytes(item.size_bytes).into(),
        category: item.category.clone().into(),
        is_dir: item.is_dir,
    }
}

pub fn large_junk_to_ui_item(item: &StorageItem) -> UILargeFileItem {
    UILargeFileItem {
        id: item.path.to_string_lossy().to_string().into(),
        name: item.name.clone().into(),
        category: item.category.clone().into(),
        size_formatted: format_bytes(item.size_bytes).into(),
        is_selected: item.is_selected,
    }
}
