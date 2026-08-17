use crate::models::SafetyLevel;

pub fn is_actionable_automatically(level: SafetyLevel) -> bool {
    matches!(level, SafetyLevel::Safe)
}

pub fn requires_explicit_user_review(level: SafetyLevel) -> bool {
    matches!(level, SafetyLevel::Review)
}

pub fn is_forbidden_from_cleanup(level: SafetyLevel) -> bool {
    matches!(level, SafetyLevel::UserData | SafetyLevel::Protected)
}
