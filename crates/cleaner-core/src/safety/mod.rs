pub mod blocklist;
pub mod levels;
pub mod validator;

pub use blocklist::{get_protected_paths, is_exact_protected_path};
pub use levels::{
    is_actionable_automatically, is_forbidden_from_cleanup, requires_explicit_user_review,
};
pub use validator::{classify_path_safety, validate_target_path, SafetyError};
