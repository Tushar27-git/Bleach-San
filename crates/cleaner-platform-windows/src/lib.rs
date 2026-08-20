pub mod elevation;
pub mod filesystem;
pub mod process;
pub mod recycle_bin;
pub mod restore_point;
pub mod task_scheduler;

pub use elevation::is_elevated;
pub use filesystem::{
    delete_dir_safely, delete_dir_safely_with_stats, delete_file_safely, is_junction_or_symlink,
    is_reparse_point, normalize_path, remove_readonly_flag,
};
pub use process::{get_running_processes, is_process_running};
pub use recycle_bin::{empty_recycle_bin, get_recycle_bin_info};
pub use restore_point::create_restore_point;
pub use task_scheduler::{is_task_registered, register_daily_task, unregister_task};
