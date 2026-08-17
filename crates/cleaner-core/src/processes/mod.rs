use cleaner_platform_windows::process::is_process_running;

pub struct ProcessGuard;

impl ProcessGuard {
    /// Checks if a required process for a rule is running.
    /// Returns Some(process_name) if running, None if closed or not specified.
    pub fn check_blocking_process(required_closed: Option<&str>) -> Option<String> {
        if let Some(proc_name) = required_closed {
            if is_process_running(proc_name).unwrap_or(false) {
                return Some(proc_name.to_string());
            }
        }
        None
    }
}
