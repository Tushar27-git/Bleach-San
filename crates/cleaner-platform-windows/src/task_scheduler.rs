use std::io;
use std::path::Path;
use std::process::Command;

const DEFAULT_TASK_NAME: &str = "BleachSanAutoClean";

/// Registers a daily background cleanup task in Windows Task Scheduler.
pub fn register_daily_task(task_name: Option<&str>, exe_path: &Path, args: &str) -> io::Result<()> {
    let name = task_name.unwrap_or(DEFAULT_TASK_NAME);
    let path_str = exe_path.to_string_lossy();
    let tr_arg = if args.is_empty() {
        format!("\"{}\"", path_str)
    } else {
        format!("\"{}\" {}", path_str, args)
    };

    let status = Command::new("schtasks.exe")
        .args([
            "/Create",
            "/SC",
            "DAILY",
            "/TN",
            name,
            "/TR",
            &tr_arg,
            "/ST",
            "03:00",
            "/F",
        ])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("schtasks failed with code: {:?}", status.code()),
        ))
    }
}

/// Unregisters/deletes a background task from Windows Task Scheduler.
pub fn unregister_task(task_name: Option<&str>) -> io::Result<()> {
    let name = task_name.unwrap_or(DEFAULT_TASK_NAME);
    let status = Command::new("schtasks.exe")
        .args(["/Delete", "/TN", name, "/F"])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("schtasks delete failed with code: {:?}", status.code()),
        ))
    }
}

/// Checks if the background cleanup task is currently registered in Windows Task Scheduler.
pub fn is_task_registered(task_name: Option<&str>) -> bool {
    let name = task_name.unwrap_or(DEFAULT_TASK_NAME);
    let output = Command::new("schtasks.exe")
        .args(["/Query", "/TN", name])
        .output();

    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}
