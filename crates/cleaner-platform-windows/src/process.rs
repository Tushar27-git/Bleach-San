use std::io;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};

/// Checks if an executable with the given process name (case-insensitive, e.g. "spotify.exe") is currently running.
pub fn is_process_running(process_name: &str) -> io::Result<bool> {
    let lower_target = process_name.to_lowercase();
    let processes = get_running_processes()?;
    Ok(processes.iter().any(|p| p.to_lowercase() == lower_target))
}

/// Enumerates all currently active processes on the system using a snapshot.
pub fn get_running_processes() -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        if snapshot.is_invalid() {
            return Err(io::Error::last_os_error());
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if Process32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                // Extract null-terminated process name
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                names.push(name);

                if Process32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }

        let _ = windows::Win32::Foundation::CloseHandle(snapshot);
    }
    Ok(names)
}
