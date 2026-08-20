use crate::elevation::is_elevated;
use std::process::Command;

/// Creates a Windows System Restore Point for disaster recovery before clean operations.
pub fn create_restore_point(description: &str) -> Result<String, String> {
    if !is_elevated() {
        return Err("Creating a Windows System Restore Point requires Administrator privileges. Please click 'Elevate to Admin' first.".to_string());
    }

    let escaped_desc = description.replace('\'', "''");
    let script = format!(
        "try {{ \
            Enable-ComputerRestore -Drive 'C:\\' -ErrorAction SilentlyContinue; \
            Checkpoint-Computer -Description '{}' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop; \
            Write-Output 'SUCCESS' \
        }} catch {{ \
            $msg = $_.Exception.Message; \
            Write-Output \"ERROR: $msg\" \
        }}",
        escaped_desc
    );

    let output = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &script])
        .output()
        .map_err(|e| format!("Failed to invoke PowerShell: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if stdout.contains("SUCCESS") {
        Ok(format!("System Restore Point '{}' created successfully.", description))
    } else if stdout.starts_with("ERROR:") {
        Err(stdout.trim_start_matches("ERROR:").trim().to_string())
    } else if !stderr.is_empty() {
        Err(stderr)
    } else {
        // Check if Windows restricts frequency (Windows 10/11 default restricts 1 restore point per 24 hours unless registry key is configured)
        if stdout.contains("24") || stdout.contains("frequency") {
            Ok(format!("A recent System Restore Point already exists on this system within the last 24 hours."))
        } else {
            Err(format!("System Restore failed: {}", stdout))
        }
    }
}
