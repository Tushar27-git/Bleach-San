use std::env;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum EnvResolutionError {
    #[error("Unknown environment variable: {0}")]
    UnknownVariable(String),
    #[error("Unterminated environment variable syntax: {0}")]
    UnterminatedVariable(String),
}

/// Resolves environment variable markers `%VAR%` inside a path string to their absolute system values.
pub fn resolve_env_vars(raw: &str) -> Result<PathBuf, EnvResolutionError> {
    if raw.starts_with("SPECIAL:") {
        return Ok(PathBuf::from(raw));
    }

    let mut result = String::new();
    let mut chars = raw.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '%' {
            let mut var_name = String::new();
            let mut closed = false;
            for next_c in chars.by_ref() {
                if next_c == '%' {
                    closed = true;
                    break;
                }
                var_name.push(next_c);
            }

            if !closed {
                return Err(EnvResolutionError::UnterminatedVariable(raw.to_string()));
            }

            let resolved_val = match var_name.to_uppercase().as_str() {
                "LOCALAPPDATA" => env::var("LOCALAPPDATA")
                    .or_else(|_| env::var("USERPROFILE").map(|u| format!("{}\\AppData\\Local", u))),
                "APPDATA" => env::var("APPDATA")
                    .or_else(|_| env::var("USERPROFILE").map(|u| format!("{}\\AppData\\Roaming", u))),
                "TEMP" | "TMP" => env::var("TEMP").or_else(|_| env::var("TMP")),
                "USERPROFILE" => env::var("USERPROFILE"),
                "PROGRAMDATA" => env::var("PROGRAMDATA"),
                "SYSTEMROOT" | "WINDIR" => env::var("SYSTEMROOT").or_else(|_| env::var("WINDIR")),
                "PROGRAMFILES" => env::var("ProgramFiles"),
                "PROGRAMFILES(X86)" => env::var("ProgramFiles(x86)"),
                other => env::var(other),
            };

            match resolved_val {
                Ok(val) => result.push_str(&val),
                Err(_) => return Err(EnvResolutionError::UnknownVariable(var_name)),
            }
        } else {
            result.push(c);
        }
    }

    Ok(PathBuf::from(result))
}
