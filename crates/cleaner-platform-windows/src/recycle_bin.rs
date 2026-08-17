use std::io;
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::{
    SHEmptyRecycleBinW, SHQueryRecycleBinW, SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI,
    SHERB_NOSOUND, SHQUERYRBINFO,
};

/// Queries the total size (in bytes) and item count of the Recycle Bin.
pub fn get_recycle_bin_info(root_path: Option<&str>) -> io::Result<(u64, u64)> {
    let wide_root: Option<Vec<u16>> = root_path.map(|r| {
        r.encode_utf16().chain(std::iter::once(0)).collect()
    });

    let mut info = SHQUERYRBINFO {
        cbSize: std::mem::size_of::<SHQUERYRBINFO>() as u32,
        ..Default::default()
    };

    unsafe {
        let pcwstr = match &wide_root {
            Some(w) => PCWSTR(w.as_ptr()),
            None => PCWSTR::null(),
        };

        if let Err(e) = SHQueryRecycleBinW(pcwstr, &mut info) {
            return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
        }
    }

    Ok((info.i64Size as u64, info.i64NumItems as u64))
}

/// Empties the Windows Recycle Bin silently without popup confirmation.
pub fn empty_recycle_bin(root_path: Option<&str>) -> io::Result<()> {
    let wide_root: Option<Vec<u16>> = root_path.map(|r| {
        r.encode_utf16().chain(std::iter::once(0)).collect()
    });

    unsafe {
        let pcwstr = match &wide_root {
            Some(w) => PCWSTR(w.as_ptr()),
            None => PCWSTR::null(),
        };

        // Flags: no confirmation, no progress UI, no sound
        let flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
        if let Err(e) = SHEmptyRecycleBinW(None, pcwstr, flags) {
            return Err(io::Error::new(io::ErrorKind::Other, e.to_string()));
        }
    }

    Ok(())
}
