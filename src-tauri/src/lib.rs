use std::fs::File;
use std::io::{Read, Result as IoResult};
use std::path::Path;
use std::time::Instant;
use tauri::{AppHandle, Emitter};
use ombracrux_core::split::split_file;
use ombracrux_core::restore::restore_file;

#[derive(Clone, serde::Serialize)]
struct ProgressPayload {
    percent: f64,
    eta_seconds: f64,
}

/// Wraps a standard file reader to calculate speed, ETA, and emit progress to the UI
struct ProgressReader<'a, R: Read> {
    inner: R,
    app: &'a AppHandle,
    total_bytes: u64,
    bytes_read: u64,
    start_time: Instant,
    last_emit: Instant,
    event_name: &'static str,
}

impl<'a, R: Read> Read for ProgressReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 { return Ok(0); } // EOF reached

        self.bytes_read += n as u64;

        // Throttle UI updates to every 50ms to prevent frontend lag
        if self.last_emit.elapsed().as_millis() > 50 || self.bytes_read >= self.total_bytes {
            let elapsed = self.start_time.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 { self.bytes_read as f64 / elapsed } else { 0.0 };
            let eta = if speed > 0.0 && self.total_bytes > self.bytes_read { 
                (self.total_bytes - self.bytes_read) as f64 / speed 
            } else { 
                0.0 
            };
            
            let mut percent = if self.total_bytes > 0 { (self.bytes_read as f64 / self.total_bytes as f64) * 100.0 } else { 0.0 };
            if percent > 100.0 { percent = 100.0; } // Cap at 100% (MAC tags add slight overhead)

            let _ = self.app.emit(self.event_name, ProgressPayload { percent, eta_seconds: eta });
            self.last_emit = Instant::now();
        }
        Ok(n)
    }
}

#[tauri::command]
async fn split_action(app: AppHandle, input_dir: String, vault_name: String, output_dir: String, threshold: u8, total_shares: u8) -> Result<String, String> {
    let input_path = Path::new(&input_dir);
    
    // Safety check: Ensure directory is not empty
    let is_empty = std::fs::read_dir(input_path).map_err(|e| format!("Failed to read directory: {}", e))?.next().is_none();
    if is_empty { return Err("The selected directory is empty. Nothing to protect.".to_string()); }

    let _ = app.emit("status-msg", "Bundling directory into secure archive...");

    let tmp_tar_path = Path::new(&output_dir).join(format!("{}.tmp.tar", vault_name));
    let tar_file = File::create(&tmp_tar_path).map_err(|e| format!("Failed to create temp archive: {}", e))?;
    let mut builder = tar::Builder::new(tar_file);
    
    // Pack the entire folder cleanly
    let dir_name = input_path.file_name().unwrap_or_default();
    builder.append_dir_all(dir_name, input_path).map_err(|e| format!("Failed to archive directory: {}", e))?;
    builder.into_inner().map_err(|e| format!("Failed to finalize archive: {}", e))?;

    let _ = app.emit("status-msg", "Encryption is in progress...");

    let mut output_files = Vec::new();
    for i in 1..=total_shares {
        let out_path = Path::new(&output_dir).join(format!("{}.part{}.ombracrx", vault_name, i));
        let f = File::create(out_path).map_err(|e| format!("Failed to create share {}: {}", i, e))?;
        output_files.push(f);
    }

    let input_tar = File::open(&tmp_tar_path).map_err(|e| format!("Failed to read temp archive: {}", e))?;
    let total_bytes = input_tar.metadata().map(|m| m.len()).unwrap_or(0);
    
    // Attach the progress monitor to the input stream
    let progress_reader = ProgressReader {
        inner: input_tar, app: &app, total_bytes, bytes_read: 0,
        start_time: Instant::now(), last_emit: Instant::now(), event_name: "split-progress",
    };

    let crypto_result = split_file(progress_reader, output_files, threshold, total_shares);
    
    let _ = std::fs::remove_file(&tmp_tar_path); // Wipe temporary archive
    crypto_result.map_err(|e| e.to_string())?;

    let _ = app.emit("status-msg", "Encryption has been finished.");
    Ok("Split successful".to_string())
}

#[tauri::command]
async fn restore_action(app: AppHandle, share_paths: Vec<String>, output_dir: String) -> Result<String, String> {
    let _ = app.emit("status-msg", "Decryption is in progress...");

    let mut input_files = Vec::new();
    let total_bytes = if !share_paths.is_empty() {
        std::fs::metadata(&share_paths[0]).map(|m| m.len()).unwrap_or(0)
    } else { 0 };

    for path in share_paths {
        let f = File::open(&path).map_err(|e| format!("Failed to open share {}: {}", path, e))?;
        // Wrap every share in a progress monitor
        input_files.push(ProgressReader {
            inner: f, app: &app, total_bytes, bytes_read: 0,
            start_time: Instant::now(), last_emit: Instant::now(), event_name: "restore-progress",
        });
    }

    let tmp_tar_path = Path::new(&output_dir).join("ombracrux_restore.tmp.tar");
    let mut out_file = File::create(&tmp_tar_path).map_err(|e| format!("Failed to create temp output: {}", e))?;

    if let Err(e) = restore_file(input_files, &mut out_file) {
        let _ = std::fs::remove_file(&tmp_tar_path);
        return Err(e.to_string());
    }

    let _ = app.emit("status-msg", "Unpacking files to destination...");

    let tar_file = File::open(&tmp_tar_path).map_err(|e| format!("Failed to read decrypted archive: {}", e))?;
    let mut archive = tar::Archive::new(tar_file);
    let unpack_result = archive.unpack(&output_dir);
    
    let _ = std::fs::remove_file(&tmp_tar_path);
    unpack_result.map_err(|e| format!("Failed to unpack files: {}", e))?;

    let _ = app.emit("status-msg", "Decryption has been finished.");
    Ok("Restore successful".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![split_action, restore_action])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}