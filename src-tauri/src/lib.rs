use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Result as IoResult, Write};
use std::path::Path;
use std::time::Instant;
use tauri::{AppHandle, Emitter};

use ombracrux_core::format::ShareHeader;
use ombracrux_core::restore::restore_pipeline;
use ombracrux_core::shares::reconstruct_key;
use ombracrux_core::split::split_directory;

#[derive(Clone, serde::Serialize)]
struct ProgressPayload {
    percent: f64,
    eta_seconds: f64,
}

// Recursively calculates total uncompressed directory size
fn calculate_dir_size(path: &Path) -> u64 {
    let mut size = 0;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                size += std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            } else if p.is_dir() {
                size += calculate_dir_size(&p);
            }
        }
    }
    size
}

fn emit_progress(
    app: &AppHandle,
    event: &str,
    current: u64,
    total: u64,
    last_emit: &mut Instant,
    start_time: &Instant,
) {
    if last_emit.elapsed().as_millis() > 50 || current >= total {
        let elapsed = start_time.elapsed().as_secs_f64();
        let speed = if elapsed > 0.0 { current as f64 / elapsed } else { 0.0 };

        let eta = if speed > 0.0 && total > current {
            (total - current) as f64 / speed
        } else {
            0.0
        };

        let mut percent = if total > 0 {
            (current as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        if percent > 100.0 {
            percent = 100.0;
        }

        let _ = app.emit(event, ProgressPayload { percent, eta_seconds: eta });
        *last_emit = Instant::now();
    }
}

struct ProgressWriter<'a, W: Write> {
    inner: W,
    app: &'a AppHandle,
    total_bytes: u64,
    bytes_written: u64,
    start_time: Instant,
    last_emit: Instant,
    event_name: &'static str,
}

impl<'a, W: Write> Write for ProgressWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;
        emit_progress(
            self.app,
            self.event_name,
            self.bytes_written,
            self.total_bytes,
            &mut self.last_emit,
            &self.start_time,
        );
        Ok(n)
    }
    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()
    }
}

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
        if n > 0 {
            self.bytes_read += n as u64;
            emit_progress(
                self.app,
                self.event_name,
                self.bytes_read,
                self.total_bytes,
                &mut self.last_emit,
                &self.start_time,
            );
        }
        Ok(n)
    }
}

#[tauri::command]
async fn split_action(
    app: AppHandle,
    input_dir: String,
    vault_name: String,
    output_dir: String,
    threshold: u8,
    total_shares: u8,
) -> Result<String, String> {
    let input_path = Path::new(&input_dir);

    let total_bytes = calculate_dir_size(input_path);
    if total_bytes == 0 {
        return Err("The selected directory is empty. Nothing to protect.".to_string());
    }

    let _ = app.emit("status-msg", "Streaming directory into secure threshold shares...");

    let mut output_files = Vec::new();
    let mut partial_paths = Vec::new();
    let mut final_paths = Vec::new();
    let start_time = Instant::now();

    for i in 1..=total_shares {
        let final_path = Path::new(&output_dir).join(format!("{}.part{}.ombracrx", vault_name, i));
        
        // Safety Check: Do not overwrite existing shares
        if final_path.exists() {
            return Err(format!("Aborted: Output file already exists: {}", final_path.display()));
        }
        
        let partial_path = final_path.with_extension("ombracrx.partial");

        // Atomic File Creation: Ensure we lock exclusively
        let f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial_path)
            .map_err(|e| format!("Failed to create temporary share {}: {}", i, e))?;

        output_files.push(ProgressWriter {
            inner: f,
            app: &app,
            total_bytes,
            bytes_written: 0,
            start_time,
            last_emit: Instant::now(),
            event_name: "split-progress",
        });
        partial_paths.push(partial_path);
        final_paths.push(final_path);
    }

    match split_directory(input_path, output_files, threshold, total_shares) {
        Ok(_) => {
            // Atomic Commit: Rename valid partials to the final expected extension
            for (partial, final_p) in partial_paths.iter().zip(final_paths.iter()) {
                fs::rename(partial, final_p).map_err(|e| format!("Failed to finalize share: {}", e))?;
            }
            let _ = app.emit("status-msg", "Encryption has been finished.");
            Ok("Split successful".to_string())
        }
        Err(e) => {
            // Rollback: Shred the corrupted partial files if the stream fails
            for partial in partial_paths {
                let _ = fs::remove_file(partial);
            }
            Err(e.to_string())
        }
    }
}

#[tauri::command]
async fn restore_action(
    app: AppHandle,
    share_paths: Vec<String>,
    output_dir: String,
) -> Result<String, String> {
    let _ = app.emit("status-msg", "Authenticating headers and reconstructing key...");

    if share_paths.is_empty() {
        return Err("No shares provided for restoration.".to_string());
    }

    let mut ssss_shares = Vec::new();
    let mut bundle_id = [0u8; 16];
    let mut base_nonce_prefix = [0u8; 16];
    let mut threshold = 0;
    let mut expected_total_shares = 0;
    
    let mut seen_indexes = HashSet::new();
    let mut active_share_file: Option<File> = None;
    let total_bytes = fs::metadata(&share_paths[0]).map(|m| m.len()).unwrap_or(0);

    for (i, path) in share_paths.iter().enumerate() {
        let mut f = File::open(path).map_err(|e| format!("Failed to open share {}: {}", path, e))?;
        let header = ShareHeader::read_from(&mut f)
            .map_err(|e| format!("Invalid or corrupted header in {}: {}", path, e))?;

        // Cross-Validation 1: Reject duplicate shares
        if !seen_indexes.insert(header.share_index) {
            return Err(format!("Duplicate share detected: Index {} appears multiple times.", header.share_index));
        }

        // Cross-Validation 2: Ensure all files belong to the exact same bundle
        if i == 0 {
            bundle_id = header.bundle_id;
            base_nonce_prefix = header.base_nonce_prefix;
            threshold = header.threshold;
            expected_total_shares = header.total_shares;
            active_share_file = Some(f);
        } else if header.bundle_id != bundle_id 
            || header.threshold != threshold 
            || header.total_shares != expected_total_shares 
            || header.base_nonce_prefix != base_nonce_prefix 
        {
            return Err("Share mismatch: The provided files do not belong to the same cryptographic bundle.".to_string());
        }

        ssss_shares.push(header.ssss_share_data);
    }

    let master_key = reconstruct_key(&ssss_shares, threshold)
        .map_err(|e| format!("Failed to reconstruct master key: {}", e))?;

    let _ = app.emit("status-msg", "Decrypting and unpacking files securely...");

    let target_dest = Path::new(&output_dir);
    let share_file = active_share_file.unwrap();

    let progress_reader = ProgressReader {
        inner: share_file,
        app: &app,
        total_bytes,
        bytes_read: 0,
        start_time: Instant::now(),
        last_emit: Instant::now(),
        event_name: "restore-progress",
    };

    restore_pipeline(
        progress_reader,
        &master_key,
        bundle_id,
        base_nonce_prefix,
        target_dest,
    )
    .map_err(|e| format!("Restoration failed: {}", e))?;

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