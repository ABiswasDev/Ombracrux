use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use fs2::available_space;
use tauri::{AppHandle, Emitter};
use tempfile::{Builder as TempFileBuilder, NamedTempFile};

use ombracrux_core::format::ShareHeader;
use ombracrux_core::preflight::{PreflightReport, scan_preflight};
use ombracrux_core::restore::restore_pipeline;
use ombracrux_core::shares::{Zeroizing, reconstruct_key};
use ombracrux_core::split::split_directory;

#[derive(Clone, serde::Serialize)]
struct ProgressPayload {
    percent: f64,
    eta_seconds: f64,
}

#[derive(Clone, serde::Serialize)]
struct PreflightPayload {
    files_scanned: u64,
    dirs_scanned: u64,
    source_bytes: u64,
    total_tar_bytes: u64,
    shares_to_create: u8,
    estimated_share_bytes: u64,
    estimated_total_output_bytes: u64,
    available_output_bytes: Option<u64>,
    insufficient_space: bool,
}

/// Uses symlink_metadata so broken symlinks also count as existing paths.
fn path_entry_exists(path: &Path) -> IoResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn reject_symlink_ancestors(input_dir: &Path) -> Result<(), String> {
    let meta = fs::symlink_metadata(input_dir)
        .map_err(|error| format!("Cannot inspect source directory: {error}"))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "Symlinks are not currently supported as the source directory: {}",
            input_dir.display()
        ));
    }
    if !meta.is_dir() {
        return Err("The source path must be an existing directory".to_string());
    }
    Ok(())
}

/// Canonicalize both directories, reject output inside the source tree,
/// and perform a single unified preflight scan via `ombracrux_core::preflight`.
fn validate_split_paths(
    input_dir: &str,
    output_dir: &str,
    total_shares: u8,
) -> Result<(PathBuf, PathBuf, PreflightReport), String> {
    let raw_source = Path::new(input_dir);
    reject_symlink_ancestors(raw_source)?;

    let source_path = fs::canonicalize(raw_source)
        .map_err(|error| format!("Cannot resolve source directory: {error}"))?;

    let output_path = fs::canonicalize(output_dir)
        .map_err(|error| format!("Cannot resolve output directory: {error}"))?;

    if !source_path.is_dir() {
        return Err("The source path must be an existing directory".to_string());
    }

    if !output_path.is_dir() {
        return Err("The output path must be an existing directory".to_string());
    }

    // Includes equality: choosing the source itself as the output is rejected.
    if output_path.starts_with(&source_path) {
        return Err(
            "Unsafe output location: choose a directory outside the source directory tree."
                .to_string(),
        );
    }

    let report = scan_preflight(&source_path, total_shares).map_err(|error| error.to_string())?;

    Ok((source_path, output_path, report))
}

fn valid_vault_name(name: &str) -> bool {
    !name.is_empty()
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        })
}

fn query_available_space(output_dir: &Option<String>) -> Option<u64> {
    match output_dir {
        Some(dir) if !dir.trim().is_empty() => {
            let out_path = Path::new(dir);
            if out_path.exists() {
                available_space(out_path).ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

#[tauri::command]
async fn check_output_space(output_dir: String) -> Result<Option<u64>, String> {
    tauri::async_runtime::spawn_blocking(move || Ok(query_available_space(&Some(output_dir))))
        .await
        .map_err(|error| format!("Disk space check task failed: {error}"))?
}

#[tauri::command]
async fn preview_split(
    input_dir: String,
    output_dir: Option<String>,
    total_shares: u8,
) -> Result<PreflightPayload, String> {
    if total_shares < 2 {
        return Err("Total shares must be between 2 and 255.".to_string());
    }

    tauri::async_runtime::spawn_blocking(move || {
        let raw_source = Path::new(&input_dir);
        reject_symlink_ancestors(raw_source)?;

        let source_path = fs::canonicalize(raw_source)
            .map_err(|error| format!("Cannot resolve source directory: {error}"))?;

        let report =
            scan_preflight(&source_path, total_shares).map_err(|error| error.to_string())?;

        let available_output_bytes = query_available_space(&output_dir);

        let insufficient_space = available_output_bytes
            .map(|avail| report.estimated_total_output_bytes > avail)
            .unwrap_or(false);

        Ok(PreflightPayload {
            files_scanned: report.files_scanned,
            dirs_scanned: report.dirs_scanned,
            source_bytes: report.source_bytes,
            total_tar_bytes: report.total_tar_bytes,
            shares_to_create: report.shares_to_create,
            estimated_share_bytes: report.estimated_share_bytes,
            estimated_total_output_bytes: report.estimated_total_output_bytes,
            available_output_bytes,
            insufficient_space,
        })
    })
    .await
    .map_err(|error| format!("Preflight scan task failed: {error}"))?
}

/// Holds hidden temporary files until all encrypted shares are complete.
struct ShareOutputTransaction {
    partial_files: Vec<Option<NamedTempFile>>,
    final_paths: Vec<PathBuf>,
    published_paths: Vec<PathBuf>,
    committed: bool,
}

impl ShareOutputTransaction {
    fn new() -> Self {
        Self {
            partial_files: Vec::new(),
            final_paths: Vec::new(),
            published_paths: Vec::new(),
            committed: false,
        }
    }

    fn create_partial(&mut self, output_dir: &Path, final_path: PathBuf) -> Result<File, String> {
        if path_entry_exists(&final_path)
            .map_err(|error| format!("Cannot inspect destination: {error}"))?
        {
            return Err(format!(
                "Refusing to overwrite existing output: {}",
                final_path.display()
            ));
        }

        if self.final_paths.iter().any(|path| path == &final_path) {
            return Err(format!("Duplicate output path: {}", final_path.display()));
        }

        let temporary = TempFileBuilder::new()
            .prefix(".ombracrux-")
            .suffix(".partial")
            .tempfile_in(output_dir)
            .map_err(|error| format!("Cannot create temporary share file: {error}"))?;

        let writer = temporary
            .reopen()
            .map_err(|error| format!("Cannot open temporary share for writing: {error}"))?;

        self.partial_files.push(Some(temporary));
        self.final_paths.push(final_path);

        Ok(writer)
    }

    fn rollback_published(&mut self) -> Vec<String> {
        let paths = std::mem::take(&mut self.published_paths);
        let mut failed_paths = Vec::new();
        let mut errors = Vec::new();

        for path in paths.into_iter().rev() {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    errors.push(format!("{}: {}", path.display(), error));
                    failed_paths.push(path);
                }
            }
        }

        self.published_paths = failed_paths;
        errors
    }

    fn commit(&mut self) -> Result<(), String> {
        for final_path in &self.final_paths {
            if path_entry_exists(final_path).map_err(|error| {
                format!(
                    "Cannot inspect destination {}: {error}",
                    final_path.display()
                )
            })? {
                return Err(format!(
                    "Refusing to overwrite existing output: {}",
                    final_path.display()
                ));
            }
        }

        for index in 0..self.partial_files.len() {
            let temporary = self.partial_files[index]
                .take()
                .ok_or_else(|| "Missing temporary share file".to_string())?;

            let final_path = self.final_paths[index].clone();

            match temporary.persist_noclobber(&final_path) {
                Ok(file) => {
                    drop(file);
                    self.published_paths.push(final_path);
                }
                Err(error) => {
                    let reason = error.error.to_string();
                    drop(error);

                    let rollback_errors = self.rollback_published();

                    if rollback_errors.is_empty() {
                        return Err(format!(
                            "Could not publish {}: {}. Earlier published shares were rolled back.",
                            final_path.display(),
                            reason
                        ));
                    }

                    return Err(format!(
                        "Could not publish {}: {}. Rollback also failed for: {}",
                        final_path.display(),
                        reason,
                        rollback_errors.join("; ")
                    ));
                }
            }
        }

        self.committed = true;
        Ok(())
    }
}

impl Drop for ShareOutputTransaction {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.rollback_published();
        }
    }
}

struct ProgressWriter<'a> {
    inner: File,
    app: Option<&'a AppHandle>,
    total_bytes: u64,
    bytes_written: u64,
    start_time: Instant,
    last_emit: Instant,
    event_name: &'static str,
}

impl Write for ProgressWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        let count = self.inner.write(buf)?;
        self.bytes_written += count as u64;

        if let Some(app) = self.app {
            emit_progress(
                app,
                self.event_name,
                self.bytes_written,
                self.total_bytes,
                &mut self.last_emit,
                &self.start_time,
            );
        }

        Ok(count)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.inner.flush()?;
        self.inner.sync_all()
    }
}

struct ProgressReader<'a, R> {
    inner: R,
    app: &'a AppHandle,
    total_bytes: u64,
    bytes_read: u64,
    start_time: Instant,
    last_emit: Instant,
    event_name: &'static str,
}

impl<R: Read> Read for ProgressReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let count = self.inner.read(buf)?;

        if count > 0 {
            self.bytes_read += count as u64;

            emit_progress(
                self.app,
                self.event_name,
                self.bytes_read,
                self.total_bytes,
                &mut self.last_emit,
                &self.start_time,
            );
        }

        Ok(count)
    }
}

fn emit_progress(
    app: &AppHandle,
    event: &str,
    current: u64,
    total: u64,
    last_emit: &mut Instant,
    start_time: &Instant,
) {
    if last_emit.elapsed().as_millis() >= 50 {
        let elapsed = start_time.elapsed().as_secs_f64();

        let speed = if elapsed > 0.0 {
            current as f64 / elapsed
        } else {
            0.0
        };

        let eta = if speed > 0.0 && total > current {
            (total - current) as f64 / speed
        } else {
            0.0
        };

        let percent = if total > 0 {
            ((current as f64 / total as f64) * 100.0).min(99.0)
        } else {
            0.0
        };

        let _ = app.emit(
            event,
            ProgressPayload {
                percent,
                eta_seconds: eta,
            },
        );

        *last_emit = Instant::now();
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
    if !valid_vault_name(&vault_name) {
        return Err(
            "Vault name may contain only ASCII letters, digits, underscores and hyphens."
                .to_string(),
        );
    }

    if total_shares == 0 || threshold == 0 || threshold > total_shares {
        return Err("Invalid threshold: require 1 <= threshold <= total shares.".to_string());
    }

    tauri::async_runtime::spawn_blocking(move || {
        // Single unified directory scan and path validation.
        let (input_path, output_path, report) =
            validate_split_paths(&input_dir, &output_dir, total_shares)?;

        if let Ok(avail) = available_space(&output_path) {
            if report.estimated_total_output_bytes > avail {
                return Err(format!(
                    "Insufficient disk space on destination drive: requires ~{:.1} GB, but only {:.1} GB is available.",
                    report.estimated_total_output_bytes as f64 / 1_073_741_824.0,
                    avail as f64 / 1_073_741_824.0
                ));
            }
        }

        let _ = app.emit("status-msg", "Generating encrypted shares...");

        let final_paths: Vec<PathBuf> = (1..=total_shares)
            .map(|index| output_path.join(format!("{}.part{}.ombracrx", vault_name, index)))
            .collect();

        for final_path in &final_paths {
            if path_entry_exists(final_path)
                .map_err(|error| format!("Cannot inspect output path: {error}"))?
            {
                return Err(format!(
                    "Output already exists. Nothing was overwritten: {}",
                    final_path.display()
                ));
            }
        }

        let mut transaction = ShareOutputTransaction::new();
        let start_time = Instant::now();
        let mut output_files = Vec::with_capacity(total_shares as usize);

        for (index, final_path) in final_paths.into_iter().enumerate() {
            let file = transaction.create_partial(&output_path, final_path)?;

            output_files.push(ProgressWriter {
                inner: file,
                app: if index == 0 { Some(&app) } else { None },
                total_bytes: report.estimated_share_bytes,
                bytes_written: 0,
                start_time,
                last_emit: Instant::now(),
                event_name: "split-progress",
            });
        }

        split_directory(&input_path, output_files, threshold, total_shares)
            .map_err(|error| format!("Encryption failed: {error}"))?;

        transaction.commit()?;

        let _ = app.emit(
            "split-progress",
            ProgressPayload {
                percent: 100.0,
                eta_seconds: 0.0,
            },
        );
        let _ = app.emit("status-msg", "Encryption has been finished.");
        Ok("Split successful".to_string())
    })
    .await
    .map_err(|error| format!("Encryption worker failed: {error}"))?
}

#[tauri::command]
async fn restore_action(
    app: AppHandle,
    share_paths: Vec<String>,
    output_dir: String,
) -> Result<String, String> {
    if share_paths.is_empty() {
        return Err("No shares provided for restoration.".to_string());
    }

    tauri::async_runtime::spawn_blocking(move || {
        let _ = app.emit("status-msg", "Verifying & Restoring files...");

        let mut key_share_data = Vec::new();
        let mut headers: Vec<ShareHeader> = Vec::new();
        let mut seen_indexes = HashSet::new();

        let mut bundle_id = [0u8; 16];
        let mut base_nonce_prefix = [0u8; 16];
        let mut threshold = 0u8;
        let mut expected_total_shares = 0u8;

        let mut active_share_file: Option<File> = None;

        let first_share_metadata = fs::metadata(&share_paths[0])
            .map_err(|error| format!("Cannot inspect first share: {error}"))?;
        let total_bytes = first_share_metadata.len();

        for (index, path) in share_paths.iter().enumerate() {
            let mut file = File::open(path)
                .map_err(|error| format!("Failed to open share {path}: {error}"))?;

            let header = ShareHeader::read_from(&mut file)
                .map_err(|error| format!("Invalid share header in {path}: {error}"))?;

            if !seen_indexes.insert(header.share_index) {
                return Err(format!(
                    "Duplicate share index detected: {}",
                    header.share_index
                ));
            }

            if index == 0 {
                bundle_id = header.bundle_id;
                base_nonce_prefix = header.base_nonce_prefix;
                threshold = header.threshold;
                expected_total_shares = header.total_shares;

                active_share_file = Some(file);
            } else if header.bundle_id != bundle_id
                || header.threshold != threshold
                || header.total_shares != expected_total_shares
                || header.base_nonce_prefix != base_nonce_prefix
            {
                return Err("Share mismatch: files do not belong to the same bundle.".to_string());
            }

            key_share_data.push(header.ssss_share_data.clone());
            headers.push(header);
        }

        if headers.len() < threshold as usize {
            return Err(format!(
                "Insufficient shares: received {}, but need at least {}.",
                headers.len(),
                threshold
            ));
        }

        let master_key: Zeroizing<[u8; 32]> = reconstruct_key(&key_share_data, threshold)
            .map_err(|error| format!("Failed to reconstruct the master key: {error}"))?;

        for header in &headers {
            header.verify_auth(&master_key).map_err(|error| {
                format!(
                    "Share {} failed header authentication: {error}",
                    header.share_index
                )
            })?;
        }

        let target_dest = Path::new(&output_dir);
        let share_file = active_share_file
            .ok_or_else(|| "Could not open a share for restoration.".to_string())?;

        let progress_reader = ProgressReader {
            inner: share_file,
            app: &app,
            total_bytes,
            bytes_read: 0,
            start_time: Instant::now(),
            last_emit: Instant::now(),
            event_name: "restore-progress",
        };

        let restored_path = restore_pipeline(
            progress_reader,
            &master_key,
            bundle_id,
            base_nonce_prefix,
            target_dest,
        )
        .map_err(|error| format!("Restoration failed: {error}"))?;

        let _ = app.emit(
            "restore-progress",
            ProgressPayload {
                percent: 100.0,
                eta_seconds: 0.0,
            },
        );

        Ok(format!(
            "Success: Files restored to\n{}",
            restored_path.display()
        ))
    })
    .await
    .map_err(|error| format!("Restoration worker failed: {error}"))?
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            preview_split,
            check_output_space,
            split_action,
            restore_action
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn rejects_output_inside_source_directory() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("source");
        let output = source.join("output");

        fs::create_dir_all(&output).unwrap();

        let result = validate_split_paths(source.to_str().unwrap(), output.to_str().unwrap(), 3);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("outside the source"));
    }

    #[test]
    fn transaction_removes_partial_files_on_drop() {
        let temp = tempdir().unwrap();
        let output = temp.path();

        let final_path = output.join("test.part1.ombracrx");

        let mut transaction = ShareOutputTransaction::new();

        let mut file = transaction.create_partial(output, final_path).unwrap();

        file.write_all(b"partial encrypted share").unwrap();
        drop(file);

        assert_eq!(fs::read_dir(output).unwrap().count(), 1);

        drop(transaction);

        assert_eq!(fs::read_dir(output).unwrap().count(), 0);
    }

    #[test]
    fn transaction_does_not_overwrite_an_existing_output() {
        let temp = tempdir().unwrap();
        let output = temp.path();

        let final_path = output.join("existing.part1.ombracrx");
        fs::write(&final_path, b"keep this file").unwrap();

        let mut transaction = ShareOutputTransaction::new();

        assert!(
            transaction
                .create_partial(output, final_path.clone())
                .is_err()
        );

        drop(transaction);

        assert_eq!(fs::read(&final_path).unwrap(), b"keep this file");

        assert_eq!(fs::read_dir(output).unwrap().count(), 1);
    }

    #[test]
    fn transaction_rolls_back_if_a_destination_appears_before_commit() {
        let temp = tempdir().unwrap();
        let output = temp.path();

        let final_one = output.join("vault.part1.ombracrx");
        let final_two = output.join("vault.part2.ombracrx");

        let mut transaction = ShareOutputTransaction::new();

        let mut file_one = transaction
            .create_partial(output, final_one.clone())
            .unwrap();
        file_one.write_all(b"first share").unwrap();
        drop(file_one);

        let mut file_two = transaction
            .create_partial(output, final_two.clone())
            .unwrap();
        file_two.write_all(b"second share").unwrap();
        drop(file_two);

        fs::write(&final_two, b"external file").unwrap();

        assert!(transaction.commit().is_err());
        drop(transaction);

        assert!(!final_one.exists());
        assert_eq!(fs::read(&final_two).unwrap(), b"external file");
    }

    #[test]
    fn commit_rolls_back_first_share_when_later_publication_fails() {
        let temp = tempdir().unwrap();
        let output = temp.path();

        let final_one = output.join("vault.part1.ombracrx");
        let final_two = output.join("missing_parent").join("vault.part2.ombracrx");

        let mut transaction = ShareOutputTransaction::new();

        let mut file_one = transaction
            .create_partial(output, final_one.clone())
            .unwrap();
        file_one.write_all(b"first share").unwrap();
        drop(file_one);

        let mut file_two = transaction
            .create_partial(output, final_two.clone())
            .unwrap();
        file_two.write_all(b"second share").unwrap();
        drop(file_two);

        let error = transaction.commit().unwrap_err();

        assert!(
            error.contains("Earlier published shares were rolled back"),
            "Unexpected error: {error}"
        );

        assert!(!final_one.exists());
        assert!(!final_two.exists());
        assert_eq!(fs::read_dir(output).unwrap().count(), 0);
    }
}
