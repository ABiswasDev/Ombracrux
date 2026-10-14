use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use tauri::{AppHandle, Emitter};
use tempfile::{Builder as TempFileBuilder, NamedTempFile};

use ombracrux_core::format::ShareHeader;
use ombracrux_core::restore::restore_pipeline;
use ombracrux_core::shares::reconstruct_key;
use ombracrux_core::split::split_directory;

#[derive(Clone, serde::Serialize)]
struct ProgressPayload {
    percent: f64,
    eta_seconds: f64,
}

/// Uses symlink_metadata so broken symlinks also count as existing paths.
fn path_entry_exists(path: &Path) -> IoResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Calculate input size without following symlinks.
///
/// Symlinks and special filesystem objects are rejected for now.
/// This also avoids recursive directory-symlink loops in progress scanning.
fn calculate_dir_size(path: &Path) -> Result<u64, String> {
    let entries = fs::read_dir(path).map_err(|error| {
        format!("Cannot read source directory {}: {error}", path.display())
    })?;

    let mut total = 0u64;

    for entry_result in entries {
        let entry = entry_result.map_err(|error| {
            format!("Cannot inspect a source directory entry: {error}")
        })?;

        let file_type = entry.file_type().map_err(|error| {
            format!("Cannot inspect {}: {error}", entry.path().display())
        })?;

        if file_type.is_symlink() {
            return Err(format!(
                "Symlinks are not currently supported in source directories: {}",
                entry.path().display()
            ));
        }

        if file_type.is_dir() {
            let child_size = calculate_dir_size(&entry.path())?;
            total = total.checked_add(child_size).ok_or_else(|| {
                "Source directory size overflow".to_string()
            })?;
        } else if file_type.is_file() {
            let metadata = entry.metadata().map_err(|error| {
                format!("Cannot read metadata for {}: {error}", entry.path().display())
            })?;

            total = total.checked_add(metadata.len()).ok_or_else(|| {
                "Source directory size overflow".to_string()
            })?;
        } else {
            return Err(format!(
                "Unsupported filesystem entry in source directory: {}",
                entry.path().display()
            ));
        }
    }

    Ok(total)
}

/// Canonicalize both directories and reject output inside the source tree.
fn validate_split_paths(
    input_dir: &str,
    output_dir: &str,
) -> Result<(PathBuf, PathBuf, u64), String> {
    let source_path = fs::canonicalize(input_dir)
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

    let total_bytes = calculate_dir_size(&source_path)?;

    Ok((source_path, output_path, total_bytes))
}

fn valid_vault_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || character == '_'
                || character == '-')
}

/// Holds hidden temporary files until all encrypted shares are complete.
///
/// On ordinary errors, unpublished temporary files are cleaned up and
/// any already-published output files are rolled back on a best-effort
/// basis. Separate filesystem names cannot be published as one globally
/// atomic operation; sudden power loss during publication remains a risk.
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

    fn create_partial(
        &mut self,
        output_dir: &Path,
        final_path: PathBuf,
    ) -> Result<File, String> {
        if path_entry_exists(&final_path)
            .map_err(|error| format!("Cannot inspect destination: {error}"))?
        {
            return Err(format!(
                "Refusing to overwrite existing output: {}",
                final_path.display()
            ));
        }

        if self.final_paths.iter().any(|path| path == &final_path) {
            return Err(format!(
                "Duplicate output path: {}",
                final_path.display()
            ));
        }

        // Create in the same directory/filesystem as the destination.
        let temporary = TempFileBuilder::new()
            .prefix(".ombracrux-")
            .suffix(".partial")
            .tempfile_in(output_dir)
            .map_err(|error| {
                format!("Cannot create temporary share file: {error}")
            })?;

        let writer = temporary.reopen().map_err(|error| {
            format!("Cannot open temporary share for writing: {error}")
        })?;

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

        // Keep failed paths so Drop can try cleanup one more time.
        self.published_paths = failed_paths;
        errors
    }

    fn commit(&mut self) -> Result<(), String> {
        // Detect existing destinations before publishing any share.
        for final_path in &self.final_paths {
            if path_entry_exists(final_path)
                .map_err(|error| {
                    format!(
                        "Cannot inspect destination {}: {error}",
                        final_path.display()
                    )
                })?
            {
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

            // FIX: Clone the path to avoid borrowing `self` immutably
            let final_path = self.final_paths[index].clone();

            match temporary.persist_noclobber(&final_path) {
                Ok(file) => {
                    // The final path now owns the completed output file.
                    drop(file);
                    self.published_paths.push(final_path);
                }
                Err(error) => {
                    let reason = error.error.to_string();

                    // Dropping PersistError also drops its temporary file.
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
            // Best-effort cleanup for any files published before an error.
            let _ = self.rollback_published();
        }

        // Remaining NamedTempFile values are removed automatically on drop.
    }
}

struct ProgressWriter<'a> {
    inner: File,
    app: &'a AppHandle,
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

        emit_progress(
            self.app,
            self.event_name,
            self.bytes_written,
            self.total_bytes,
            &mut self.last_emit,
            &self.start_time,
        );

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
    if last_emit.elapsed().as_millis() > 50 || current >= total {
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
            ((current as f64 / total as f64) * 100.0).min(100.0)
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
        return Err(
            "Invalid threshold: require 1 <= threshold <= total shares.".to_string(),
        );
    }

    let (input_path, output_path, total_bytes) =
        validate_split_paths(&input_dir, &output_dir)?;

    let _ = app.emit(
        "status-msg",
        "Streaming directory into authenticated threshold shares...",
    );

    let final_paths: Vec<PathBuf> = (1..=total_shares)
        .map(|index| {
            output_path.join(format!(
                "{}.part{}.ombracrx",
                vault_name, index
            ))
        })
        .collect();

    // Preflight all final paths before creating any temporary output.
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

    for final_path in final_paths {
        let file = transaction.create_partial(
            &output_path,
            final_path.clone(),
        )?;

        output_files.push(ProgressWriter {
            inner: file,
            app: &app,
            total_bytes,
            bytes_written: 0,
            start_time,
            last_emit: Instant::now(),
            event_name: "split-progress",
        });
    }

    // If the split fails, the temporary output transaction is dropped.
    split_directory(
        &input_path,
        output_files,
        threshold,
        total_shares,
    )
    .map_err(|error| format!("Encryption failed: {error}"))?;

    transaction.commit()?;

    let _ = app.emit("status-msg", "Encryption has been finished.");
    Ok("Split successful".to_string())
}

#[tauri::command]
async fn restore_action(
    app: AppHandle,
    share_paths: Vec<String>,
    output_dir: String,
) -> Result<String, String> {
    let _ = app.emit(
        "status-msg",
        "Validating share headers and reconstructing the key...",
    );

    if share_paths.is_empty() {
        return Err("No shares provided for restoration.".to_string());
    }

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

        // The file cursor remains immediately after its complete header.
        let header = ShareHeader::read_from(&mut file)
            .map_err(|error| {
                format!("Invalid share header in {path}: {error}")
            })?;

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
            return Err(
                "Share mismatch: files do not belong to the same bundle."
                    .to_string(),
            );
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

    let master_key = reconstruct_key(&key_share_data, threshold)
        .map_err(|error| {
            format!("Failed to reconstruct the master key: {error}")
        })?;

    // Only after key reconstruction can we authenticate each individual
    // header, including its own Shamir fragment and share index.
    for header in &headers {
        header.verify_auth(&master_key).map_err(|error| {
            format!(
                "Share {} failed header authentication: {error}",
                header.share_index
            )
        })?;
    }

    let _ = app.emit(
        "status-msg",
        "Headers authenticated. Decrypting and restoring...",
    );

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

    // Capture the exact path generated by the restorer
    let restored_path = restore_pipeline(
        progress_reader,
        &master_key,
        bundle_id,
        base_nonce_prefix,
        target_dest,
    )
    .map_err(|error| format!("Restoration failed: {error}"))?;

    let _ = app.emit("status-msg", "Decryption has been finished.");
    
    // Pass the exact destination to the UI
    Ok(format!("Success: Files restored to\n{}", restored_path.display()))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
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

        let result = validate_split_paths(
            source.to_str().unwrap(),
            output.to_str().unwrap(),
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("outside the source"));
    }

    #[test]
    fn transaction_removes_partial_files_on_drop() {
        let temp = tempdir().unwrap();
        let output = temp.path();

        let final_path = output.join("test.part1.ombracrx");

        let mut transaction = ShareOutputTransaction::new();

        let mut file = transaction
            .create_partial(output, final_path)
            .unwrap();

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

        assert!(transaction
            .create_partial(output, final_path.clone())
            .is_err());

        drop(transaction);

        assert_eq!(
            fs::read(&final_path).unwrap(),
            b"keep this file"
        );

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

        // Simulate a competing process creating a final destination.
        fs::write(&final_two, b"external file").unwrap();

        assert!(transaction.commit().is_err());
        drop(transaction);

        assert!(!final_one.exists());
        assert_eq!(fs::read(&final_two).unwrap(), b"external file");
    }
}