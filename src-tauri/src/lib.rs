use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{Read, Result as IoResult, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use fs2::available_space;
use tauri::{AppHandle, Emitter};
use tempfile::{Builder as TempFileBuilder, NamedTempFile};

use ombracrux_core::format::ShareHeader;
use ombracrux_core::manifest::write_recovery_files;
use ombracrux_core::preflight::{PreflightReport, scan_preflight};
use ombracrux_core::restore::restore_pipeline;
use ombracrux_core::shares::{Zeroizing, reconstruct_key};
use ombracrux_core::split::split_directory;
use ombracrux_core::verify::verify_payload_stream;

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

#[derive(Clone, serde::Serialize)]
struct ShareInspectionPayload {
    selected_count: usize,
    threshold: u8,
    total_shares: u8,
    share_indices: Vec<u8>,
    single_share_bytes: u64,
    total_verify_read_bytes: u64,
    meets_threshold: bool,
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

#[tauri::command]
async fn inspect_shares(share_paths: Vec<String>) -> Result<ShareInspectionPayload, String> {
    if share_paths.is_empty() {
        return Err("No shares selected.".to_string());
    }

    tauri::async_runtime::spawn_blocking(move || {
        let mut bundle_id = [0u8; 16];
        let mut base_nonce_prefix = [0u8; 16];
        let mut threshold = 0u8;
        let mut total_shares = 0u8;
        let mut seen_indices = HashSet::new();
        let mut share_indices = Vec::with_capacity(share_paths.len());
        let mut single_share_bytes = 0u64;
        let mut total_verify_read_bytes = 0u64;

        for (idx, path) in share_paths.iter().enumerate() {
            let meta =
                fs::metadata(path).map_err(|e| format!("Cannot inspect share {path}: {e}"))?;
            let file_len = meta.len();

            if idx == 0 {
                single_share_bytes = file_len;
            }

            total_verify_read_bytes = total_verify_read_bytes
                .checked_add(file_len)
                .ok_or_else(|| "Total share size overflow".to_string())?;

            let mut file =
                File::open(path).map_err(|e| format!("Failed to open share {path}: {e}"))?;
            let header = ShareHeader::read_from(&mut file)
                .map_err(|e| format!("Invalid share header in {path}: {e}"))?;

            if !seen_indices.insert(header.share_index) {
                return Err(format!(
                    "Duplicate share index detected: #{}",
                    header.share_index
                ));
            }

            if idx == 0 {
                bundle_id = header.bundle_id;
                base_nonce_prefix = header.base_nonce_prefix;
                threshold = header.threshold;
                total_shares = header.total_shares;
            } else if header.bundle_id != bundle_id
                || header.threshold != threshold
                || header.total_shares != total_shares
                || header.base_nonce_prefix != base_nonce_prefix
            {
                return Err(
                    "Share mismatch: selected files do not belong to the same bundle.".to_string(),
                );
            }

            share_indices.push(header.share_index);
        }

        share_indices.sort_unstable();
        let meets_threshold = share_paths.len() >= threshold as usize;

        Ok(ShareInspectionPayload {
            selected_count: share_paths.len(),
            threshold,
            total_shares,
            share_indices,
            single_share_bytes,
            total_verify_read_bytes,
            meets_threshold,
        })
    })
    .await
    .map_err(|error| format!("Share inspection failed: {error}"))?
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
    app: Option<&'a AppHandle>,
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

            if let Some(app) = self.app {
                emit_progress(
                    app,
                    self.event_name,
                    self.bytes_read,
                    self.total_bytes,
                    &mut self.last_emit,
                    &self.start_time,
                );
            }
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

/// Attempts payload restoration across all authenticated shares in order,
/// automatically failing over to the next share if a share's payload stream
/// is corrupted or truncated.
fn restore_with_failover(
    app: Option<&AppHandle>,
    share_paths: &[String],
    headers: &[ShareHeader],
    master_key: &[u8; 32],
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
    target_dest: &Path,
) -> Result<(PathBuf, u8, usize), String> {
    let dest_meta = fs::metadata(target_dest)
        .map_err(|error| format!("Cannot access destination folder: {error}"))?;
    if !dest_meta.is_dir() {
        return Err("The output path must be an existing directory.".to_string());
    }

    let mut failure_reasons = Vec::new();

    for (attempt_idx, (path, header)) in share_paths.iter().zip(headers.iter()).enumerate() {
        if attempt_idx > 0 {
            if let Some(app_handle) = app {
                let _ = app_handle.emit(
                    "status-msg",
                    format!(
                        "Share #{} payload failed; failing over to Share #{}...",
                        headers[attempt_idx - 1].share_index,
                        header.share_index
                    ),
                );
            }
        }

        let file_meta = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) => {
                failure_reasons.push(format!(
                    "Share #{}: cannot inspect share file ({error})",
                    header.share_index
                ));
                continue;
            }
        };

        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) => {
                failure_reasons.push(format!(
                    "Share #{}: cannot reopen share file ({error})",
                    header.share_index
                ));
                continue;
            }
        };

        if let Err(error) = ShareHeader::read_from(&mut file) {
            failure_reasons.push(format!(
                "Share #{}: invalid header on reopen ({error})",
                header.share_index
            ));
            continue;
        }

        let progress_reader = ProgressReader {
            inner: file,
            app,
            total_bytes: file_meta.len(),
            bytes_read: 0,
            start_time: Instant::now(),
            last_emit: Instant::now(),
            event_name: "restore-progress",
        };

        match restore_pipeline(
            progress_reader,
            master_key,
            bundle_id,
            base_nonce_prefix,
            target_dest,
        ) {
            Ok(restored_path) => {
                return Ok((restored_path, header.share_index, attempt_idx));
            }
            Err(error) => {
                failure_reasons.push(format!("Share #{}: {error}", header.share_index));
            }
        }
    }

    Err(format!(
        "Restoration failed across all {} selected shares ({})",
        share_paths.len(),
        failure_reasons.join("; ")
    ))
}

#[tauri::command]
async fn split_action(
    app: AppHandle,
    input_dir: String,
    vault_name: String,
    output_dir: String,
    threshold: u8,
    total_shares: u8,
    export_manifest: bool,
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

        if export_manifest {
            for recovery_file in [
                output_path.join(format!("{vault_name}.manifest.json")),
                output_path.join(format!("{vault_name}.recovery-card.html")),
            ] {
                if path_entry_exists(&recovery_file)
                    .map_err(|error| format!("Cannot inspect recovery output path: {error}"))?
                {
                    return Err(format!(
                        "Recovery manifest file already exists. Nothing was overwritten: {}",
                        recovery_file.display()
                    ));
                }
            }
        }

        let mut transaction = ShareOutputTransaction::new();
        let start_time = Instant::now();
        let mut output_files = Vec::with_capacity(total_shares as usize);

        for (index, final_path) in final_paths.iter().cloned().enumerate() {
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

        let mut completion_note = format!(
            "Created {} encrypted shares in {}",
            total_shares,
            output_path.display()
        );

        if export_manifest {
            let _ = app.emit(
                "status-msg",
                "Streaming SHA-256 checksums for recovery manifest & card...",
            );
            match write_recovery_files(&output_path, &vault_name, &final_paths) {
                Ok(generated) => {
                    completion_note = format!(
                        "Created {} shares + {}\nPrintable Card: {}",
                        total_shares,
                        generated
                            .manifest_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("manifest.json"),
                        generated
                            .html_card_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("recovery-card.html")
                    );
                }
                Err(error) => {
                    completion_note = format!(
                        "Created {} encrypted shares in {}.\nWarning: Optional manifest/recovery card export failed ({error}). Your encrypted shares are intact.",
                        total_shares,
                        output_path.display()
                    );
                }
            }
        }

        let _ = app.emit(
            "split-progress",
            ProgressPayload {
                percent: 100.0,
                eta_seconds: 0.0,
            },
        );
        let _ = app.emit("status-msg", "Encryption has been finished.");
        Ok(completion_note)
    })
    .await
    .map_err(|error| format!("Encryption worker failed: {error}"))?
}

#[tauri::command]
async fn verify_action(app: AppHandle, share_paths: Vec<String>) -> Result<String, String> {
    if share_paths.is_empty() {
        return Err("No shares provided for verification.".to_string());
    }

    tauri::async_runtime::spawn_blocking(move || {
        let _ = app.emit("status-msg", "Reconstructing key & authenticating share headers...");

        let mut key_share_data = Vec::new();
        let mut headers: Vec<ShareHeader> = Vec::new();
        let mut seen_indexes = HashSet::new();

        let mut bundle_id = [0u8; 16];
        let mut base_nonce_prefix = [0u8; 16];
        let mut threshold = 0u8;
        let mut expected_total_shares = 0u8;
        let mut total_bytes_all_shares = 0u64;

        for (index, path) in share_paths.iter().enumerate() {
            let metadata = fs::metadata(path)
                .map_err(|error| format!("Cannot inspect share {path}: {error}"))?;
            total_bytes_all_shares = total_bytes_all_shares
                .checked_add(metadata.len())
                .ok_or_else(|| "Total verification byte size overflow".to_string())?;

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
                "Insufficient shares for threshold verification: selected {}, but need at least {}.",
                headers.len(),
                threshold
            ));
        }

        let master_key: Zeroizing<[u8; 32]> = reconstruct_key(&key_share_data, threshold)
            .map_err(|error| format!("Failed to reconstruct the master key: {error}"))?;

        for header in &headers {
            header.verify_auth(&master_key).map_err(|error| {
                format!(
                    "Share {} failed header HMAC authentication: {error}",
                    header.share_index
                )
            })?;
        }

        let start_time = Instant::now();
        let mut last_emit = Instant::now();
        let mut cumulative_bytes_read = 0u64;
        let mut last_report = None;

        for (i, path) in share_paths.iter().enumerate() {
            let _ = app.emit(
                "status-msg",
                format!(
                    "Verifying share {} of {} (in-memory AEAD + TAR check)...",
                    i + 1,
                    share_paths.len()
                ),
            );

            let mut file = File::open(path)
                .map_err(|error| format!("Failed to reopen share {path}: {error}"))?;
            let header = ShareHeader::read_from(&mut file)
                .map_err(|error| format!("Invalid share header in {path}: {error}"))?;

            let mut reader = ProgressReader {
                inner: file,
                app: Some(&app),
                total_bytes: total_bytes_all_shares,
                bytes_read: cumulative_bytes_read,
                start_time,
                last_emit,
                event_name: "restore-progress",
            };

            let report = verify_payload_stream(
                &mut reader,
                &master_key,
                bundle_id,
                base_nonce_prefix,
            )
            .map_err(|error| {
                format!(
                    "Share #{} ({path}) failed payload verification: {error}",
                    header.share_index
                )
            })?;

            cumulative_bytes_read = reader.bytes_read;
            last_emit = reader.last_emit;
            last_report = Some(report);
        }

        let _ = app.emit(
            "restore-progress",
            ProgressPayload {
                percent: 100.0,
                eta_seconds: 0.0,
            },
        );
        let _ = app.emit("status-msg", "");

        let summary = last_report.ok_or_else(|| "Verification produced no report.".to_string())?;

        Ok(format!(
            "Verified {} of {} shares (Threshold: {}) — 100% Intact.\nArchive contains {} files and {} folders ({} B plaintext across {} authenticated chunks). Zero files written to disk.",
            share_paths.len(),
            expected_total_shares,
            threshold,
            summary.files_verified,
            summary.dirs_verified,
            summary.plaintext_bytes_verified,
            summary.chunks_verified
        ))
    })
    .await
    .map_err(|error| format!("Verification worker failed: {error}"))?
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
        let (restored_path, used_share_index, attempt_idx) = restore_with_failover(
            Some(&app),
            &share_paths,
            &headers,
            &master_key,
            bundle_id,
            base_nonce_prefix,
            target_dest,
        )?;

        let _ = app.emit(
            "restore-progress",
            ProgressPayload {
                percent: 100.0,
                eta_seconds: 0.0,
            },
        );
        let _ = app.emit("status-msg", "");

        if attempt_idx > 0 {
            Ok(format!(
                "Success (recovered via Share #{} after earlier share payload error): Files restored to\n{}",
                used_share_index,
                restored_path.display()
            ))
        } else {
            Ok(format!(
                "Success: Files restored to\n{}",
                restored_path.display()
            ))
        }
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
            inspect_shares,
            split_action,
            verify_action,
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

    #[test]
    fn restore_fails_over_to_next_share_when_first_payload_is_corrupted() {
        let temp = tempdir().unwrap();
        let src = temp.path().join("src");
        let shares_dir = temp.path().join("shares");
        let restore_dir = temp.path().join("restored");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&shares_dir).unwrap();
        fs::create_dir_all(&restore_dir).unwrap();
        fs::write(src.join("important.txt"), b"resilient threshold data").unwrap();

        let share_paths_buf: Vec<PathBuf> = (1..=2)
            .map(|i| shares_dir.join(format!("Vault.part{i}.ombracrx")))
            .collect();
        let files: Vec<File> = share_paths_buf
            .iter()
            .map(|p| File::create(p).unwrap())
            .collect();

        split_directory(&src, files, 2, 2).unwrap();

        // Corrupt the encrypted payload body of Share #1 while leaving its header intact
        let mut share1_bytes = fs::read(&share_paths_buf[0]).unwrap();
        let last_idx = share1_bytes.len() - 5;
        share1_bytes[last_idx] ^= 0xFF;
        fs::write(&share_paths_buf[0], &share1_bytes).unwrap();

        let share_strings: Vec<String> = share_paths_buf
            .iter()
            .map(|p| p.to_str().unwrap().to_string())
            .collect();

        let mut headers = Vec::new();
        let mut key_shares = Vec::new();
        for path in &share_paths_buf {
            let mut f = File::open(path).unwrap();
            let h = ShareHeader::read_from(&mut f).unwrap();
            key_shares.push(h.ssss_share_data.clone());
            headers.push(h);
        }

        let master_key = reconstruct_key(&key_shares, 2).unwrap();
        for h in &headers {
            h.verify_auth(&master_key).unwrap();
        }

        let (restored_path, used_share_index, attempt_idx) = restore_with_failover(
            None,
            &share_strings,
            &headers,
            &master_key,
            headers[0].bundle_id,
            headers[0].base_nonce_prefix,
            &restore_dir,
        )
        .unwrap();

        assert_eq!(attempt_idx, 1);
        assert_eq!(used_share_index, 2);
        assert_eq!(
            fs::read(restored_path.join("important.txt")).unwrap(),
            b"resilient threshold data"
        );
    }
}
