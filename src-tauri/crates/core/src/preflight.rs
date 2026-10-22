use anyhow::{anyhow, Result};
use std::fs;
use std::path::Path;

/// Fixed per-share header size:
/// 8 (magic) + 1 (version) + 16 (bundle_id) + 1 (total_shares) + 1 (threshold)
/// + 1 (share_index) + 16 (base_nonce_prefix) + 2 (share_len) + 33 (Shamir share)
/// + 32 (HMAC-SHA256 header_auth) = 111 bytes.
const SHARE_HEADER_BYTES: u64 = 111;

/// TAR uses 512-byte blocks for headers and file payload alignment.
const TAR_BLOCK_BYTES: u64 = 512;

/// TAR archives terminate with two 512-byte zero blocks (1024 bytes).
const TAR_EOF_BYTES: u64 = 1024;

/// Maximum plaintext chunk size fed into the XChaCha20-Poly1305 stream pipeline (1 MiB).
const STREAM_CHUNK_SIZE: u64 = 1024 * 1024;

/// Per-chunk encryption framing overhead (4-byte length + 1-byte flags + 16-byte Poly1305 tag).
const CHUNK_FRAMING_OVERHEAD: u64 = 21;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightReport {
    pub files_scanned: u64,
    pub dirs_scanned: u64,
    pub source_bytes: u64,
    pub shares_to_create: u8,
    pub estimated_share_bytes: u64,
    pub estimated_total_output_bytes: u64,
}

#[derive(Default)]
struct ScanCounters {
    files_scanned: u64,
    dirs_scanned: u64,
    source_bytes: u64,
    tar_stream_bytes: u64,
}

fn scan_directory_recursive(path: &Path, counters: &mut ScanCounters) -> Result<()> {
    let entries = fs::read_dir(path)
        .map_err(|error| anyhow!("Cannot read source directory {}: {error}", path.display()))?;

    for entry_result in entries {
        let entry = entry_result
            .map_err(|error| anyhow!("Cannot inspect a source directory entry: {error}"))?;

        let file_type = entry
            .file_type()
            .map_err(|error| anyhow!("Cannot inspect {}: {error}", entry.path().display()))?;

        if file_type.is_symlink() {
            return Err(anyhow!(
                "Symlinks are not currently supported in source directories: {}",
                entry.path().display()
            ));
        }

        if file_type.is_dir() {
            counters.dirs_scanned = counters
                .dirs_scanned
                .checked_add(1)
                .ok_or_else(|| anyhow!("Directory count overflow"))?;

            counters.tar_stream_bytes = counters
                .tar_stream_bytes
                .checked_add(TAR_BLOCK_BYTES)
                .ok_or_else(|| anyhow!("Archive size estimation overflow"))?;

            scan_directory_recursive(&entry.path(), counters)?;
        } else if file_type.is_file() {
            let metadata = entry.metadata().map_err(|error| {
                anyhow!(
                    "Cannot read metadata for {}: {error}",
                    entry.path().display()
                )
            })?;

            let file_len = metadata.len();

            counters.files_scanned = counters
                .files_scanned
                .checked_add(1)
                .ok_or_else(|| anyhow!("File count overflow"))?;

            counters.source_bytes = counters
                .source_bytes
                .checked_add(file_len)
                .ok_or_else(|| anyhow!("Source directory size overflow"))?;

            let padded_payload = file_len
                .div_ceil(TAR_BLOCK_BYTES)
                .checked_mul(TAR_BLOCK_BYTES)
                .ok_or_else(|| anyhow!("Archive padding size overflow"))?;

            let entry_tar_bytes = TAR_BLOCK_BYTES
                .checked_add(padded_payload)
                .ok_or_else(|| anyhow!("Archive entry size overflow"))?;

            counters.tar_stream_bytes = counters
                .tar_stream_bytes
                .checked_add(entry_tar_bytes)
                .ok_or_else(|| anyhow!("Archive stream size overflow"))?;
        } else {
            return Err(anyhow!(
                "Unsupported filesystem entry in source directory: {}",
                entry.path().display()
            ));
        }
    }

    Ok(())
}

/// Scans a source directory without following symlinks and estimates the resulting
/// encrypted share size and total multi-share storage consumption.
pub fn scan_preflight(source_dir: &Path, total_shares: u8) -> Result<PreflightReport> {
    if total_shares == 0 {
        return Err(anyhow!("Total shares must be at least 1"));
    }

    let root_meta = fs::symlink_metadata(source_dir)
        .map_err(|error| anyhow!("Cannot inspect source directory: {error}"))?;

    if root_meta.file_type().is_symlink() {
        return Err(anyhow!(
            "Symlinks are not currently supported as the source directory: {}",
            source_dir.display()
        ));
    }

    if !root_meta.is_dir() {
        return Err(anyhow!("The selected source path must be a directory"));
    }

    let mut counters = ScanCounters::default();
    scan_directory_recursive(source_dir, &mut counters)?;

    let total_tar_bytes = counters
        .tar_stream_bytes
        .checked_add(TAR_EOF_BYTES)
        .ok_or_else(|| anyhow!("TAR size estimation overflow"))?;

    let data_chunks = total_tar_bytes.div_ceil(STREAM_CHUNK_SIZE).max(1);
    // Include framing for all data chunks plus the final authenticated EOF frame.
    let framing_bytes = (data_chunks + 1)
        .checked_mul(CHUNK_FRAMING_OVERHEAD)
        .ok_or_else(|| anyhow!("Framing estimation overflow"))?;

    let estimated_share_bytes = SHARE_HEADER_BYTES
        .checked_add(total_tar_bytes)
        .and_then(|v| v.checked_add(framing_bytes))
        .ok_or_else(|| anyhow!("Estimated share size overflow"))?;

    let estimated_total_output_bytes =
        estimated_share_bytes
            .checked_mul(u64::from(total_shares))
            .ok_or_else(|| anyhow!("Estimated total output size overflow"))?;

    Ok(PreflightReport {
        files_scanned: counters.files_scanned,
        dirs_scanned: counters.dirs_scanned,
        source_bytes: counters.source_bytes,
        shares_to_create: total_shares,
        estimated_share_bytes,
        estimated_total_output_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn preflight_counts_files_and_estimates_total_output() {
        let temp = tempdir().unwrap();
        let sub = temp.path().join("docs");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("a.txt"), vec![b'x'; 1000]).unwrap();
        fs::write(temp.path().join("b.txt"), vec![b'y'; 2500]).unwrap();

        let report = scan_preflight(temp.path(), 5).unwrap();

        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.dirs_scanned, 1);
        assert_eq!(report.source_bytes, 3500);
        assert_eq!(report.shares_to_create, 5);
        assert!(report.estimated_share_bytes > report.source_bytes);
        assert_eq!(
            report.estimated_total_output_bytes,
            report.estimated_share_bytes * 5
        );
    }

    #[test]
    fn preflight_rejects_zero_shares() {
        let temp = tempdir().unwrap();
        assert!(scan_preflight(temp.path(), 0).is_err());
    }
}
