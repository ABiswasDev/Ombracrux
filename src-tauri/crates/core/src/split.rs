use anyhow::{anyhow, Result};
use rand::{rngs::OsRng, RngCore};
use std::path::Path;

use crate::archive::stream_directory_to_memory;
use crate::crypto::encrypt_pipeline;
use crate::format::{ShareHeader, FORMAT_VERSION, MAGIC_BYTES};
use crate::shares::split_key;

/// Splits a directory into multiple encrypted share files using Shamir's Secret Sharing
/// and a bounded zero-RAM streaming pipeline.
pub fn split_directory<W: std::io::Write>(
    src_dir: &Path,
    mut output_files: Vec<W>,
    threshold: u8,
    total_shares: u8,
) -> Result<()> {
    if output_files.len() != total_shares as usize {
        return Err(anyhow!("Number of output files must match total_shares"));
    }

    // 1. Generate cryptographic material securely
    let mut master_key = [0u8; 32];
    OsRng.fill_bytes(&mut master_key);

    let mut bundle_id = [0u8; 16];
    OsRng.fill_bytes(&mut bundle_id);

    let mut base_nonce_prefix = [0u8; 16];
    OsRng.fill_bytes(&mut base_nonce_prefix);

    // 2. Split the master encryption key using SSSS
    let key_shares = split_key(&master_key, threshold, total_shares)?;

    // 3. Write individual V2 headers and unique key shares to each file
    for (i, file) in output_files.iter_mut().enumerate() {
        let header = ShareHeader {
            magic: *MAGIC_BYTES,
            version: FORMAT_VERSION,
            bundle_id,
            total_shares,
            threshold,
            share_index: (i + 1) as u8,
            base_nonce_prefix,
            ssss_share_data: key_shares[i].clone(),
        };
        
        header.write_to(&mut *file)?;
    }

    // 4. Start the bounded in-memory archiver (1 MB chunks)
    let rx = stream_directory_to_memory(src_dir, 1024 * 1024);

    // 5. Stream the chunks through the AEAD cipher and broadcast to all files
    encrypt_pipeline(rx, output_files, &master_key, bundle_id, base_nonce_prefix)
        .map_err(|e| anyhow!("Encryption pipeline failed: {}", e))?;

    Ok(())
}