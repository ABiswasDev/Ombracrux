use anyhow::{anyhow, Result};
use rand::{rngs::OsRng, RngCore};
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

use crate::archive::stream_directory_to_memory;
use crate::crypto::encrypt_pipeline;
use crate::format::{ShareHeader, FORMAT_VERSION, MAGIC_BYTES};
use crate::shares::split_key;

pub fn split_directory<W: Write>(
    src_dir: &Path,
    mut output_files: Vec<W>,
    threshold: u8,
    total_shares: u8,
) -> Result<()> {
    if !src_dir.is_dir() {
        return Err(anyhow!("The selected source path is not a directory"));
    }

    if total_shares == 0 || threshold == 0 || threshold > total_shares {
        return Err(anyhow!(
            "Invalid threshold parameters: require 1 <= threshold <= total shares"
        ));
    }

    if output_files.len() != total_shares as usize {
        return Err(anyhow!("Number of output files must match total_shares"));
    }

    let mut master_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *master_key);

    let mut bundle_id = [0u8; 16];
    OsRng.fill_bytes(&mut bundle_id);

    let mut base_nonce_prefix = [0u8; 16];
    OsRng.fill_bytes(&mut base_nonce_prefix);

    let key_shares = split_key(&*master_key, threshold, total_shares)?;

    for (index, file) in output_files.iter_mut().enumerate() {
        let share_index = u8::try_from(index + 1)
            .map_err(|_| anyhow!("Share index exceeds the supported range"))?;

        let header = ShareHeader {
            magic: *MAGIC_BYTES,
            version: FORMAT_VERSION,
            bundle_id,
            total_shares,
            threshold,
            share_index,
            base_nonce_prefix,
            ssss_share_data: key_shares[index].clone(),
        };

        header.write_to(&mut *file)?;
    }

    // 1 MiB archive chunks with a channel capacity of two.
    // No plaintext TAR intermediate is written to disk.
    let receiver = stream_directory_to_memory(src_dir, 1024 * 1024);

    encrypt_pipeline(
        receiver,
        output_files,
        &*master_key,
        bundle_id,
        base_nonce_prefix,
    )
    .map_err(|error| anyhow!("Encryption pipeline failed: {error}"))?;

    Ok(())
}
