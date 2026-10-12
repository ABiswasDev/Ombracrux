use anyhow::{anyhow, Result};
use std::io::{Read, Write};

use crate::crypto::decrypt_stream;
use crate::format::{ShareHeader, HEADER_SIZE};
use crate::shares::reconstruct_key;

/// Restores an original file from a collection of share streams.
pub fn restore_file<R: Read, W: Write>(
    mut inputs: Vec<R>,
    mut output: W,
) -> Result<()> {
    if inputs.is_empty() {
        return Err(anyhow!("No input shares provided for restoration."));
    }

    let mut key_shares = Vec::new();
    let mut expected_bundle_id = None;
    let mut expected_threshold = 0;
    let mut expected_nonce = None;

    // 1. Read and validate all headers and extract the key shares
    for (index, reader) in inputs.iter_mut().enumerate() {
        // Read header
        let mut header_buf = [0u8; HEADER_SIZE];
        reader.read_exact(&mut header_buf)
            .map_err(|_| anyhow!("Failed to read header from share index {}. File may be too small.", index))?;
        
        let header = ShareHeader::from_bytes(&header_buf)?;

        // Verify bundle matching (prevents mixing shares from different backups)
        if let Some(expected_id) = expected_bundle_id {
            if header.bundle_id != expected_id {
                return Err(anyhow!("Bundle ID mismatch! You are mixing shares from different backups."));
            }
        } else {
            expected_bundle_id = Some(header.bundle_id);
            expected_threshold = header.threshold;
        }

        // Read share length
        let mut len_buf = [0u8; 2];
        reader.read_exact(&mut len_buf)?;
        let share_len = u16::from_le_bytes(len_buf) as usize;

        // Read share bytes
        let mut share_bytes = vec![0u8; share_len];
        reader.read_exact(&mut share_bytes)?;
        key_shares.push(share_bytes);

        // Read nonce
        let mut nonce = [0u8; 24];
        reader.read_exact(&mut nonce)?;

        if let Some(expected_n) = expected_nonce {
            if nonce != expected_n {
                return Err(anyhow!("Nonce mismatch across shares. Shares may be corrupted."));
            }
        } else {
            expected_nonce = Some(nonce);
        }
    }

    // 2. Enforce the threshold barrier
    if key_shares.len() < expected_threshold as usize {
        return Err(anyhow!(
            "Insufficient shares. Provided {}, required {}.",
            key_shares.len(),
            expected_threshold
        ));
    }

    // 3. Reconstruct the XChaCha20 encryption key
    let encryption_key = reconstruct_key(&key_shares, expected_threshold)?;
    let nonce = expected_nonce.unwrap(); // Guaranteed to be set if we reached here

    // 4. Decrypt the payload using the FIRST provided stream.
    // (All valid shares contain the identical encrypted payload, so we only need to stream from one).
    let primary_reader = &mut inputs[0];
    decrypt_stream(primary_reader, &mut output, &encryption_key, &nonce)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::split_file;
    use std::io::Cursor;

    #[test]
    fn test_end_to_end_split_and_restore() {
        let original_data = b"This is the highly confidential payload that needs threshold recovery. It represents a large file.";
        let threshold = 3;
        let total_shares = 5;

        // Mock 5 output files in memory
        let mut out1 = Vec::new();
        let mut out2 = Vec::new();
        let mut out3 = Vec::new();
        let mut out4 = Vec::new();
        let mut out5 = Vec::new();

        // 1. SPLIT: Write to all 5 "files" simultaneously
        let writers: Vec<&mut Vec<u8>> = vec![&mut out1, &mut out2, &mut out3, &mut out4, &mut out5];
        split_file(Cursor::new(original_data), writers, threshold, total_shares).unwrap();

        // Ensure data was actually written
        assert!(!out1.is_empty());

        // 2. RESTORE: Intentionally drop 2 shares and attempt to restore using only shares 2, 4, and 5
        let readers: Vec<&[u8]> = vec![out2.as_slice(), out4.as_slice(), out5.as_slice()];
        let mut restored_data = Vec::new();
        
        restore_file(readers, &mut restored_data).unwrap();

        // 3. VERIFY: The recovered file must perfectly match the input
        assert_eq!(original_data.as_slice(), restored_data.as_slice());
    }
}