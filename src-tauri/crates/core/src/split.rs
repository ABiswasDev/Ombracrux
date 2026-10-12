use anyhow::{anyhow, Result};
use rand::RngCore;
use std::io::{Read, Write};

use crate::crypto::{encrypt_stream, generate_key, generate_nonce};
use crate::format::ShareHeader;
use crate::shares::split_key;

/// A simple utility to write identical data to multiple streams simultaneously.
struct MultiWriter<'a, W: Write> {
    writers: &'a mut [W],
}

impl<'a, W: Write> Write for MultiWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        for writer in self.writers.iter_mut() {
            writer.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        for writer in self.writers.iter_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}

/// Splits an input stream into multiple encrypted share streams.
pub fn split_file<R: Read, W: Write>(
    mut input: R,
    mut outputs: Vec<W>,
    threshold: u8,
    total_shares: u8,
) -> Result<()> {
    if outputs.len() != total_shares as usize {
        return Err(anyhow!("Number of output streams must match total_shares"));
    }

    // 1. Generate cryptographic material
    let key = generate_key();
    let nonce = generate_nonce();
    
    let mut bundle_id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bundle_id);

    let mut header = ShareHeader::new(threshold, total_shares);
    header.bundle_id = bundle_id;

    // 2. Split the encryption key
    let key_shares = split_key(&key, threshold, total_shares)?;

    // 3. Write individual headers, unique key shares, and the shared nonce to each output
    for (i, writer) in outputs.iter_mut().enumerate() {
        let share_bytes = &key_shares[i];
        
        // Write 27-byte header
        writer.write_all(&header.to_bytes())?;
        
        // Write share length (2 bytes, little-endian) and the actual share payload
        let share_len = share_bytes.len() as u16;
        writer.write_all(&share_len.to_le_bytes())?;
        writer.write_all(share_bytes)?;
        
        // Write 24-byte AEAD nonce
        writer.write_all(&nonce)?;
    }

    // 4. Stream the input file, encrypt it exactly once, and write simultaneously to all outputs
    let multi_writer = MultiWriter { writers: &mut outputs };
    encrypt_stream(&mut input, multi_writer, &key, &nonce)?;

    Ok(())
}