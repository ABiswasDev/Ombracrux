use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use byteorder::{BigEndian, ReadBytesExt};
use rand::RngCore;
use std::fs::{self};
use std::io::{self, Read};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Derives the identical Nonce used during encryption.
fn derive_nonce(prefix: &[u8; 16], chunk_idx: u64) -> XNonce {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..16].copy_from_slice(prefix);
    nonce_bytes[16..].copy_from_slice(&chunk_idx.to_be_bytes());
    *XNonce::from_slice(&nonce_bytes)
}

/// Constructs the exact Associated Data to validate sequence and integrity.
fn construct_aad(bundle_id: &[u8; 16], chunk_idx: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(25);
    aad.extend_from_slice(bundle_id);
    aad.extend_from_slice(&chunk_idx.to_be_bytes());
    aad.push(if is_final { 1 } else { 0 });
    aad
}

/// A custom streaming reader that decrypts XChaCha20 chunks on the fly.
/// This prevents loading massive files into RAM during restoration.
struct DecryptReader<R: Read> {
    reader: R,
    cipher: XChaCha20Poly1305,
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
    chunk_index: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    is_eof: bool,
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // Yield remaining bytes from the currently decrypted chunk
        if self.buffer_pos < self.buffer.len() {
            let len = std::cmp::min(buf.len(), self.buffer.len() - self.buffer_pos);
            buf[..len].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + len]);
            self.buffer_pos += len;
            return Ok(len);
        }

        if self.is_eof {
            return Ok(0);
        }

        // Read the exact size of the next incoming chunk
        let chunk_len = match self.reader.read_u32::<BigEndian>() {
            Ok(len) => len,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                self.is_eof = true;
                return Ok(0);
            }
            Err(e) => return Err(e),
        };

        // Hard cap at 1MB + 16 bytes MAC to prevent RAM exhaustion attacks
        if chunk_len > 1024 * 1024 + 16 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Chunk exceeds maximum allowed size"));
        }

        let mut ciphertext = vec![0u8; chunk_len as usize];
        self.reader.read_exact(&mut ciphertext)?;

        let nonce = derive_nonce(&self.base_nonce_prefix, self.chunk_index);
        
        let aad_standard = construct_aad(&self.bundle_id, self.chunk_index, false);
        let aad_final = construct_aad(&self.bundle_id, self.chunk_index, true);

        // Try decrypting as a standard chunk first. If Poly1305 authentication fails, 
        // try decrypting it as the final chunk. If both fail, the file is corrupted/tampered.
        let payload_standard = Payload { msg: &ciphertext, aad: &aad_standard };
        let decrypted = match self.cipher.decrypt(&nonce, payload_standard) {
            Ok(pt) => pt,
            Err(_) => {
                let payload_final = Payload { msg: &ciphertext, aad: &aad_final };
                match self.cipher.decrypt(&nonce, payload_final) {
                    Ok(pt) => {
                        self.is_eof = true; 
                        pt
                    },
                    Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData, "Poly1305 Authentication Failed: Corrupted or tampered share")),
                }
            }
        };

        self.buffer = decrypted;
        self.buffer_pos = 0;
        self.chunk_index += 1;

        // Recursively return the newly decrypted bytes
        self.read(buf)
    }
}

/// Executes the full, safe restoration pipeline.
pub fn restore_pipeline<R: Read>(
    share_file: R,
    master_key: &[u8; 32],
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
    target_dest: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    
    // 1. Generate a unique, isolated staging directory
    let mut rng = rand::thread_rng();
    let staging_dir_name = format!(".ombracrx-restore-{:016x}", rng.next_u64());
    let staging_path = target_dest.parent().unwrap_or(Path::new(".")).join(staging_dir_name);

    fs::create_dir_all(&staging_path)?;

    // 2. Lock down permissions strictly to the current user
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&staging_path)?.permissions();
        perms.set_mode(0o700); // rwx------
        fs::set_permissions(&staging_path, perms)?;
    }

    // 3. Initialize the DecryptReader
    let cipher = XChaCha20Poly1305::new(master_key.into());
    let decrypt_stream = DecryptReader {
        reader: share_file,
        cipher,
        bundle_id,
        base_nonce_prefix,
        chunk_index: 0,
        buffer: Vec::new(),
        buffer_pos: 0,
        is_eof: false,
    };

    // 4. Pipe the decrypted stream directly into the tar unpacker
    let mut archive = tar::Archive::new(decrypt_stream);
    
    // 5. Execute extraction. If ANY cryptographic check fails mid-stream, 
    // it triggers an error and we instantly jump to the cleanup block.
    match archive.unpack(&staging_path) {
        Ok(_) => {
            // Success: Atomically commit the staging folder to the final destination
            fs::rename(&staging_path, target_dest)?;
            Ok(())
        }
        Err(e) => {
            // Failure: Shred the partially extracted, unverified files
            let _ = fs::remove_dir_all(&staging_path);
            Err(Box::new(e))
        }
    }
}