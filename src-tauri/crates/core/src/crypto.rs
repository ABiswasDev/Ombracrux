use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use std::io::{Read, Write};
use zeroize::Zeroize;

// Process files in 1MB chunks to keep memory usage low and stable
const CHUNK_SIZE: usize = 1024 * 1024;

/// Generates a cryptographically secure random 256-bit (32-byte) key
pub fn generate_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Generates a cryptographically secure random 192-bit (24-byte) extended nonce
pub fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Safely increments the nonce for each chunk to prevent key-stream reuse
fn increment_nonce(nonce: &mut [u8; 24]) {
    for byte in nonce.iter_mut().rev() {
        let (new_byte, overflow) = byte.overflowing_add(1);
        *byte = new_byte;
        if !overflow {
            break;
        }
    }
}

/// Encrypts a data stream in chunks, authenticating each chunk to prevent tampering.
pub fn encrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key_bytes: &[u8; 32],
    base_nonce_bytes: &[u8; 24],
) -> Result<()> {
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce_bytes = *base_nonce_bytes;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut chunk_index: u64 = 0;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break; // End of file reached
        }

        let nonce = XNonce::from_slice(&nonce_bytes);

        // Bind the chunk index to the encryption as Associated Data (AAD).
        // This makes it cryptographically impossible for an attacker to reorder chunks.
        let aad = chunk_index.to_le_bytes();
        let payload = Payload {
            msg: &buffer[..bytes_read],
            aad: &aad,
        };

        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow!("Encryption failed at chunk {}: {:?}", chunk_index, e))?;

        // Write the chunk length (4 bytes, little-endian) so the decryptor knows how much to read
        let len = ciphertext.len() as u32;
        writer.write_all(&len.to_le_bytes())?;

        // Write the actual ciphertext and its appended 16-byte MAC tag
        writer.write_all(&ciphertext)?;

        increment_nonce(&mut nonce_bytes);
        chunk_index += 1;
    }

    // Securely wipe the nonce from RAM when finished
    nonce_bytes.zeroize();
    Ok(())
}

/// Decrypts an authenticated data stream. Fails immediately if any chunk is altered.
pub fn decrypt_stream<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    key_bytes: &[u8; 32],
    base_nonce_bytes: &[u8; 24],
) -> Result<()> {
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce_bytes = *base_nonce_bytes;
    let mut chunk_index: u64 = 0;

    loop {
        let mut len_buf = [0u8; 4];
        let bytes_read = reader.read(&mut len_buf)?;
        if bytes_read == 0 {
            break; // End of file reached
        }
        if bytes_read < 4 {
            return Err(anyhow!("Unexpected EOF while reading chunk length. File may be truncated."));
        }

        let chunk_len = u32::from_le_bytes(len_buf) as usize;
        
        // Sanity check: prevent memory exhaustion attacks from maliciously altered length headers
        if chunk_len > CHUNK_SIZE + 16 {
            return Err(anyhow!("Chunk size {} exceeds maximum allowed bounds.", chunk_len));
        }

        let mut ciphertext = vec![0u8; chunk_len];
        reader.read_exact(&mut ciphertext)?;

        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = chunk_index.to_le_bytes();
        let payload = Payload {
            msg: &ciphertext,
            aad: &aad,
        };

        // Decryption automatically verifies the Poly1305 MAC tag
        let plaintext = cipher.decrypt(nonce, payload).map_err(|_| {
            anyhow!("Decryption failed at chunk {}! The data is corrupted or has been tampered with.", chunk_index)
        })?;

        writer.write_all(&plaintext)?;

        increment_nonce(&mut nonce_bytes);
        chunk_index += 1;
    }

    nonce_bytes.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_encrypt_decrypt_stream_success() {
        let data = b"Hello Ombracrux! This is a test of the AEAD streaming architecture.";
        let key = generate_key();
        let nonce = generate_nonce();

        // Encrypt
        let mut encrypted_buffer = Vec::new();
        encrypt_stream(Cursor::new(data), &mut encrypted_buffer, &key, &nonce).unwrap();

        // Decrypt
        let mut decrypted_buffer = Vec::new();
        decrypt_stream(Cursor::new(encrypted_buffer), &mut decrypted_buffer, &key, &nonce).unwrap();

        assert_eq!(data.as_slice(), decrypted_buffer.as_slice());
    }

    #[test]
    fn test_tamper_detection_fails_safely() {
        let data = b"Highly sensitive vault data.";
        let key = generate_key();
        let nonce = generate_nonce();

        let mut encrypted_buffer = Vec::new();
        encrypt_stream(Cursor::new(data), &mut encrypted_buffer, &key, &nonce).unwrap();

        // Simulate tampering by flipping a single bit in the ciphertext
        let last_idx = encrypted_buffer.len() - 1;
        encrypted_buffer[last_idx] ^= 1;

        let mut decrypted_buffer = Vec::new();
        let result = decrypt_stream(Cursor::new(encrypted_buffer), &mut decrypted_buffer, &key, &nonce);

        // The test explicitly expects an error here. If it succeeds, the cryptography is broken.
        assert!(result.is_err(), "Decryption should have failed due to tampered ciphertext!");
    }
}