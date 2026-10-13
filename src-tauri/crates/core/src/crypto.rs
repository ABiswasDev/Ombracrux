use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::io;
use std::sync::mpsc::Receiver;
use byteorder::{BigEndian, WriteBytesExt};

/// Constructs the 24-byte XChaCha20 Nonce: [16-byte Prefix] + [8-byte u64 Chunk Index]
fn derive_nonce(prefix: &[u8; 16], chunk_idx: u64) -> XNonce {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..16].copy_from_slice(prefix);
    nonce_bytes[16..].copy_from_slice(&chunk_idx.to_be_bytes());
    XNonce::from(nonce_bytes)
}

/// Constructs the Associated Data to bind the chunk to its exact position and file.
fn construct_aad(bundle_id: &[u8; 16], chunk_idx: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(25);
    aad.extend_from_slice(bundle_id);
    aad.extend_from_slice(&chunk_idx.to_be_bytes());
    aad.push(if is_final { 1 } else { 0 });
    aad
}

/// Consumes the plaintext Tarball stream and broadcasts it to N authenticated shares.
pub fn encrypt_pipeline<W: std::io::Write>(
    rx: Receiver<Vec<u8>>,
    mut output_shares: Vec<W>,
    master_key: &[u8; 32],
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
) -> Result<(), Box<dyn std::error::Error>> {
    
    let cipher = XChaCha20Poly1305::new(master_key.into());
    let mut chunk_index: u64 = 0;

    // We buffer exactly one chunk ahead so we can accurately detect the `is_final` state.
    let mut current_chunk = rx.recv().ok();

    while let Some(plaintext) = current_chunk {
        let next_chunk = rx.recv().ok();
        let is_final = next_chunk.is_none();

        let nonce = derive_nonce(&base_nonce_prefix, chunk_index);
        let aad = construct_aad(&bundle_id, chunk_index, is_final);

        let payload = Payload {
            msg: &plaintext,
            aad: &aad,
        };

        // Encrypts the chunk and appends the 16-byte Poly1305 tag automatically.
        let ciphertext = cipher.encrypt(&nonce, payload)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Encryption failed"))?;

        // Broadcast to all N files simultaneously
        for file in output_shares.iter_mut() {
            file.write_u32::<BigEndian>(ciphertext.len() as u32)?;
            file.write_all(&ciphertext)?;
        }

        current_chunk = next_chunk;
        chunk_index += 1;
    }

    for file in output_shares.iter_mut() {
        file.flush()?;
    }

    Ok(())
}