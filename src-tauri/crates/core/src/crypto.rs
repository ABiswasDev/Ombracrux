use crate::archive::ArchiveMessage;
use crate::format::FORMAT_VERSION;

use byteorder::{BigEndian, WriteBytesExt};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use std::io::{self, Write};
use std::sync::mpsc::Receiver;

const CHUNK_SIZE: usize = 1024 * 1024;
const AEAD_TAG_SIZE: usize = 16;

fn derive_nonce(prefix: &[u8; 16], chunk_index: u64) -> XNonce {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..16].copy_from_slice(prefix);
    nonce_bytes[16..].copy_from_slice(&chunk_index.to_be_bytes());

    *XNonce::from_slice(&nonce_bytes)
}

/// Authenticated data layout:
/// version | bundle ID | chunk index | plaintext chunk length
/// | total plaintext length | final-record flag
///
/// For data chunks, total plaintext length is zero and final flag is zero.
/// For the final record, chunk length is zero, total length is populated,
/// and final flag is one.
fn construct_aad(
    bundle_id: &[u8; 16],
    chunk_index: u64,
    plaintext_len: u32,
    total_plaintext_len: u64,
    is_final: bool,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(39);

    aad.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    aad.extend_from_slice(bundle_id);
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(&total_plaintext_len.to_be_bytes());
    aad.push(u8::from(is_final));

    aad
}

fn write_frame<W: Write>(output_shares: &mut [W], ciphertext: &[u8]) -> io::Result<()> {
    let length = u32::try_from(ciphertext.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Encrypted frame is too large"))?;

    for file in output_shares.iter_mut() {
        file.write_u32::<BigEndian>(length)?;
        file.write_all(ciphertext)?;
    }

    Ok(())
}

/// Encrypts the bounded archive stream and broadcasts each encrypted
/// frame to all output shares.
///
/// A stream is successful only when an explicit ArchiveMessage::End
/// is received and its authenticated final record is written.
/// Disconnection or an archive error is a failure.
pub fn encrypt_pipeline<W: Write>(
    rx: Receiver<ArchiveMessage>,
    mut output_shares: Vec<W>,
    master_key: &[u8; 32],
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
) -> Result<(), Box<dyn std::error::Error>> {
    if output_shares.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "At least one output share is required",
        )
        .into());
    }

    let cipher = XChaCha20Poly1305::new(master_key.into());

    let mut chunk_index: u64 = 0;
    let mut total_plaintext_len: u64 = 0;

    loop {
        match rx.recv() {
            Ok(ArchiveMessage::Chunk(plaintext)) => {
                if plaintext.is_empty() || plaintext.len() > CHUNK_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Invalid plaintext chunk size",
                    )
                    .into());
                }

                let plaintext_len = u32::try_from(plaintext.len())?;

                let aad = construct_aad(&bundle_id, chunk_index, plaintext_len, 0, false);

                let nonce = derive_nonce(&base_nonce_prefix, chunk_index);

                let ciphertext = cipher
                    .encrypt(
                        &nonce,
                        Payload {
                            msg: &plaintext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "Chunk encryption failed")
                    })?;

                write_frame(&mut output_shares, &ciphertext)?;

                total_plaintext_len = total_plaintext_len
                    .checked_add(plaintext.len() as u64)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Plaintext stream length overflow",
                        )
                    })?;

                chunk_index = chunk_index.checked_add(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Chunk counter overflow")
                })?;
            }

            Ok(ArchiveMessage::End) => {
                // The final record authenticates the number of data chunks
                // and the total plaintext archive length. It encrypts an
                // empty plaintext, so its ciphertext consists of the tag.
                let final_aad =
                    construct_aad(&bundle_id, chunk_index, 0, total_plaintext_len, true);

                let final_nonce = derive_nonce(&base_nonce_prefix, chunk_index);

                let final_ciphertext = cipher
                    .encrypt(
                        &final_nonce,
                        Payload {
                            msg: &[],
                            aad: &final_aad,
                        },
                    )
                    .map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Final-record authentication failed",
                        )
                    })?;

                if final_ciphertext.len() != AEAD_TAG_SIZE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unexpected final-record size",
                    )
                    .into());
                }

                write_frame(&mut output_shares, &final_ciphertext)?;
                break;
            }

            Ok(ArchiveMessage::Error(message)) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Archive creation failed: {message}"),
                )
                .into());
            }

            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Archive producer stopped without an explicit End message",
                )
                .into());
            }
        }
    }

    for file in output_shares.iter_mut() {
        file.flush()?;
    }

    Ok(())
}
