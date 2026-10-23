use crate::format::FORMAT_VERSION;
use byteorder::{BigEndian, ReadBytesExt};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::io::{self, Read};
use std::path::Component;
use tar::Archive;

const CHUNK_SIZE: usize = 1024 * 1024;
const AEAD_TAG_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    pub files_verified: u64,
    pub dirs_verified: u64,
    pub plaintext_bytes_verified: u64,
    pub chunks_verified: u64,
}

fn derive_nonce(prefix: &[u8; 16], chunk_index: u64) -> XNonce {
    let mut nonce_bytes = [0u8; 24];
    nonce_bytes[..16].copy_from_slice(prefix);
    nonce_bytes[16..].copy_from_slice(&chunk_index.to_be_bytes());

    *XNonce::from_slice(&nonce_bytes)
}

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

struct AuthenticatedVerifyReader<R: Read> {
    inner: R,
    cipher: XChaCha20Poly1305,
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
    chunk_index: u64,
    total_plaintext_len: u64,
    buffer: Vec<u8>,
    cursor: usize,
    seen_final: bool,
}

impl<R: Read> AuthenticatedVerifyReader<R> {
    fn new(
        inner: R,
        master_key: &[u8; 32],
        bundle_id: [u8; 16],
        base_nonce_prefix: [u8; 16],
    ) -> Self {
        Self {
            inner,
            cipher: XChaCha20Poly1305::new(master_key.into()),
            bundle_id,
            base_nonce_prefix,
            chunk_index: 0,
            total_plaintext_len: 0,
            buffer: Vec::new(),
            cursor: 0,
            seen_final: false,
        }
    }

    fn read_next_authenticated_chunk(&mut self) -> io::Result<bool> {
        if self.seen_final {
            return Ok(false);
        }

        let frame_len = match self.inner.read_u32::<BigEndian>() {
            Ok(len) => len as usize,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Truncated share stream: missing authenticated final record",
                ));
            }
            Err(err) => return Err(err),
        };

        if frame_len == AEAD_TAG_SIZE {
            let mut final_tag = [0u8; AEAD_TAG_SIZE];
            self.inner.read_exact(&mut final_tag)?;

            let final_aad = construct_aad(
                &self.bundle_id,
                self.chunk_index,
                0,
                self.total_plaintext_len,
                true,
            );
            let final_nonce = derive_nonce(&self.base_nonce_prefix, self.chunk_index);

            self.cipher
                .decrypt(
                    &final_nonce,
                    Payload {
                        msg: &final_tag,
                        aad: &final_aad,
                    },
                )
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Final-record authentication failed during verification",
                    )
                })?;

            // Reject any extra unauthenticated bytes appended after the final record.
            let mut extra = [0u8; 1];
            if self.inner.read(&mut extra)? != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unexpected trailing bytes after final authenticated record",
                ));
            }

            self.seen_final = true;
            self.buffer.clear();
            self.cursor = 0;
            return Ok(false);
        }

        if frame_len < AEAD_TAG_SIZE || frame_len > CHUNK_SIZE + AEAD_TAG_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid encrypted frame size in share stream",
            ));
        }

        let mut ciphertext = vec![0u8; frame_len];
        self.inner.read_exact(&mut ciphertext)?;

        let plaintext_len = u32::try_from(frame_len - AEAD_TAG_SIZE)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Plaintext length overflow"))?;

        let aad = construct_aad(&self.bundle_id, self.chunk_index, plaintext_len, 0, false);
        let nonce = derive_nonce(&self.base_nonce_prefix, self.chunk_index);

        let plaintext = self
            .cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Chunk {} failed XChaCha20-Poly1305 authentication",
                        self.chunk_index
                    ),
                )
            })?;

        self.total_plaintext_len = self
            .total_plaintext_len
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Plaintext stream size overflow")
            })?;

        self.chunk_index = self
            .chunk_index
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Chunk counter overflow"))?;

        self.buffer = plaintext;
        self.cursor = 0;
        Ok(true)
    }
}

impl<R: Read> Read for AuthenticatedVerifyReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        while self.cursor >= self.buffer.len() {
            if !self.read_next_authenticated_chunk()? {
                return Ok(0);
            }
        }

        let available = self.buffer.len() - self.cursor;
        let to_copy = available.min(out.len());
        out[..to_copy].copy_from_slice(&self.buffer[self.cursor..self.cursor + to_copy]);
        self.cursor += to_copy;
        Ok(to_copy)
    }
}

fn validate_tar_entry_path(path: &std::path::Path) -> io::Result<()> {
    if path.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Archive contains an empty entry path",
        ));
    }

    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsafe archive entry path detected: {}", path.display()),
                ));
            }
        }
    }

    Ok(())
}

/// Streams and authenticates an encrypted share payload completely in memory,
/// validating every XChaCha20-Poly1305 chunk, TAR entry header, and final EOF tag
/// without writing any files to disk.
pub fn verify_payload_stream<R: Read>(
    reader: R,
    master_key: &[u8; 32],
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
) -> Result<VerifyReport, Box<dyn std::error::Error>> {
    let mut auth_reader =
        AuthenticatedVerifyReader::new(reader, master_key, bundle_id, base_nonce_prefix);

    let mut files_verified = 0u64;
    let mut dirs_verified = 0u64;
    let mut plaintext_bytes_verified = 0u64;

    {
        let mut archive = Archive::new(&mut auth_reader);
        let entries = archive.entries()?;

        for entry_result in entries {
            let mut entry = entry_result?;
            let path = entry.path()?.into_owned();
            validate_tar_entry_path(&path)?;

            let entry_type = entry.header().entry_type();
            if entry_type.is_dir() {
                dirs_verified = dirs_verified.saturating_add(1);
            } else if entry_type.is_file() {
                files_verified = files_verified.saturating_add(1);
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported TAR entry type in archive: {}", path.display()),
                )
                .into());
            }

            let copied = io::copy(&mut entry, &mut io::sink())?;
            plaintext_bytes_verified = plaintext_bytes_verified.saturating_add(copied);
        }
    }

    // Drain any remaining TAR EOF padding blocks so the final authenticated frame
    // and trailing-byte checks are guaranteed to run.
    io::copy(&mut auth_reader, &mut io::sink())?;

    if !auth_reader.seen_final {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "Share stream ended without an authenticated final record",
        )
        .into());
    }

    Ok(VerifyReport {
        files_verified,
        dirs_verified,
        plaintext_bytes_verified,
        chunks_verified: auth_reader.chunk_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::ShareHeader;
    use crate::shares::reconstruct_key;
    use crate::split::split_directory;
    use std::fs;
    use std::io::Cursor;
    use tempfile::tempdir;

    #[test]
    fn dry_run_verify_validates_stream_without_writing_to_disk() {
        let temp = tempdir().unwrap();
        let sub = temp.path().join("nested");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("one.txt"), vec![b'a'; 1200]).unwrap();
        fs::write(temp.path().join("two.txt"), vec![b'b'; 2800]).unwrap();

        let mut buffers: Vec<Vec<u8>> = (0..3).map(|_| Vec::new()).collect();
        let writers: Vec<&mut Vec<u8>> = buffers.iter_mut().collect();
        split_directory(temp.path(), writers, 2, 3).unwrap();

        let mut c0 = Cursor::new(&buffers[0]);
        let mut c1 = Cursor::new(&buffers[1]);
        let h0 = ShareHeader::read_from(&mut c0).unwrap();
        let h1 = ShareHeader::read_from(&mut c1).unwrap();

        let key =
            reconstruct_key(&[h0.ssss_share_data.clone(), h1.ssss_share_data.clone()], 2).unwrap();
        h0.verify_auth(&key).unwrap();
        h1.verify_auth(&key).unwrap();

        let report =
            verify_payload_stream(&mut c0, &key, h0.bundle_id, h0.base_nonce_prefix).unwrap();

        assert_eq!(report.files_verified, 2);
        assert_eq!(report.dirs_verified, 1);
        assert_eq!(report.plaintext_bytes_verified, 4000);
        assert!(report.chunks_verified >= 1);
    }

    #[test]
    fn dry_run_verify_rejects_corrupted_payload_byte() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("file.txt"), b"important data").unwrap();

        let mut buffers: Vec<Vec<u8>> = (0..2).map(|_| Vec::new()).collect();
        let writers: Vec<&mut Vec<u8>> = buffers.iter_mut().collect();
        split_directory(temp.path(), writers, 2, 2).unwrap();

        // Flip a byte inside the encrypted ciphertext body of share 0
        let last_idx = buffers[0].len() - 5;
        buffers[0][last_idx] ^= 0xFF;

        let mut c0 = Cursor::new(&buffers[0]);
        let mut c1 = Cursor::new(&buffers[1]);
        let h0 = ShareHeader::read_from(&mut c0).unwrap();
        let h1 = ShareHeader::read_from(&mut c1).unwrap();

        let key =
            reconstruct_key(&[h0.ssss_share_data.clone(), h1.ssss_share_data.clone()], 2).unwrap();

        assert!(verify_payload_stream(&mut c0, &key, h0.bundle_id, h0.base_nonce_prefix).is_err());
    }
    #[test]
    fn dry_run_verify_rejects_trailing_bytes_after_final_record() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("file.txt"), b"authenticated payload").unwrap();

        let mut buffers: Vec<Vec<u8>> = (0..2).map(|_| Vec::new()).collect();
        let writers: Vec<&mut Vec<u8>> = buffers.iter_mut().collect();
        split_directory(temp.path(), writers, 2, 2).unwrap();

        // Append an extra unauthenticated byte after the final EOF frame
        buffers[0].push(0x99);

        let mut c0 = Cursor::new(&buffers[0]);
        let mut c1 = Cursor::new(&buffers[1]);
        let h0 = ShareHeader::read_from(&mut c0).unwrap();
        let h1 = ShareHeader::read_from(&mut c1).unwrap();

        let key =
            reconstruct_key(&[h0.ssss_share_data.clone(), h1.ssss_share_data.clone()], 2).unwrap();

        let err = verify_payload_stream(&mut c0, &key, h0.bundle_id, h0.base_nonce_prefix)
            .unwrap_err()
            .to_string();
        assert!(err.contains("trailing bytes"));
    }

    #[test]
    fn dry_run_verify_rejects_truncated_share_stream() {
        let temp = tempdir().unwrap();
        fs::write(temp.path().join("file.txt"), b"authenticated payload").unwrap();

        let mut buffers: Vec<Vec<u8>> = (0..2).map(|_| Vec::new()).collect();
        let writers: Vec<&mut Vec<u8>> = buffers.iter_mut().collect();
        split_directory(temp.path(), writers, 2, 2).unwrap();

        // Truncate the final 20-byte authenticated EOF frame (4B length + 16B tag)
        let truncated_len = buffers[0].len() - 20;
        buffers[0].truncate(truncated_len);

        let mut c0 = Cursor::new(&buffers[0]);
        let mut c1 = Cursor::new(&buffers[1]);
        let h0 = ShareHeader::read_from(&mut c0).unwrap();
        let h1 = ShareHeader::read_from(&mut c1).unwrap();

        let key =
            reconstruct_key(&[h0.ssss_share_data.clone(), h1.ssss_share_data.clone()], 2).unwrap();

        let err = verify_payload_stream(&mut c0, &key, h0.bundle_id, h0.base_nonce_prefix)
            .unwrap_err()
            .to_string();
        assert!(err.contains("missing authenticated final record"));
    }
}
