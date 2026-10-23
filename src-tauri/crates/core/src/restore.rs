use crate::format::FORMAT_VERSION;

use byteorder::{BigEndian, ReadBytesExt};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

const CHUNK_SIZE: usize = 1024 * 1024;
const AEAD_TAG_SIZE: usize = 16;
const MAX_CIPHERTEXT_SIZE: usize = CHUNK_SIZE + AEAD_TAG_SIZE;

/// Distinguishes recoverable share/payload corruption from unrecoverable
/// destination filesystem errors so multi-share failover only retries when
/// another share could succeed.
#[derive(Debug)]
pub enum RestoreError {
    PayloadOrArchive(io::Error),
    Destination(io::Error),
}

impl RestoreError {
    pub fn is_recoverable_with_another_share(&self) -> bool {
        matches!(self, RestoreError::PayloadOrArchive(_))
    }
}

impl fmt::Display for RestoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RestoreError::PayloadOrArchive(err) => write!(f, "{err}"),
            RestoreError::Destination(err) => write!(f, "Destination error: {err}"),
        }
    }
}

impl std::error::Error for RestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RestoreError::PayloadOrArchive(err) | RestoreError::Destination(err) => Some(err),
        }
    }
}

fn is_destination_io_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied
            | io::ErrorKind::StorageFull
            | io::ErrorKind::ReadOnlyFilesystem
            | io::ErrorKind::AlreadyExists
            | io::ErrorKind::WriteZero
    )
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

struct DecryptReader<R: Read> {
    reader: R,
    cipher: XChaCha20Poly1305,
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
    chunk_index: u64,
    total_plaintext_len: u64,
    buffer: Vec<u8>,
    buffer_pos: usize,
    final_seen: bool,
    stream_failed: bool,
}

impl<R: Read> DecryptReader<R> {
    fn new(
        reader: R,
        master_key: &[u8; 32],
        bundle_id: [u8; 16],
        base_nonce_prefix: [u8; 16],
    ) -> Self {
        Self {
            reader,
            cipher: XChaCha20Poly1305::new(master_key.into()),
            bundle_id,
            base_nonce_prefix,
            chunk_index: 0,
            total_plaintext_len: 0,
            buffer: Vec::new(),
            buffer_pos: 0,
            final_seen: false,
            stream_failed: false,
        }
    }

    fn read_next_frame(&mut self) -> io::Result<bool> {
        let frame_len = match self.reader.read_u32::<BigEndian>() {
            Ok(length) => length as usize,
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                self.stream_failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Missing final record or truncated frame length",
                ));
            }
            Err(error) => {
                self.stream_failed = true;
                return Err(error);
            }
        };

        if frame_len < AEAD_TAG_SIZE || frame_len > MAX_CIPHERTEXT_SIZE {
            self.stream_failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid encrypted frame length",
            ));
        }

        let mut ciphertext = vec![0u8; frame_len];
        if let Err(error) = self.reader.read_exact(&mut ciphertext) {
            self.stream_failed = true;
            return Err(error);
        }

        // A frame containing only the authentication tag represents the
        // dedicated final record. It is not a data chunk.
        if frame_len == AEAD_TAG_SIZE {
            let final_aad = construct_aad(
                &self.bundle_id,
                self.chunk_index,
                0,
                self.total_plaintext_len,
                true,
            );

            let final_nonce = derive_nonce(&self.base_nonce_prefix, self.chunk_index);

            let plaintext = self
                .cipher
                .decrypt(
                    &final_nonce,
                    Payload {
                        msg: &ciphertext,
                        aad: &final_aad,
                    },
                )
                .map_err(|_| {
                    self.stream_failed = true;
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Final-record authentication failed",
                    )
                })?;

            if !plaintext.is_empty() {
                self.stream_failed = true;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Final record unexpectedly contains data",
                ));
            }

            // The final record must be the last item in the share stream.
            let mut trailing = [0u8; 1];
            match self.reader.read(&mut trailing) {
                Ok(0) => {}
                Ok(_) => {
                    self.stream_failed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Unexpected data found after the final record",
                    ));
                }
                Err(error) => {
                    self.stream_failed = true;
                    return Err(error);
                }
            }

            self.final_seen = true;
            return Ok(false);
        }

        let plaintext_len = frame_len - AEAD_TAG_SIZE;

        if plaintext_len == 0 || plaintext_len > CHUNK_SIZE {
            self.stream_failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid plaintext chunk length",
            ));
        }

        let aad = construct_aad(
            &self.bundle_id,
            self.chunk_index,
            plaintext_len as u32,
            0,
            false,
        );

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
                self.stream_failed = true;
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Chunk authentication failed: data may be corrupted or tampered with",
                )
            })?;

        if plaintext.len() != plaintext_len {
            self.stream_failed = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Authenticated chunk length mismatch",
            ));
        }

        self.total_plaintext_len = self
            .total_plaintext_len
            .checked_add(plaintext.len() as u64)
            .ok_or_else(|| {
                self.stream_failed = true;
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Plaintext stream length overflow",
                )
            })?;

        self.chunk_index = self.chunk_index.checked_add(1).ok_or_else(|| {
            self.stream_failed = true;
            io::Error::new(io::ErrorKind::InvalidData, "Chunk counter overflow")
        })?;

        self.buffer = plaintext;
        self.buffer_pos = 0;

        Ok(true)
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        loop {
            if self.buffer_pos < self.buffer.len() {
                let available = self.buffer.len() - self.buffer_pos;
                let count = available.min(output.len());

                output[..count]
                    .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + count]);

                self.buffer_pos += count;
                return Ok(count);
            }

            self.buffer.clear();
            self.buffer_pos = 0;

            if self.final_seen {
                return Ok(0);
            }

            if !self.read_next_frame()? {
                return Ok(0);
            }
        }
    }
}

fn create_private_staging_dir(output_root: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let mut rng = rand::thread_rng();

    for _ in 0..32 {
        let mut random_bytes = [0u8; 16];
        rng.fill_bytes(&mut random_bytes);

        let suffix = random_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("");

        let staging_path = output_root.join(format!(".ombracrx-restore-{suffix}.tmp"));
        let final_path = output_root.join(format!("Ombracrux-Restored-{suffix}"));

        if final_path.exists() {
            continue;
        }

        let mut builder = fs::DirBuilder::new();

        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }

        match builder.create(&staging_path) {
            Ok(()) => return Ok((staging_path, final_path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "Could not create a unique restoration staging directory",
    ))
}

/// Restores an archive into a private staging directory and classifies
/// whether any failure was caused by share/archive corruption or by the
/// destination filesystem.
pub fn restore_pipeline_classified<R: Read>(
    share_file: R,
    master_key: &[u8; 32],
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
    output_root: &Path,
) -> Result<PathBuf, RestoreError> {
    if !output_root.is_dir() {
        return Err(RestoreError::Destination(io::Error::new(
            io::ErrorKind::InvalidInput,
            "The restoration output location must be an existing directory",
        )));
    }

    let (staging_path, final_path) =
        create_private_staging_dir(output_root).map_err(RestoreError::Destination)?;

    let mut decrypt_stream =
        DecryptReader::new(share_file, master_key, bundle_id, base_nonce_prefix);

    let unpack_result: io::Result<()> = (|| {
        // The TAR reader may stop after the TAR end markers. The explicit
        // drain below is therefore required to authenticate the entire
        // encrypted stream, including its final record.
        {
            let mut archive = tar::Archive::new(&mut decrypt_stream);
            archive.unpack(&staging_path)?;
        }

        // Do not publish the staged files unless every chunk and the
        // authenticated final record have been read and validated.
        io::copy(&mut decrypt_stream, &mut io::sink())?;

        Ok(())
    })();

    if let Err(error) = unpack_result {
        let _ = fs::remove_dir_all(&staging_path);
        if decrypt_stream.stream_failed {
            return Err(RestoreError::PayloadOrArchive(error));
        }
        if is_destination_io_error(&error) {
            return Err(RestoreError::Destination(error));
        }
        return Err(RestoreError::PayloadOrArchive(error));
    }

    // Both paths are inside output_root, so this is a same-filesystem
    // directory rename. The final path is unique and is checked before use.
    if final_path.exists() {
        let _ = fs::remove_dir_all(&staging_path);

        return Err(RestoreError::Destination(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Restoration destination already exists",
        )));
    }

    if let Err(error) = fs::rename(&staging_path, &final_path) {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(RestoreError::Destination(error));
    }

    Ok(final_path)
}

/// Restores an archive into a private staging directory.
///
/// `output_root` is the existing folder selected by the user. The
/// fully authenticated result is published as a new child directory.
pub fn restore_pipeline<R: Read>(
    share_file: R,
    master_key: &[u8; 32],
    bundle_id: [u8; 16],
    base_nonce_prefix: [u8; 16],
    output_root: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    restore_pipeline_classified(
        share_file,
        master_key,
        bundle_id,
        base_nonce_prefix,
        output_root,
    )
    .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
}
