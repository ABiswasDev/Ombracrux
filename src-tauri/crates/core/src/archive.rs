use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread;

const CHANNEL_CAPACITY: usize = 2;

#[derive(Debug)]
pub enum ArchiveMessage {
    Chunk(Vec<u8>),
    End,
    Error(String),
}

/// Streams TAR bytes through bounded memory buffers.
///
/// The channel holds at most two queued chunks. This is not the
/// application's total memory usage: the writer and consumer also
/// have their own buffers.
pub struct ChannelWriter {
    sender: SyncSender<ArchiveMessage>,
    buffer: Vec<u8>,
    chunk_size: usize,
}

impl ChannelWriter {
    pub fn new(sender: SyncSender<ArchiveMessage>, chunk_size: usize) -> Self {
        let chunk_size = chunk_size.max(1);

        Self {
            sender,
            buffer: Vec::with_capacity(chunk_size),
            chunk_size,
        }
    }

    fn send_buffer(&mut self) -> io::Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        let chunk = std::mem::replace(&mut self.buffer, Vec::with_capacity(self.chunk_size));

        self.sender.send(ArchiveMessage::Chunk(chunk)).map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Encryption consumer stopped before archiving completed",
            )
        })
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let mut consumed = 0;

        while consumed < input.len() {
            let available = self.chunk_size - self.buffer.len();
            let count = available.min(input.len() - consumed);

            self.buffer
                .extend_from_slice(&input[consumed..consumed + count]);

            consumed += count;

            if self.buffer.len() == self.chunk_size {
                self.send_buffer()?;
            }
        }

        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send_buffer()
    }
}

fn open_verified_regular_file(path: &Path) -> io::Result<File> {
    let sym_meta = fs::symlink_metadata(path)?;
    if sym_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Symlinks are not currently supported in source directories: {}",
                path.display()
            ),
        ));
    }
    if !sym_meta.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Unsupported filesystem entry in source directory: {}",
                path.display()
            ),
        ));
    }

    let file = File::open(path)?;
    let open_meta = file.metadata()?;

    if !open_meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Source entry changed to a non-regular file during archiving: {}",
                path.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if sym_meta.dev() != open_meta.dev() || sym_meta.ino() != open_meta.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Detected concurrent file replacement during archiving: {}",
                    path.display()
                ),
            ));
        }
    }

    Ok(file)
}

fn append_directory_no_symlinks<W: Write>(
    archive: &mut tar::Builder<W>,
    root_dir: &Path,
    current_dir: &Path,
) -> io::Result<()> {
    let dir_meta = fs::symlink_metadata(current_dir)?;
    if dir_meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Symlinks are not currently supported in source directories: {}",
                current_dir.display()
            ),
        ));
    }
    if !dir_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "Expected a directory in source tree: {}",
                current_dir.display()
            ),
        ));
    }

    let mut entries: Vec<fs::DirEntry> =
        fs::read_dir(current_dir)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        let entry_path = entry.path();
        let file_type = entry.file_type()?;

        if file_type.is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Symlinks are not currently supported in source directories: {}",
                    entry_path.display()
                ),
            ));
        }

        let rel_path = entry_path
            .strip_prefix(root_dir)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;

        if file_type.is_dir() {
            archive.append_dir(rel_path, &entry_path)?;
            append_directory_no_symlinks(archive, root_dir, &entry_path)?;
        } else if file_type.is_file() {
            let mut file = open_verified_regular_file(&entry_path)?;
            archive.append_file(rel_path, &mut file)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Unsupported filesystem entry in source directory: {}",
                    entry_path.display()
                ),
            ));
        }
    }

    Ok(())
}

/// Builds a TAR archive directly into a bounded in-memory channel.
///
/// No plaintext TAR file is created on disk, and symbolic links are
/// strictly rejected during traversal. The receiver must require an
/// explicit End message; channel disconnection alone is never
/// considered successful completion.
pub fn stream_directory_to_memory(src_dir: &Path, chunk_size: usize) -> Receiver<ArchiveMessage> {
    let (tx, rx) = sync_channel::<ArchiveMessage>(CHANNEL_CAPACITY);
    let status_tx = tx.clone();
    let src_dir = src_dir.to_path_buf();
    let chunk_size = chunk_size.max(1);

    thread::spawn(move || {
        let writer = ChannelWriter::new(tx, chunk_size);
        let mut archive = tar::Builder::new(writer);
        archive.follow_symlinks(false);

        if let Err(error) = append_directory_no_symlinks(&mut archive, &src_dir, &src_dir) {
            let _ = status_tx.send(ArchiveMessage::Error(format!(
                "Failed to archive directory: {error}"
            )));
            return;
        }

        let mut writer = match archive.into_inner() {
            Ok(writer) => writer,
            Err(error) => {
                let _ = status_tx.send(ArchiveMessage::Error(format!(
                    "Failed to finish TAR archive: {error}"
                )));
                return;
            }
        };

        if let Err(error) = writer.flush() {
            let _ = status_tx.send(ArchiveMessage::Error(format!(
                "Failed to flush TAR stream: {error}"
            )));
            return;
        }

        // End is sent only after the TAR archive has finished
        // and all buffered archive bytes have been delivered.
        let _ = status_tx.send(ArchiveMessage::End);
    });

    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn archive_stream_rejects_symlinks_in_source_directory() {
        use std::os::unix::fs::symlink;

        let temp = tempdir().unwrap();
        let outside = temp.path().join("outside.txt");
        let source = temp.path().join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(&outside, b"secret outside file").unwrap();

        let link_path = source.join("escape_link.txt");
        symlink(&outside, &link_path).unwrap();

        let rx = stream_directory_to_memory(&source, 64 * 1024);

        let mut saw_error = false;
        let mut saw_end = false;

        while let Ok(msg) = rx.recv() {
            match msg {
                ArchiveMessage::Error(err) => {
                    assert!(err.contains("Symlinks are not currently supported"));
                    saw_error = true;
                    break;
                }
                ArchiveMessage::End => {
                    saw_end = true;
                    break;
                }
                ArchiveMessage::Chunk(_) => {}
            }
        }

        assert!(
            saw_error,
            "Expected symlink in source directory to fail archiving"
        );
        assert!(
            !saw_end,
            "Archive stream must not emit End when a symlink is rejected"
        );
    }
}
