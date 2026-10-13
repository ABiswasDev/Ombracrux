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

/// Builds a TAR archive directly into a bounded in-memory channel.
///
/// No plaintext TAR file is created on disk. The receiver must
/// require an explicit End message; channel disconnection alone
/// is never considered successful completion.
pub fn stream_directory_to_memory(src_dir: &Path, chunk_size: usize) -> Receiver<ArchiveMessage> {
    let (tx, rx) = sync_channel::<ArchiveMessage>(CHANNEL_CAPACITY);
    let status_tx = tx.clone();
    let src_dir = src_dir.to_path_buf();
    let chunk_size = chunk_size.max(1);

    thread::spawn(move || {
        let writer = ChannelWriter::new(tx, chunk_size);
        let mut archive = tar::Builder::new(writer);

        if let Err(error) = archive.append_dir_all(".", &src_dir) {
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
