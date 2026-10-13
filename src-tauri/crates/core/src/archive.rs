use std::io::{self, Write};
use std::path::Path;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread;

/// A custom writer that buffers data and sends it across a thread channel
/// once it reaches the target chunk size.
pub struct ChannelWriter {
    sender: SyncSender<Vec<u8>>,
    buffer: Vec<u8>,
    chunk_size: usize,
}

impl ChannelWriter {
    pub fn new(sender: SyncSender<Vec<u8>>, chunk_size: usize) -> Self {
        Self {
            sender,
            buffer: Vec::with_capacity(chunk_size),
            chunk_size,
        }
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < buf.len() {
            let space = self.chunk_size - self.buffer.len();
            let to_copy = space.min(buf.len() - written);
            self.buffer.extend_from_slice(&buf[written..written + to_copy]);
            written += to_copy;

            // When the buffer hits exactly 1MB, ship it to the encryptor thread.
            // If the channel is full (2 chunks), this will safely block and pause the archiver.
            if self.buffer.len() == self.chunk_size {
                let chunk = std::mem::replace(&mut self.buffer, Vec::with_capacity(self.chunk_size));
                self.sender.send(chunk).map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffer.is_empty() {
            let chunk = std::mem::replace(&mut self.buffer, Vec::new());
            self.sender.send(chunk).map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))?;
        }
        Ok(())
    }
}

/// Spawns a background thread to tar the directory and returns a receiver 
/// yielding perfectly sized memory chunks.
pub fn stream_directory_to_memory(src_dir: &Path, chunk_size: usize) -> Receiver<Vec<u8>> {
    // Bounded capacity of 2 strictly enforces backpressure.
    let (tx, rx) = sync_channel::<Vec<u8>>(2);
    let src_dir = src_dir.to_path_buf();

    thread::spawn(move || {
        let channel_writer = ChannelWriter::new(tx, chunk_size);
        let mut tar = tar::Builder::new(channel_writer);
        
        // Appends files to the stream without loading them entirely into RAM
        if let Err(e) = tar.append_dir_all(".", &src_dir) {
            eprintln!("Archiving failed: {}", e);
            return;
        }
        
        let mut writer = match tar.into_inner() {
            Ok(w) => w,
            Err(_) => return,
        };
        let _ = writer.flush();
        // Dropping `tx` automatically closes the channel, signaling EOF to the encryptor.
    });

    rx
}