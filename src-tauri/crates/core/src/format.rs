use anyhow::{anyhow, Result};
use std::convert::TryInto;

/// Magic bytes to identify an Ombracrux V2 share file ("OMBRACRX")
pub const MAGIC_BYTES: [u8; 8] = *b"OMBRACRX";
pub const FORMAT_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 27; // 8 (magic) + 1 (version) + 16 (bundle) + 1 (threshold) + 1 (total)

#[derive(Debug, Clone, PartialEq)]
pub struct ShareHeader {
    pub bundle_id: [u8; 16],
    pub threshold: u8,
    pub total_shares: u8,
}

impl ShareHeader {
    /// Creates a new header with a random bundle ID
    pub fn new(threshold: u8, total_shares: u8) -> Self {
        Self {
            bundle_id: [0; 16], // We populate this with random bytes during the split process
            threshold,
            total_shares,
        }
    }

    /// Serializes the header into a fixed-size byte array for writing to disk
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buffer = [0u8; HEADER_SIZE];
        buffer[0..8].copy_from_slice(&MAGIC_BYTES);
        buffer[8] = FORMAT_VERSION;
        buffer[9..25].copy_from_slice(&self.bundle_id);
        buffer[25] = self.threshold;
        buffer[26] = self.total_shares;
        buffer
    }

    /// Parses and validates a header from raw bytes read from a file
    pub fn from_bytes(buffer: &[u8]) -> Result<Self> {
        if buffer.len() < HEADER_SIZE {
            return Err(anyhow!("File is too small to contain a valid Ombracrux header"));
        }

        let magic: [u8; 8] = buffer[0..8].try_into()?;
        if magic != MAGIC_BYTES {
            return Err(anyhow!("Invalid magic bytes: not an Ombracrux share"));
        }

        let version = buffer[8];
        if version != FORMAT_VERSION {
            return Err(anyhow!("Unsupported format version: {}", version));
        }

        let bundle_id: [u8; 16] = buffer[9..25].try_into()?;
        let threshold = buffer[25];
        let total_shares = buffer[26];

        if threshold == 0 || threshold > total_shares {
            return Err(anyhow!("Invalid threshold or total shares configuration in header"));
        }

        Ok(Self {
            bundle_id,
            threshold,
            total_shares,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_serialization() {
        let mut header = ShareHeader::new(3, 5);
        header.bundle_id = [7; 16]; // Mock bundle ID for testing

        let bytes = header.to_bytes();
        let parsed = ShareHeader::from_bytes(&bytes).unwrap();

        assert_eq!(header, parsed);
    }

    #[test]
    fn test_invalid_magic_bytes() {
        let mut bytes = ShareHeader::new(3, 5).to_bytes();
        bytes[0] = b'X'; // Corrupt the magic bytes
        
        assert!(ShareHeader::from_bytes(&bytes).is_err());
    }
}