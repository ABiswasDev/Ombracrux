use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};

pub const MAGIC_BYTES: &[u8; 8] = b"OMBRACRX";
pub const FORMAT_VERSION: u16 = 2;

#[derive(Debug, Clone)]
pub struct ShareHeader {
    pub magic: [u8; 8],
    pub version: u16,
    pub bundle_id: [u8; 16],
    pub total_shares: u8,
    pub threshold: u8,
    pub share_index: u8,
    pub base_nonce_prefix: [u8; 16],
    pub ssss_share_data: Vec<u8>,
}

impl ShareHeader {
    pub fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.magic)?;
        writer.write_u16::<BigEndian>(self.version)?;
        writer.write_all(&self.bundle_id)?;
        writer.write_u8(self.total_shares)?;
        writer.write_u8(self.threshold)?;
        writer.write_u8(self.share_index)?;
        writer.write_all(&self.base_nonce_prefix)?;
        
        writer.write_u16::<BigEndian>(self.ssss_share_data.len() as u16)?;
        writer.write_all(&self.ssss_share_data)?;
        Ok(())
    }

    pub fn read_from<R: Read>(mut reader: R) -> io::Result<Self> {
        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic)?;
        if magic != *MAGIC_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid magic bytes"));
        }

        let version = reader.read_u16::<BigEndian>()?;
        if version != FORMAT_VERSION {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported version"));
        }

        let mut bundle_id = [0u8; 16];
        reader.read_exact(&mut bundle_id)?;

        let total_shares = reader.read_u8()?;
        let threshold = reader.read_u8()?;
        if threshold > total_shares || threshold == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid threshold constraints"));
        }

        let share_index = reader.read_u8()?;
        let mut base_nonce_prefix = [0u8; 16];
        reader.read_exact(&mut base_nonce_prefix)?;

        let ssss_len = reader.read_u16::<BigEndian>()?;
        // Defense in depth: prevent malicious headers from allocating massive RAM
        if ssss_len > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "SSSS payload exceeds max size"));
        }
        
        let mut ssss_share_data = vec![0u8; ssss_len as usize];
        reader.read_exact(&mut ssss_share_data)?;

        Ok(Self {
            magic,
            version,
            bundle_id,
            total_shares,
            threshold,
            share_index,
            base_nonce_prefix,
            ssss_share_data,
        })
    }
}