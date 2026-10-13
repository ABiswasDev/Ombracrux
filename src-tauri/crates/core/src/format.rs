use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};

pub const MAGIC_BYTES: &[u8; 8] = b"OMBRACRX";
pub const FORMAT_VERSION: u16 = 3;
const MAX_SSSS_SHARE_LEN: usize = 4096;

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
    fn validate(&self) -> io::Result<()> {
        if self.magic != *MAGIC_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid share magic bytes",
            ));
        }

        if self.version != FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Unsupported share format version",
            ));
        }

        if self.total_shares == 0 || self.threshold == 0 || self.threshold > self.total_shares {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid threshold or total-share count",
            ));
        }

        if self.share_index == 0 || self.share_index > self.total_shares {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Share index is outside the valid range",
            ));
        }

        if self.ssss_share_data.is_empty()
            || self.ssss_share_data.len() > MAX_SSSS_SHARE_LEN
            || self.ssss_share_data.len() > u16::MAX as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Shamir share-data length",
            ));
        }

        Ok(())
    }

    pub fn write_to<W: Write>(&self, mut writer: W) -> io::Result<()> {
        self.validate()?;

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

        let version = reader.read_u16::<BigEndian>()?;

        let mut bundle_id = [0u8; 16];
        reader.read_exact(&mut bundle_id)?;

        let total_shares = reader.read_u8()?;
        let threshold = reader.read_u8()?;
        let share_index = reader.read_u8()?;

        let mut base_nonce_prefix = [0u8; 16];
        reader.read_exact(&mut base_nonce_prefix)?;

        let ssss_len = reader.read_u16::<BigEndian>()? as usize;

        if ssss_len == 0 || ssss_len > MAX_SSSS_SHARE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Shamir share-data length",
            ));
        }

        let mut ssss_share_data = vec![0u8; ssss_len];
        reader.read_exact(&mut ssss_share_data)?;

        let header = Self {
            magic,
            version,
            bundle_id,
            total_shares,
            threshold,
            share_index,
            base_nonce_prefix,
            ssss_share_data,
        };

        header.validate()?;
        Ok(header)
    }
}
