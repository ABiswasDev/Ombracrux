use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub const MAGIC_BYTES: &[u8; 8] = b"OMBRACRX";
pub const FORMAT_VERSION: u16 = 4;

const MAX_SSSS_SHARE_LEN: usize = 4096;
const HEADER_AUTH_INFO: &[u8] = b"ombracrux/v4/share-header-auth";
const HEADER_AUTH_DOMAIN: &[u8] = b"Ombracrux authenticated share header v4\0";

type HeaderMac = Hmac<Sha256>;

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
    pub header_auth: [u8; 32],
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

        if self.ssss_share_data.is_empty() || self.ssss_share_data.len() > MAX_SSSS_SHARE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Shamir share-data length",
            ));
        }

        Ok(())
    }

    fn create_mac(&self, master_key: &[u8; 32]) -> io::Result<HeaderMac> {
        self.validate()?;

        let hkdf = Hkdf::<Sha256>::new(Some(&self.bundle_id[..]), master_key);

        let mut derived_key = Zeroizing::new([0u8; 32]);

        hkdf.expand(HEADER_AUTH_INFO, &mut derived_key[..])
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Could not derive the header-authentication key",
                )
            })?;

        let mut mac = HeaderMac::new_from_slice(&derived_key[..]).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Could not initialize header authentication",
            )
        })?;

        // Domain separation prevents ambiguity with other uses of HMAC.
        mac.update(HEADER_AUTH_DOMAIN);

        // Authenticate every security-relevant header field, including
        // the serialized Shamir share data.
        mac.update(&self.magic);
        mac.update(&self.version.to_be_bytes());
        mac.update(&self.bundle_id);
        mac.update(&[self.total_shares, self.threshold, self.share_index]);
        mac.update(&self.base_nonce_prefix);

        let share_len = u16::try_from(self.ssss_share_data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Shamir share-data length exceeds the format limit",
            )
        })?;

        mac.update(&share_len.to_be_bytes());
        mac.update(&self.ssss_share_data);

        Ok(mac)
    }

    /// Calculates and stores the authenticator for this individual share.
    pub fn sign(&mut self, master_key: &[u8; 32]) -> io::Result<()> {
        let tag = self.create_mac(master_key)?.finalize().into_bytes();
        self.header_auth.copy_from_slice(&tag);
        Ok(())
    }

    /// Verifies the header tag in constant time using HMAC verification.
    pub fn verify_auth(&self, master_key: &[u8; 32]) -> io::Result<()> {
        self.create_mac(master_key)?
            .verify_slice(&self.header_auth)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Share header authentication failed",
                )
            })
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

        let share_len = u16::try_from(self.ssss_share_data.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Shamir share-data length exceeds the format limit",
            )
        })?;

        writer.write_u16::<BigEndian>(share_len)?;
        writer.write_all(&self.ssss_share_data)?;
        writer.write_all(&self.header_auth)?;

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

        let share_len = reader.read_u16::<BigEndian>()? as usize;

        if share_len == 0 || share_len > MAX_SSSS_SHARE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Invalid Shamir share-data length",
            ));
        }

        let mut ssss_share_data = vec![0u8; share_len];
        reader.read_exact(&mut ssss_share_data)?;

        let mut header_auth = [0u8; 32];
        reader.read_exact(&mut header_auth)?;

        let header = Self {
            magic,
            version,
            bundle_id,
            total_shares,
            threshold,
            share_index,
            base_nonce_prefix,
            ssss_share_data,
            header_auth,
        };

        header.validate()?;
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn sample_header() -> ShareHeader {
        ShareHeader {
            magic: *MAGIC_BYTES,
            version: FORMAT_VERSION,
            bundle_id: [3u8; 16],
            total_shares: 5,
            threshold: 3,
            share_index: 1,
            base_nonce_prefix: [7u8; 16],
            ssss_share_data: vec![1, 2, 3, 4, 5],
            header_auth: [0u8; 32],
        }
    }

    #[test]
    fn header_authentication_survives_serialization() {
        let key = [42u8; 32];
        let mut header = sample_header();

        header.sign(&key).unwrap();
        header.verify_auth(&key).unwrap();

        let mut serialized = Vec::new();
        header.write_to(&mut serialized).unwrap();

        let decoded = ShareHeader::read_from(Cursor::new(serialized)).unwrap();
        decoded.verify_auth(&key).unwrap();
    }

    #[test]
    fn modified_share_data_fails_authentication() {
        let key = [42u8; 32];
        let mut header = sample_header();

        header.sign(&key).unwrap();
        header.ssss_share_data[0] ^= 0x80;

        assert!(header.verify_auth(&key).is_err());
    }

    #[test]
    fn modified_share_index_fails_authentication() {
        let key = [42u8; 32];
        let mut header = sample_header();

        header.sign(&key).unwrap();
        header.share_index = 2;

        assert!(header.verify_auth(&key).is_err());
    }

    #[test]
    fn incorrect_master_key_fails_authentication() {
        let mut header = sample_header();
        header.sign(&[42u8; 32]).unwrap();

        assert!(header.verify_auth(&[43u8; 32]).is_err());
    }
}
