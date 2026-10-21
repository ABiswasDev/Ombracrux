use anyhow::{anyhow, Result};
use sharks::{Share, Sharks};
pub use zeroize::Zeroizing;

/// Splits a 256-bit (32-byte) master key into `total_shares` using Shamir's Secret Sharing,
/// requiring at least `threshold` shares to reconstruct.
pub fn split_key(key: &[u8; 32], threshold: u8, total_shares: u8) -> Result<Vec<Vec<u8>>> {
    if threshold == 0 || total_shares == 0 || threshold > total_shares {
        return Err(anyhow!(
            "Invalid split parameters: threshold must be >= 1 and <= total_shares"
        ));
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(key);

    let shares: Vec<Vec<u8>> = dealer
        .take(total_shares as usize)
        .map(|s| Vec::from(&s))
        .collect();

    Ok(shares)
}

/// Reconstructs the 32-byte master key from a slice of raw share byte vectors.
/// Both the intermediate secret buffer and returned key are wrapped in `Zeroizing`
/// so key material is wiped from RAM when dropped.
pub fn reconstruct_key(shares_bytes: &[Vec<u8>], threshold: u8) -> Result<Zeroizing<[u8; 32]>> {
    if threshold == 0 {
        return Err(anyhow!("Threshold must be at least 1"));
    }

    if shares_bytes.len() < threshold as usize {
        return Err(anyhow!(
            "Insufficient shares: got {}, need at least {}",
            shares_bytes.len(),
            threshold
        ));
    }

    let mut shares = Vec::with_capacity(shares_bytes.len());
    for b in shares_bytes {
        let share =
            Share::try_from(b.as_slice()).map_err(|e| anyhow!("Corrupted share data: {}", e))?;
        shares.push(share);
    }

    let sharks = Sharks(threshold);
    let secret = Zeroizing::new(
        sharks
            .recover(shares.as_slice())
            .map_err(|e| anyhow!("Failed to reconstruct secret: {}", e))?,
    );

    if secret.len() != 32 {
        return Err(anyhow!(
            "Reconstructed key has invalid length: expected 32, got {}",
            secret.len()
        ));
    }

    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&secret);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reconstruct_exact_threshold() {
        let master_key = [42u8; 32];
        let shares = split_key(&master_key, 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        let subset = &shares[1..4];
        let recovered = reconstruct_key(subset, 3).unwrap();
        assert_eq!(*recovered, master_key);
    }

    #[test]
    fn test_reconstruct_fails_with_insufficient_shares() {
        let master_key = [99u8; 32];
        let shares = split_key(&master_key, 3, 5).unwrap();

        let subset = &shares[0..2];
        assert!(reconstruct_key(subset, 3).is_err());
    }

    #[test]
    fn test_invalid_split_parameters() {
        let master_key = [1u8; 32];
        assert!(split_key(&master_key, 0, 5).is_err());
        assert!(split_key(&master_key, 5, 0).is_err());
        assert!(split_key(&master_key, 6, 5).is_err());
    }
}
