use anyhow::{anyhow, Result};
use sharks::{Share, Sharks};

/// Splits a 256-bit encryption key into multiple shares using Shamir's Secret Sharing.
pub fn split_key(key: &[u8; 32], threshold: u8, total_shares: u8) -> Result<Vec<Vec<u8>>> {
    if threshold == 0 || threshold > total_shares {
        return Err(anyhow!("Invalid split parameters: threshold must be > 0 and <= total_shares"));
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(key.as_slice());
    
    // Extract the requested number of shares and serialize them to bytes
    let shares: Vec<Vec<u8>> = dealer
        .take(total_shares as usize)
        .map(|share| Vec::from(&share))
        .collect();

    Ok(shares)
}

/// Reconstructs the original 256-bit encryption key from a provided list of shares.
pub fn reconstruct_key(share_bytes: &[Vec<u8>], threshold: u8) -> Result<[u8; 32]> {
    if share_bytes.len() < threshold as usize {
        return Err(anyhow!(
            "Not enough shares to reconstruct the key. Have {}, need {}",
            share_bytes.len(),
            threshold
        ));
    }

    let sharks = Sharks(threshold);
    
    // Deserialize raw bytes back into Shark Share objects
    let mut shares = Vec::new();
    for bytes in share_bytes {
        let share = Share::try_from(bytes.as_slice())
            .map_err(|_| anyhow!("Failed to parse share data. The share file might be corrupted."))?;
        shares.push(share);
    }

    // Recover the secret key mathematically
    let secret = sharks.recover(&shares)
        .map_err(|_| anyhow!("Failed to reconstruct the secret key from the provided shares."))?;

    if secret.len() != 32 {
        return Err(anyhow!("Reconstructed key has an invalid length. Expected 32 bytes."));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&secret);

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key;

    #[test]
    fn test_split_and_reconstruct_exact_threshold() {
        let original_key = generate_key();
        let threshold = 3;
        let total_shares = 5;

        // Split the key into 5 shares
        let shares = split_key(&original_key, threshold, total_shares).unwrap();
        assert_eq!(shares.len(), 5);

        // Take exactly 3 shares (the threshold) to reconstruct
        let selected_shares = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        
        let reconstructed_key = reconstruct_key(&selected_shares, threshold).unwrap();
        assert_eq!(original_key, reconstructed_key);
    }

    #[test]
    fn test_reconstruct_fails_with_insufficient_shares() {
        let original_key = generate_key();
        let threshold = 3;
        let total_shares = 5;

        let shares = split_key(&original_key, threshold, total_shares).unwrap();

        // Try to reconstruct with only 2 shares (below threshold of 3)
        let selected_shares = vec![shares[0].clone(), shares[1].clone()];
        
        let result = reconstruct_key(&selected_shares, threshold);
        assert!(result.is_err(), "Reconstruction should fail when threshold is not met");
    }

    #[test]
    fn test_invalid_split_parameters() {
        let key = generate_key();
        // Trying to require 6 shares to unlock when only 5 exist
        let result = split_key(&key, 6, 5);
        assert!(result.is_err());
    }
}