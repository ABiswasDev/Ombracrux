use ombracrux_core::archive::stream_directory_to_memory;
use ombracrux_core::crypto::encrypt_pipeline;
use ombracrux_core::format::ShareHeader;
use ombracrux_core::restore::restore_pipeline;
use ombracrux_core::shares::reconstruct_key;
use ombracrux_core::split::split_directory;

use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn create_sample_directory(root: &Path) -> PathBuf {
    let source = root.join("source");

    fs::create_dir_all(source.join("nested")).unwrap();

    fs::write(source.join("hello.txt"), b"Ombracrux streaming test").unwrap();
    fs::write(source.join("nested").join("data.bin"), [0, 1, 2, 3, 255]).unwrap();
    fs::write(source.join("empty.dat"), b"").unwrap();

    source
}

struct TestVault {
    shares: Vec<Vec<u8>>,
    headers: Vec<ShareHeader>,
    header_lengths: Vec<usize>,
    master_key: [u8; 32],
}

fn create_test_vault(source: &Path) -> TestVault {
    let mut share_one = Vec::new();
    let mut share_two = Vec::new();
    let mut share_three = Vec::new();

    split_directory(
        source,
        vec![&mut share_one, &mut share_two, &mut share_three],
        2,
        3,
    )
    .unwrap();

    let shares = vec![share_one, share_two, share_three];

    let mut headers = Vec::new();
    let mut header_lengths = Vec::new();

    for bytes in &shares {
        let mut cursor = Cursor::new(bytes.as_slice());
        let header = ShareHeader::read_from(&mut cursor).unwrap();

        header_lengths.push(cursor.position() as usize);
        headers.push(header);
    }

    let share_fragments: Vec<Vec<u8>> = headers
        .iter()
        .map(|header| header.ssss_share_data.clone())
        .collect();

    let master_key = reconstruct_key(&share_fragments, headers[0].threshold).unwrap();

    for header in &headers {
        header.verify_auth(&master_key).unwrap();
    }

    TestVault {
        shares,
        headers,
        header_lengths,
        master_key: *master_key,
    }
}

fn restore_share(
    vault: &TestVault,
    share_index: usize,
    payload: Vec<u8>,
    output_root: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let header = &vault.headers[share_index];

    restore_pipeline(
        Cursor::new(payload),
        &vault.master_key,
        header.bundle_id,
        header.base_nonce_prefix,
        output_root,
    )
}

fn only_restored_directory(root: &Path) -> PathBuf {
    let entries: Vec<PathBuf> = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();

    assert_eq!(entries.len(), 1, "Expected exactly one published directory");
    assert!(entries[0].is_dir());
    assert!(entries[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("Ombracrux-Restored-"));

    entries[0].clone()
}

#[test]
fn streaming_split_and_restore_preserves_directory_contents() {
    let temp = tempdir().unwrap();
    let source = create_sample_directory(temp.path());
    let output_root = temp.path().join("restored-output");

    fs::create_dir(&output_root).unwrap();

    let vault = create_test_vault(&source);

    let payload = vault.shares[0][vault.header_lengths[0]..].to_vec();

    restore_share(&vault, 0, payload, &output_root).unwrap();

    let restored = only_restored_directory(&output_root);

    assert_eq!(
        fs::read(restored.join("hello.txt")).unwrap(),
        b"Ombracrux streaming test"
    );

    assert_eq!(
        fs::read(restored.join("nested").join("data.bin")).unwrap(),
        [0, 1, 2, 3, 255]
    );

    assert_eq!(fs::read(restored.join("empty.dat")).unwrap(), b"");
}

#[test]
fn modified_share_header_is_rejected() {
    let temp = tempdir().unwrap();
    let source = create_sample_directory(temp.path());
    let vault = create_test_vault(&source);

    let mut modified = vault.headers[0].clone();

    modified.share_index = 3;

    assert!(modified.verify_auth(&vault.master_key).is_err());
}

#[test]
fn corrupted_ciphertext_is_rejected_and_staging_is_cleaned() {
    let temp = tempdir().unwrap();
    let source = create_sample_directory(temp.path());
    let output_root = temp.path().join("restore-output");

    fs::create_dir(&output_root).unwrap();

    let vault = create_test_vault(&source);
    let offset = vault.header_lengths[0];

    let mut corrupted = vault.shares[0][offset..].to_vec();

    // The first frame has a 4-byte length prefix. Flip a ciphertext byte.
    assert!(corrupted.len() > 5 + 16);
    corrupted[5] ^= 0x80;

    assert!(restore_share(&vault, 0, corrupted, &output_root).is_err());

    assert_eq!(
        fs::read_dir(&output_root).unwrap().count(),
        0,
        "Failed restoration must not publish a recovered directory"
    );
}

#[test]
fn missing_final_record_is_rejected() {
    let temp = tempdir().unwrap();
    let source = create_sample_directory(temp.path());
    let output_root = temp.path().join("restore-output");

    fs::create_dir(&output_root).unwrap();

    let vault = create_test_vault(&source);
    let offset = vault.header_lengths[0];

    let mut truncated = vault.shares[0][offset..].to_vec();

    // Final frame = 4-byte length prefix + 16-byte authentication tag.
    assert!(truncated.len() > 20);
    truncated.truncate(truncated.len() - 20);

    assert!(restore_share(&vault, 0, truncated, &output_root).is_err());

    assert_eq!(
        fs::read_dir(&output_root).unwrap().count(),
        0,
        "Truncated streams must not publish a recovered directory"
    );
}

#[test]
fn incomplete_final_authentication_tag_is_rejected() {
    let temp = tempdir().unwrap();
    let source = create_sample_directory(temp.path());
    let output_root = temp.path().join("restore-output");

    fs::create_dir(&output_root).unwrap();

    let vault = create_test_vault(&source);
    let offset = vault.header_lengths[0];

    let mut truncated = vault.shares[0][offset..].to_vec();

    // Simulate interruption during the final record.
    truncated.pop();

    assert!(restore_share(&vault, 0, truncated, &output_root).is_err());

    assert_eq!(fs::read_dir(&output_root).unwrap().count(), 0);
}

#[test]
fn archive_errors_do_not_become_successful_encryption() {
    let temp = tempdir().unwrap();
    let missing_source = temp.path().join("directory-that-does-not-exist");

    let receiver = stream_directory_to_memory(&missing_source, 1024);

    let mut output = Vec::<u8>::new();
    let key = [9u8; 32];

    let result = encrypt_pipeline(receiver, vec![&mut output], &key, [1u8; 16], [2u8; 16]);

    assert!(result.is_err());
    assert!(
        output.is_empty(),
        "A failed archive must not produce an authenticated final record"
    );
}

#[test]
fn extra_bytes_after_final_record_are_rejected() {
    let temp = tempdir().unwrap();
    let source = create_sample_directory(temp.path());
    let output_root = temp.path().join("restore-output");

    fs::create_dir(&output_root).unwrap();

    let vault = create_test_vault(&source);
    let offset = vault.header_lengths[0];

    let mut payload = vault.shares[0][offset..].to_vec();
    payload.push(0xAA);

    assert!(restore_share(&vault, 0, payload, &output_root).is_err());

    assert_eq!(fs::read_dir(&output_root).unwrap().count(), 0);
}
