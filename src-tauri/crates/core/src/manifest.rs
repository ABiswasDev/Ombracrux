use crate::format::ShareHeader;
use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareChecksumEntry {
    pub share_index: u8,
    pub file_name: String,
    pub size_bytes: u64,
    pub sha256_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryManifest {
    pub vault_name: String,
    pub format_version: u16,
    pub bundle_id_hex: String,
    pub threshold: u8,
    pub total_shares: u8,
    pub generated_unix_secs: u64,
    pub shares: Vec<ShareChecksumEntry>,
}

#[derive(Debug, Clone)]
pub struct GeneratedRecoveryFiles {
    pub manifest_path: PathBuf,
    pub html_card_path: PathBuf,
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn escape_json(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(&mut escaped, "\\u{:04x}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    escaped
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Streams a completed share file in 64 KiB chunks to compute its SHA-256 digest
/// and byte length without loading the entire share into memory.
pub fn stream_file_sha256(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path)
        .map_err(|e| anyhow!("Failed to open share {} for hashing: {e}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; HASH_BUFFER_SIZE];
    let mut total_bytes = 0u64;

    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|e| anyhow!("Failed while hashing {}: {e}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        total_bytes = total_bytes
            .checked_add(count as u64)
            .ok_or_else(|| anyhow!("Share file size overflow during hashing"))?;
    }

    let digest = hasher.finalize();
    Ok((total_bytes, to_hex(&digest)))
}

/// Builds a `RecoveryManifest` from completed share files on disk.
///
/// Deliberately omits the master key, Shamir share payloads, and original source path.
pub fn build_manifest(vault_name: &str, share_paths: &[PathBuf]) -> Result<RecoveryManifest> {
    if share_paths.is_empty() {
        return Err(anyhow!(
            "Cannot build a recovery manifest without share files"
        ));
    }

    let mut format_version = 0u16;
    let mut bundle_id = [0u8; 16];
    let mut threshold = 0u8;
    let mut total_shares = 0u8;
    let mut entries = Vec::with_capacity(share_paths.len());

    for (idx, path) in share_paths.iter().enumerate() {
        let mut file =
            File::open(path).map_err(|e| anyhow!("Cannot open share {}: {e}", path.display()))?;
        let header = ShareHeader::read_from(&mut file)
            .map_err(|e| anyhow!("Cannot read header in {}: {e}", path.display()))?;
        drop(file);

        if idx == 0 {
            format_version = header.version;
            bundle_id = header.bundle_id;
            threshold = header.threshold;
            total_shares = header.total_shares;
        } else if header.version != format_version
            || header.bundle_id != bundle_id
            || header.threshold != threshold
            || header.total_shares != total_shares
        {
            return Err(anyhow!(
                "Share header mismatch while generating recovery manifest"
            ));
        }

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("Invalid share filename: {}", path.display()))?
            .to_string();

        let (size_bytes, sha256_hex) = stream_file_sha256(path)?;

        entries.push(ShareChecksumEntry {
            share_index: header.share_index,
            file_name,
            size_bytes,
            sha256_hex,
        });
    }

    entries.sort_by_key(|e| e.share_index);

    let generated_unix_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Ok(RecoveryManifest {
        vault_name: vault_name.to_string(),
        format_version,
        bundle_id_hex: to_hex(&bundle_id),
        threshold,
        total_shares,
        generated_unix_secs,
        shares: entries,
    })
}

pub fn render_manifest_json(manifest: &RecoveryManifest) -> String {
    let mut json = String::new();
    json.push_str("{\n");
    json.push_str(&format!(
        "  \"vault_name\": \"{}\",\n",
        escape_json(&manifest.vault_name)
    ));
    json.push_str(&format!(
        "  \"format_version\": {},\n",
        manifest.format_version
    ));
    json.push_str(&format!(
        "  \"bundle_id\": \"{}\",\n",
        escape_json(&manifest.bundle_id_hex)
    ));
    json.push_str(&format!("  \"threshold\": {},\n", manifest.threshold));
    json.push_str(&format!("  \"total_shares\": {},\n", manifest.total_shares));
    json.push_str(&format!(
        "  \"generated_unix_secs\": {},\n",
        manifest.generated_unix_secs
    ));
    json.push_str("  \"security_notice\": \"SHA-256 checksums detect accidental storage bit-rot only if this manifest is intact. Authoritative cryptographic authentication is enforced by Ombracrux via HMAC-SHA256 headers and XChaCha20-Poly1305 stream framing during recovery.\",\n");
    json.push_str("  \"shares\": [\n");

    for (i, share) in manifest.shares.iter().enumerate() {
        let comma = if i + 1 < manifest.shares.len() {
            ","
        } else {
            ""
        };
        json.push_str("    {\n");
        json.push_str(&format!("      \"share_index\": {},\n", share.share_index));
        json.push_str(&format!(
            "      \"file_name\": \"{}\",\n",
            escape_json(&share.file_name)
        ));
        json.push_str(&format!("      \"size_bytes\": {},\n", share.size_bytes));
        json.push_str(&format!(
            "      \"sha256\": \"{}\"\n",
            escape_json(&share.sha256_hex)
        ));
        json.push_str(&format!("    }}{comma}\n"));
    }

    json.push_str("  ]\n}\n");
    json
}

pub fn render_recovery_card_html(manifest: &RecoveryManifest) -> String {
    let mut rows = String::new();
    for share in &manifest.shares {
        rows.push_str(&format!(
            "<tr><td>#{}</td><td><code>{}</code></td><td>{} B</td><td><code>{}</code></td><td>________________</td></tr>\n",
            share.share_index,
            escape_html(&share.file_name),
            share.size_bytes,
            escape_html(&share.sha256_hex)
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Ombracrux Recovery Card — {vault}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; margin: 28px; line-height: 1.45; }}
  h1 {{ font-size: 1.35rem; margin-bottom: 4px; letter-spacing: 0.5px; text-transform: uppercase; }}
  .sub {{ color: #475569; font-size: 0.88rem; margin-bottom: 18px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 18px; }}
  .meta-box {{ border: 1px solid #cbd5e1; border-radius: 6px; padding: 8px 10px; background: #f8fafc; }}
  .meta-label {{ font-size: 0.72rem; text-transform: uppercase; color: #64748b; font-weight: 600; }}
  .meta-val {{ font-size: 0.95rem; font-weight: 700; margin-top: 2px; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 0.8rem; }}
  th, td {{ border: 1px solid #cbd5e1; padding: 7px 8px; text-align: left; }}
  th {{ background: #f1f5f9; font-weight: 700; text-transform: uppercase; font-size: 0.72rem; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.76rem; }}
  .notice {{ margin-top: 18px; padding: 10px 12px; border-left: 3px solid #059669; background: #ecfdf5; font-size: 0.78rem; color: #065f46; }}
  @media print {{ body {{ margin: 12mm; }} }}
</style>
</head>
<body>
  <h1>Ombracrux Printable Recovery Card</h1>
  <div class="sub">Shamir Threshold Archive Engine &bull; Keep this sheet with your offline recovery records</div>

  <div class="meta-grid">
    <div class="meta-box">
      <div class="meta-label">Vault Name</div>
      <div class="meta-val">{vault}</div>
    </div>
    <div class="meta-box">
      <div class="meta-label">Recovery Threshold</div>
      <div class="meta-val">Any {threshold} of {total_shares} Shares</div>
    </div>
    <div class="meta-box">
      <div class="meta-label">Format Version</div>
      <div class="meta-val">v{version}</div>
    </div>
    <div class="meta-box">
      <div class="meta-label">Bundle ID</div>
      <div class="meta-val"><code>{bundle_id}</code></div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Share</th>
        <th>File Name</th>
        <th>Size</th>
        <th>SHA-256 Checksum</th>
        <th>Storage Location (Handwritten Note)</th>
      </tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>

  <div class="notice">
    <strong>Security &amp; Verification Note:</strong> This card contains zero secret keys, Shamir fragments, or source paths.
    SHA-256 checksums verify accidental media bit-rot only if this reference sheet has not been modified.
    During restoration, Ombracrux enforces cryptographic authentication (HMAC-SHA256 headers and XChaCha20-Poly1305 authenticated framing) as the actual security control.
  </div>
</body>
</html>
"#,
        vault = escape_html(&manifest.vault_name),
        threshold = manifest.threshold,
        total_shares = manifest.total_shares,
        version = manifest.format_version,
        bundle_id = escape_html(&manifest.bundle_id_hex),
        rows = rows
    )
}

/// Writes `<vault_name>.manifest.json` and `<vault_name>.recovery-card.html` into `output_dir`,
/// refusing to overwrite any existing file.
pub fn write_recovery_files(
    output_dir: &Path,
    vault_name: &str,
    share_paths: &[PathBuf],
) -> Result<GeneratedRecoveryFiles> {
    let manifest_path = output_dir.join(format!("{vault_name}.manifest.json"));
    let html_card_path = output_dir.join(format!("{vault_name}.recovery-card.html"));

    for target in [&manifest_path, &html_card_path] {
        if fs::symlink_metadata(target).is_ok() {
            return Err(anyhow!(
                "Refusing to overwrite existing recovery file: {}",
                target.display()
            ));
        }
    }

    let manifest = build_manifest(vault_name, share_paths)?;
    let json_bytes = render_manifest_json(&manifest);
    let html_bytes = render_recovery_card_html(&manifest);

    let mut json_file = File::options()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .map_err(|e| anyhow!("Could not create {}: {e}", manifest_path.display()))?;
    json_file
        .write_all(json_bytes.as_bytes())
        .and_then(|_| json_file.sync_all())
        .map_err(|e| {
            let _ = fs::remove_file(&manifest_path);
            anyhow!("Failed writing {}: {e}", manifest_path.display())
        })?;

    let mut html_file = File::options()
        .write(true)
        .create_new(true)
        .open(&html_card_path)
        .map_err(|e| {
            let _ = fs::remove_file(&manifest_path);
            anyhow!("Could not create {}: {e}", html_card_path.display())
        })?;
    html_file
        .write_all(html_bytes.as_bytes())
        .and_then(|_| html_file.sync_all())
        .map_err(|e| {
            let _ = fs::remove_file(&manifest_path);
            let _ = fs::remove_file(&html_card_path);
            anyhow!("Failed writing {}: {e}", html_card_path.display())
        })?;

    Ok(GeneratedRecoveryFiles {
        manifest_path,
        html_card_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::split_directory;
    use tempfile::tempdir;

    #[test]
    fn manifest_and_html_card_stream_checksums_and_omit_source_paths() {
        let temp = tempdir().unwrap();
        let src = temp.path().join("Confidential_Source_Dir_Name");
        let out = temp.path().join("out");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(src.join("secret.txt"), b"top secret payload").unwrap();

        let share_paths: Vec<PathBuf> = (1..=3)
            .map(|i| out.join(format!("TestVault.part{i}.ombracrx")))
            .collect();
        let files: Vec<File> = share_paths
            .iter()
            .map(|p| File::create(p).unwrap())
            .collect();

        split_directory(&src, files, 2, 3).unwrap();

        let generated = write_recovery_files(&out, "TestVault", &share_paths).unwrap();
        assert!(generated.manifest_path.exists());
        assert!(generated.html_card_path.exists());

        let json_text = fs::read_to_string(&generated.manifest_path).unwrap();
        let html_text = fs::read_to_string(&generated.html_card_path).unwrap();

        assert!(json_text.contains("\"vault_name\": \"TestVault\""));
        assert!(json_text.contains("\"threshold\": 2"));
        assert!(json_text.contains("\"total_shares\": 3"));
        assert!(json_text.contains("TestVault.part1.ombracrx"));
        assert!(!json_text.contains("Confidential_Source_Dir_Name"));
        assert!(!html_text.contains("Confidential_Source_Dir_Name"));
        assert!(html_text.contains("Any 2 of 3 Shares"));
    }

    #[test]
    fn manifest_rejects_mixed_bundles_and_escapes_html_characters() {
        let temp = tempdir().unwrap();
        let src = temp.path().join("src");
        let out_a = temp.path().join("out_a");
        let out_b = temp.path().join("out_b");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&out_a).unwrap();
        fs::create_dir_all(&out_b).unwrap();
        fs::write(src.join("data.txt"), b"vault payload").unwrap();

        let paths_a: Vec<PathBuf> = (1..=2)
            .map(|i| out_a.join(format!("A.part{i}.ombracrx")))
            .collect();
        let files_a: Vec<File> = paths_a.iter().map(|p| File::create(p).unwrap()).collect();
        split_directory(&src, files_a, 2, 2).unwrap();

        let paths_b: Vec<PathBuf> = (1..=2)
            .map(|i| out_b.join(format!("B.part{i}.ombracrx")))
            .collect();
        let files_b: Vec<File> = paths_b.iter().map(|p| File::create(p).unwrap()).collect();
        split_directory(&src, files_b, 2, 2).unwrap();

        // Mixing Share #1 from Vault A and Share #2 from Vault B must fail
        let mixed = vec![paths_a[0].clone(), paths_b[1].clone()];
        assert!(build_manifest("MixedVault", &mixed).is_err());

        // Special characters in vault name must be escaped in HTML and JSON output
        let manifest = build_manifest("Vault_<script>&\"test\"", &paths_a).unwrap();
        let html = render_recovery_card_html(&manifest);
        let json = render_manifest_json(&manifest);

        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;&amp;&quot;test&quot;"));
        assert!(json.contains("Vault_<script>&\\\"test\\\""));
    }
}
