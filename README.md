<p align="center">
  <img src="images/banner.png" alt="Ombracrux Banner" width="800">
</p>

<h1 align="center">OMBRACRUX</h1>

<p align="center">
  <strong>Shamir Threshold Archive Engine</strong><br>
  <em>Encrypt sensitive files Lord Voldemort style.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PLATFORM-WINDOWS%20%7C%20MACOS%20%7C%20LINUX-101622?style=for-the-badge" alt="Platform">
  <a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-POLYFORM%20NONCOMMERCIAL%201.0.0-10b981?style=for-the-badge" alt="License"></a>
</p>

---

## Overview & Features

**Ombracrux** is an offline, cross-platform desktop application built with **Rust** and **Tauri** for threshold-based encrypted folder storage. It combines **Shamir's Secret Sharing ($T$-of-$N$)** over $GF(2^8)$ with chunk-indexed **XChaCha20-Poly1305** authenticated streaming encryption to split a folder into distributed cryptographic share files (`.ombracrx`).

To unlock and restore the original folder, a user-defined minimum number of shares (the **Threshold**, $T$) must be brought back together to reconstruct the 256-bit master encryption key—eliminating single points of failure without relying on passwords, cloud servers, or external key-management services.

<p align="center">
  <img src="images/screenshot.png" alt="Ombracrux Interface" width="480">
</p>

* **Bounded-Memory Encryption Streaming:** Source directories are packaged on the fly through a bounded in-memory stream and piped directly into the cipher, writing encrypted share files without creating an unencrypted temporary archive file on disk.
* **Preflight Storage Estimator & Capacity Check:** Scans the source directory before encryption to estimate total archive size, per-share size, and total multi-share storage required, while checking available free space on the destination drive.
* **Authenticated Share Headers:** Every share header—including its Shamir key fragment, share index, threshold parameters, and bundle identifier—is authenticated via `HMAC-SHA256` using a subkey derived through `HKDF-SHA256`.
* **Chunk-Indexed AEAD & Truncation Defense:** Payload streams are encrypted in 1 MiB frames bound to deterministic chunk nonces, sequence-verified Associated Data (AAD), and a mandatory authenticated final closure record.
* **Recovery Manifest & Printable HTML Card:** Optionally exports a `<VaultName>.manifest.json` file and a printable `<VaultName>.recovery-card.html` sheet containing share filenames, byte sizes, `SHA-256` checksums, and threshold details—while excluding secret keys, Shamir fragments, and source paths.
* **Share Set Inspection & In-Memory Verification:** Inspects selected shares for bundle compatibility and threshold readiness, and allows full in-memory cryptographic and TAR structure verification (`Verify Shares`) without writing unpacked files to disk.
* **Automatic Payload Failover & Staged Restoration:** Share creation writes to hidden `.partial` files first and performs best-effort rollback if publication fails mid-commit. Restoration unpacks decrypted files into a private temporary staging folder (`0700` permissions on Unix) and automatically fails over to another selected share if an earlier share's payload stream is damaged or truncated.
* **Offline Execution:** Contains no telemetry and makes no application-initiated network requests in the current implementation.

---

## User Guide

You do not need a background in cryptography to use Ombracrux. Think of Ombracrux as a digital vault whose key is shattered into multiple pieces (**Shares**).

### Core Concepts in Plain English
* **Shares ($N$ — Total Shares):** The total number of encrypted `.ombracrx` files Ombracrux will create from your folder (for example, `5` shares). You can store each share in a different place—such as a home PC, an external USB drive, a safe deposit box, or with a trusted family member.
* **Threshold ($T$):** The minimum number of shares required to unlock and recover your folder (for example, `3` out of `5`).
  * If your threshold is `3` out of `5`, **any 3 shares** can recover your files.
  * If a thief steals `1` or `2` of your shares, they cannot reconstruct your encryption key.
  * If you lose `1` or `2` of your USB drives in a fire, you can still recover everything using the remaining `3` shares.
* **Vault Name:** A short label (using ASCII letters, numbers, underscores `_`, or hyphens `-`) used to name your generated share files, such as `Ombracrux_Vault.part1.ombracrx`.

#### Choosing a Threshold ($T$-of-$N$ Trade-Offs)

| Configuration | Shares You Can Lose ($N - T$) | Minimum Shares Needed to Recover ($T$) | Operational Use Case |
| :--- | :---: | :---: | :--- |
| **2-of-3** | 1 | 2 | Personal backup across 3 separate drives or locations |
| **3-of-5** | 2 | 3 | Balanced long-term archival across multiple physical sites |
| **4-of-7** | 3 | 4 | High-security cold storage distributed among multiple custodians |

*Higher thresholds ($T$) require an attacker to compromise more locations, but also require you to keep at least $T$ shares intact and accessible. Note: Setting **Threshold ($T$) = 1** (`1-of-N`) provides redundancy against drive loss, but offers **no multi-share secrecy** because any single share can unlock the vault on its own.*

---

### How to Protect a Folder (`Split` Tab)

1. **Select Your Input Folder:** Click **Browse** next to **Input Folder** and choose the folder containing the files you want to protect. *(Note: Symbolic links, OS shortcuts, and NTFS junctions/reparse points are rejected for safety.)*
2. **Name Your Vault:** Enter a **Vault Name** (for example, `Ombracrux_Vault`).
3. **Choose Your Shares & Threshold:**
   * Set **Total Shares (N)** to the total number of `.ombracrx` files you want to generate (between `2` and `255`).
   * Set **Threshold (T)** to the minimum number of shares required to unlock the vault later (between `1` and `N`).
4. **Select Your Output Folder:** Click **Browse** next to **Output Folder** and choose an existing folder outside your Input Folder where the `.ombracrx` share files should be saved.
5. **Review the Preflight Report & Recovery Kit Option:**
   * **Preflight Checks:** Ombracrux automatically scans your source folder and displays the file count, source data size, per-share size estimate, total output size estimate, and available free space on the destination drive. *(Note: Preflight figures are estimates based on current folder state; ensure sufficient headroom if files or disk space change before encryption finishes.)*
   * **Recovery Kit (`manifest.json` & `recovery-card.html`):** Keep **Export SHA-256 manifest (.json) & printable recovery card (.html)** checked (enabled by default) to generate `<VaultName>.manifest.json` and `<VaultName>.recovery-card.html` alongside your shares.
6. **Create Secure Shares:** Click **Create Secure Shares**. Once the progress bar completes, distribute each `.ombracrx` share to a separate physical storage device or location, and store or print your recovery card separately.

---

### How to Verify or Recover a Folder (`Restore` Tab)

1. **Switch to the Restore Tab:** Click **Restore** at the top of the window.
2. **Select Your Share Files:** Click **Browse** next to **Input Shares** and select at least $T$ (your threshold number) of the `.ombracrx` share files belonging to the same vault (hold `Ctrl` or `Shift` in the file picker to select multiple `.ombracrx` files at once).
3. **Review the Share Set Check:**
   * Ombracrux immediately inspects the selected share headers to confirm they belong to the same bundle, checks for duplicate share indices, displays which share numbers are loaded (e.g., `Shares: #2, #3, #5`), and confirms whether the configured threshold is met.
   * *Important:* Header inspection checks metadata compatibility only; it does not verify that the encrypted payload bytes inside each share are free of storage corruption.
4. **Verify Before Recovery (Optional Audit — Zero Disk Writes):**
   * Click **Verify Shares** to perform a complete in-memory audit of all selected shares.
   * Ombracrux reconstructs the master key, authenticates every share header, and streams the entire encrypted payload of **each selected share** in memory—verifying every `XChaCha20-Poly1305` chunk, TAR entry path, and final closure record without unpacking or writing any files to disk.
5. **Recover & Unpack:**
   * Click **Browse** next to **Output Folder (Required for Unpack Only)** and choose where your recovered folder should be created.
   * Click **Recover & Unpack**. Ombracrux verifies all selected headers, reconstructs the master key, and unpacks the archive into a new folder named `Ombracrux-Restored-<id>` inside your chosen Output Folder.
   * **Automatic Payload Failover:** If the encrypted payload stream in the first selected share is damaged or truncated, Ombracrux automatically cleans up the temporary staging folder and retries recovery using the next selected share in your set. Unrecoverable destination errors (such as a read-only folder or full destination disk) abort immediately without unnecessary retries.

---

## Standard Operating Procedure (SOP)

Follow these operational guidelines to maximize long-term recoverability and avoid common storage mistakes.

### Best Practices (Do's)

1. **Prepare a Clean Source Folder Before Splitting:**
   * Close open applications (such as databases, word processors, or virtual machines) that might modify or lock files inside your source folder while Ombracrux is scanning and archiving it.
2. **Choose a Balanced Threshold ($T$-of-$N$):**
   * Use at least a `2-of-3` or `3-of-5` configuration so your vault can survive both the theft of a single device and the physical failure of a storage drive.
3. **Enforce Physical & Geographic Separation:**
   * Store each `.ombracrx` share on a **separate physical medium** (e.g., Drive 1 at home, Drive 2 in a bank safe or office, Drive 3 with a trusted family member) so a single fire, theft, or drive failure cannot affect multiple shares at once.
4. **Print and Store the Recovery Card Separately:**
   * Print `<VaultName>.recovery-card.html` on paper (or keep `<VaultName>.manifest.json` in your offline records) and write down the physical location of each share in the handwritten note column. Because the card contains no secret keys or folder paths, it is safe to store in a binder or filing cabinet.
5. **Run Periodic Integrity Audits (`Verify Shares`):**
   * Once or twice a year, gather at least $T$ shares, open the **Restore** tab, and click **Verify Shares**. This confirms your storage media have not suffered silent bit-rot over time—without unpacking sensitive plaintext onto a disk.
6. **Select Extra Shares During Recovery When Available:**
   * If you have more than $T$ shares handy during recovery (for example, selecting 4 shares for a `3-of-5` vault), select all available shares. If one drive has a bad sector in its payload stream, Ombracrux will automatically fail over to the next healthy share in your selection.

### Practices to Avoid (Don'ts)

1. **Do NOT Store All Shares on the Same Drive or Cloud Account:**
   * Keeping all $N$ shares in the same folder, on the same external SSD, or inside a single cloud account defeats threshold cryptography. Anyone who accesses that single drive has all the shares needed to unlock the vault, and a single drive failure destroys every copy.
2. **Do NOT Use `Threshold = 1` (`1-of-N`) for Sensitive Threat Models:**
   * A `1-of-N` split means **any single share** can reconstruct the master key by itself. Never use `T = 1` if you want protection against a stolen drive.
3. **Do NOT Modify the Source Directory During an Active Split:**
   * Avoid adding, deleting, editing, or replacing files or folders inside the source directory while a split operation is running.
4. **Do NOT Rename Internal Header Bytes or Truncate `.ombracrx` Files:**
   * Never open `.ombracrx` files in a text editor or alter their contents. Even a 1-bit change in the header or stream will be rejected by `HMAC-SHA256` or `XChaCha20-Poly1305` authentication.
5. **Do NOT Mistake the `SHA-256` Manifest for Cryptographic Authentication:**
   * The `.manifest.json` and `.recovery-card.html` checksums are convenience aids to spot accidental storage bit-rot against a known-good sheet. Always rely on Ombracrux's built-in **Verify Shares** or **Recover & Unpack** workflows for authoritative cryptographic verification.
6. **Do NOT Unpack Sensitive Vaults onto Untrusted or Shared Public Folders:**
   * During `Recover & Unpack`, decrypted files are staged on the destination filesystem before final rename. Only unpack vaults onto a trusted local drive with appropriate access permissions.

---

## Origins & Design

Ombracrux is an independent implementation using **Rust** and **Tauri** to provide a cross-platform desktop application inspired by the threshold-based file recovery concept demonstrated by [Horcrux](https://github.com/jesseduffield/horcrux) (created by Jesse Duffield).

While sharing the conceptual workflow of threshold secret recovery, Ombracrux uses its own Rust architecture (`ombracrux-core`) and extends the concept with:
1. **Hardened Directory Streaming:** On-the-fly in-memory directory archiving (`archive.rs`) with explicit symlink/reparse-point rejection and platform-specific file/directory identity checks.
2. **Authenticated Streaming Format:** Per-share `HKDF-SHA256` + `HMAC-SHA256` header authentication (`format.rs`) and chunk-indexed `XChaCha20-Poly1305` AEAD framing (`crypto.rs`, `restore.rs`, `verify.rs`).
3. **Cryptographic Building Blocks:** Built on established Rust libraries including `sharks` for Shamir's Secret Sharing (`shares.rs`) alongside RustCrypto's `chacha20poly1305`, `hkdf`, `hmac`, `sha2`, and `zeroize` crates.
4. **Resilient Desktop Workflow:** Modular workspace separation between the React/Tauri frontend and the `ombracrux-core` Rust crate, featuring preflight capacity estimation (`preflight.rs`), recovery kit generation (`manifest.rs`), in-memory stream verification (`verify.rs`), classified payload failover (`restore.rs`), and transactional share publication (`lib.rs`).

---

## Threat Models Ombracrux Deals With

Ombracrux is engineered to protect data at rest against specific physical, operational, and cryptographic risks:

### 1. Single-Point Physical Seizure or Device Theft
* **The Threat:** An adversary steals a single backup drive, compromises one storage location, or seizes fewer than $T$ share files.
* **How Ombracrux Mitigates It:** Shamir's Secret Sharing over $GF(2^8)$ provides information-theoretic secrecy for the key fragments alone when fewer than $T$ fragments are known. Because each `.ombracrx` file also contains the encrypted payload and an `HMAC-SHA256` header tag, the confidentiality and integrity of the complete vault artifact rely on the computational security of `XChaCha20-Poly1305`, `HKDF-SHA256`, and `HMAC-SHA256`.

### 2. Media Degradation or Partial Share Loss
* **The Threat:** One or more cold-storage drives suffer physical damage, bad sectors, or loss over time.
* **How Ombracrux Mitigates It:** Ombracrux provides two distinct layers of redundancy:
  * **Key Recovery:** Any valid set of at least $T$ compatible shares with intact, authenticated headers can reconstruct the 256-bit master key.
  * **Payload Recovery:** Each `.ombracrx` share carries a complete copy of the encrypted archive stream. If one selected share's payload copy has suffered media corruption or truncation, the recovery workflow automatically fails over to another selected share containing an intact encrypted payload copy. *(Note: Recovery requires both at least $T$ valid headers to reconstruct the key and at least one intact payload stream among the selected shares.)*

### 3. Share Tampering, Cross-Bundle Splicing & Stream Truncation
* **The Threat:** An attacker modifies a share's index or Shamir fragment, swaps chunks between different vaults, truncates the end of a file, or appends trailing bytes.
* **How Ombracrux Mitigates It:**
  * **Header Integrity:** After reconstructing the candidate master key from the supplied Shamir fragments, Ombracrux verifies the constant-time `HMAC-SHA256` tag on **every supplied share header**, rejecting modified share indices, altered metadata, or mixed bundles before payload decryption begins.
  * **Stream Integrity:** Each encrypted chunk binds the format version, 16-byte `bundle_id`, chunk index, and plaintext length into the `XChaCha20-Poly1305` AAD, followed by a dedicated final closure record authenticating the total chunk count and total plaintext byte length. Any bit flip, chunk reordering, truncation, or trailing byte immediately aborts that stream and removes its temporary staging directory.

### 4. Unencrypted Archive Intermediates During Encryption
* **The Threat:** Traditional archive-then-encrypt workflows write a complete unencrypted archive to disk before encrypting it, leaving plaintext data behind in temporary storage.
* **How Ombracrux Mitigates It:** During the **Split** operation, source files are read directly into a bounded in-memory channel (holding at most 2 chunks in transit) and encrypted in memory before being written to the destination share files. *(Note: During the **Restore** operation, decrypted files are unpacked into a temporary staging directory on the destination disk prior to final stream verification; use **Verify Shares** when you want to verify share integrity strictly in RAM without disk writes.)*

### 5. Symmetric Encryption & Quantum-Computing Considerations
* **The Threat:** Adversaries capturing encrypted archives today to subject them to future quantum-assisted key search.
* **How Ombracrux Mitigates It:** Ombracrux does not rely on classical public-key cryptography (such as RSA or ECDH) for its core encryption workflow. It pairs Shamir threshold splitting with 256-bit symmetric `XChaCha20-Poly1305`, which provides an estimated ~128-bit theoretical security margin against generic quantum key search (Grover's algorithm). *Note: Ombracrux has not been formally validated or independently audited for post-quantum security.*

---

## Security Scope & Operational Boundaries

Users should understand the operational boundaries of the current implementation:

* **Trusted Source Directory & Filesystem Restrictions:** Symbolic links, OS shortcuts, NTFS reparse points/junctions, and special device files are rejected during both preflight scanning and archive creation. Ombracrux performs platform-specific no-follow opens and identity checks (`O_NOFOLLOW` and `dev`/`ino` checks on Unix; `FILE_FLAG_OPEN_REPARSE_POINT` and metadata/reparse checks on Windows) to reduce the risk of concurrent file or directory replacement while archiving. However, because directory enumeration traverses paths recursively, Ombracrux assumes the source directory is not concurrently modified by untrusted local processes during an active split.
* **Secret Memory Handling:** Ombracrux wraps selected sensitive buffers—including generated and reconstructed 256-bit master keys, intermediate Shamir secret buffers, and derived `HKDF-SHA256` header subkeys—in `zeroize::Zeroizing` to reduce how long secret material remains in memory. This is a best-effort user-space safeguard; it cannot guarantee the removal of copies held by the compiler, CPU caches, OS kernel, or swap space.
* **Recovery Kit (`manifest.json` & `recovery-card.html`) Trust Boundary:** The optional recovery manifest and printable HTML card contain zero secret keys, Shamir fragments, or source paths. Their `SHA-256` checksums help detect accidental storage bit-rot only when compared against an intact, trusted manifest. A manifest that an attacker can modify is not proof of authenticity; authoritative cryptographic authentication is enforced by `HMAC-SHA256` headers and `XChaCha20-Poly1305` stream framing during verification and recovery.
* **Irrecoverable Loss Below the Threshold (or Total Payload Loss):** There are no backdoors, master recovery keys, or escrow mechanisms. If fewer than $T$ compatible shares survive—or if every surviving share's encrypted payload stream is damaged—your data cannot be recovered.
* **Plaintext Staging During Restoration & Deletion Semantics:** During `Recover & Unpack`, files are unpacked into a hidden `.ombracrx-restore-*.tmp` staging directory inside the output folder (`0700` permissions on Unix; inherited directory ACLs on Windows) before the final closure record is reached. If verification fails, Ombracrux deletes the staging directory via standard OS file removal (`remove_dir_all`), which unlinks files but does not guarantee physical block erasure on wear-leveled SSDs, and cannot run if the process is terminated abruptly (`SIGKILL` or power loss). Leftover `.ombracrux-*.partial` or `.ombracrx-restore-*.tmp` files after a power outage can be safely deleted manually.
* **Privacy & Network Behavior:** Ombracrux operates locally without cloud dependencies, telemetry, or application-initiated network requests in the current implementation. For vulnerability reporting and security policy details, see [SECURITY.md](SECURITY.md).
* **Compromised Host OS (Out of Scope):** Ombracrux assumes the host operating system is trusted during split, verify, and restore operations. It cannot defend against active kernel rootkits, memory scrapers, or malware on a compromised machine, and has not undergone an independent cryptographic audit.

---

## Storage Overhead & System Requirements

### Storage Footprint
Ombracrux splits the **256-bit encryption key** into Shamir fragments, while **duplicating the encrypted archive payload** inside each generated `.ombracrx` share so that any $T$ shares can independently reconstruct and unpack the vault:
* **No Source Folder Overhead:** Encryption writes no temporary files into your source directory.
* **Destination Space Formula ($N \times A$):** If your source folder produces a packaged TAR stream of size $A$ (which includes file contents plus 512-byte TAR metadata headers, block padding, and 1024-byte EOF markers), splitting into $N$ shares requires approximately **$N \times A$** bytes of free space in the output folder, plus framing overhead (112-byte header per share, 20 bytes per 1 MiB chunk, and 20 bytes for the final closure record).
* **Practical Example:** If a folder produces an archive stream of approximately **1 GB** and you configure **5 shares ($N = 5$)**, Ombracrux requires roughly **5 GB** of free destination space (about 1 GB per `.ombracrx` file).

### Expected Minimum Specifications
* **OS:** Linux (Ubuntu 22.04+, Linux Mint, Debian, Fedora), Windows 10/11 (64-bit), macOS 11+
* **Processor:** 64-bit dual-core CPU
* **Memory:** 4 GB RAM expected minimum (while encryption, verification, and decryption stream in bounded 1 MiB chunks, total memory usage includes the operating system, WebView frontend, and channel buffers)

---

## Download & Installation

Download the latest installers from the [Releases Page](https://github.com/ABiswasDev/Ombracrux/releases):

* **Linux:** `.deb`, `.rpm`, or `.AppImage`
* **Windows:** `.msi` or `.exe` installer
* **macOS:** `.dmg` disk image

---

## Developer Guide: Building & Testing from Source

Ombracrux uses a Tauri workspace connecting a React/TypeScript frontend with the `ombracrux-core` Rust crate.

### 1. Prerequisites
* **Node.js:** v20+ (CI builds with Node.js v24) and `npm`
* **Rust:** Stable toolchain (`rustup`, `cargo`, `rustfmt`)
* **Linux System Dependencies (Ubuntu / Mint / Debian):**
  ```bash
  sudo apt update
  sudo apt install -y libwebkit2gtk-4.1-dev libgtk-3-dev build-essential curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev patchelf pkg-config libglib2.0-dev
  
### 2. Local Development
```bash
git clone https://github.com/ABiswasDev/Ombracrux.git
cd Ombracrux
npm ci
npm run tauri dev
```

### 3. Running Automated Checks & Tests
Ombracrux includes 37 Rust unit and integration tests across ombracrux-core, ombracrux_lib, and tests/streaming.rs. Covered areas include Shamir key splitting and reconstruction, HMAC-SHA256 header authentication, byte-exact preflight size estimation (including empty entries and GNU LongLink paths), recovery manifest and HTML escaping, in-memory stream verification (including corrupted bytes, trailing bytes, truncation, malformed frame lengths, and malicious TAR traversal/symlink entries), transactional share rollback, symlink/reparse-point rejection, and multi-share restoration failover with staging cleanup.

Run formatting, compilation, and the workspace test suite locally before submitting changes:

All formatting, workspace compilation, and automated unit/integration tests are executed from `src-tauri`:
```bash
cd src-tauri
cargo fmt --all -- --check
cargo check --workspace
cargo test --workspace
```

### 4. Building Production Installers
```bash
npm run tauri build
```

---

## Project Structure

```plaintext
Ombracrux/
├── .github/workflows/
│   ├── ci.yml                  # Automated formatting, check, and test verification
│   └── release.yml             # Cross-platform release bundler
├── LICENSE                     # PolyForm Noncommercial License 1.0.0 terms
├── README.md                   # Project documentation, SOP, and user guide
├── SECURITY.md                 # Security policy and vulnerability reporting
├── index.html                  # Webview entry document
├── package.json                # Frontend dependencies and build scripts
├── vite.config.ts              # Vite bundler configuration
├── src/                        # Frontend Presentation Layer (React / TypeScript)
│   ├── App.tsx                 # Fixed-viewport UI, preflight/verify state, and IPC bridge
│   ├── App.css                 # Obsidian & Spectral Emerald theme styling
│   └── main.tsx                # React DOM entry point
└── src-tauri/                  # Rust Backend & Cryptographic Workspace
    ├── Cargo.toml              # Tauri application manifest
    ├── tauri.conf.json         # Window geometry, CSP security, and bundler configuration
    ├── capabilities/
    │   └── default.json        # Tauri v2 permission scopes (dialog, opener)
    ├── icons/                  # Application bundle icons
    ├── src/
    │   ├── lib.rs              # IPC commands, preflight/inspect, failover, and transactions
    │   └── main.rs             # Application binary entry point
    └── crates/core/            # Independent Cryptographic Engine (ombracrux-core)
        ├── Cargo.toml          # Isolated crypto dependencies (sharks, chacha20poly1305, hkdf, hmac)
        ├── src/
        │   ├── lib.rs          # Core crate module exports
        │   ├── archive.rs      # Bounded-memory TAR streaming and no-follow filesystem checks
        │   ├── crypto.rs       # Chunk-indexed XChaCha20-Poly1305 encryption pipeline
        │   ├── format.rs       # Binary share header serialization & HMAC-SHA256 authentication
        │   ├── manifest.rs     # Streaming SHA-256 recovery manifest & printable HTML card
        │   ├── preflight.rs    # Source directory scanner and byte-exact storage estimator
        │   ├── restore.rs      # Authenticated stream decryption, staging, and classified errors
        │   ├── shares.rs       # Shamir's Secret Sharing (GF(2^8)) key split & zeroized recovery
        │   ├── split.rs        # High-level directory split orchestrator
        │   └── verify.rs       # In-memory AEAD stream and TAR entry security verifier
        └── tests/
            └── streaming.rs    # End-to-end tampering, truncation, and restoration test suite
```

---

## Author & Maintainer

* **Abhishek Biswas** — *AI Systems Strategist & Security Architect* — [@ABiswasDev](https://github.com/ABiswasDev)

---

## License & Trademark Notice

### Source-Available License (PolyForm Noncommercial 1.0.0)
Ombracrux is source-available software licensed under the **[PolyForm Noncommercial License 1.0.0](LICENSE)**.

* **Permitted Noncommercial Use:** Personal use, security research, academic study, non-commercial experimentation, and use by qualifying charitable, educational, public research, and government organizations are permitted under the terms of the [LICENSE](LICENSE).
* **Commercial Use Prohibited:** Any commercial use—including selling, trading, licensing, bundling into commercial products, or using the software in a commercial business operation—is strictly prohibited under the PolyForm Noncommercial License and requires a separate written commercial license agreement from the author.

Required Notice: Copyright (c) 2026 Abhishek Biswas (https://github.com/ABiswasDev/Ombracrux)

### Trademark & Branding Policy
The names **"Ombracrux"**, a part of **"Ombraveil"** Research entity, and all associated logos, emblems, and visual identifiers are proprietary trademarks of **Abhishek Biswas**. While the source code is made available under the PolyForm Noncommercial License 1.0.0, **no license or right to use these trademarks is granted**:

* **No Rebranding as Official Releases:** You may not distribute modified versions or forks of this software under the names "Ombracrux", or "Ombraveil", or use confusingly similar names or logos that imply endorsement by or affiliation with **Abhishek Biswas**(https://www.linkedin.com/in/abby33459/).
* **Attribution Required on Forks:** Any permitted non-commercial fork or modified redistribution must retain the `Required Notice` above and clearly state that it is an unofficial modification.