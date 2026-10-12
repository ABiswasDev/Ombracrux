<p align="center">
  <img src="images/banner.png" alt="Ombracrux Banner" width="800">
</p>

<h1 align="center">Ombracrux</h1>

<p align="center">
  <strong>Post-Quantum Resilient Threshold Storage.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PLATFORM-WINDOWS%20%7C%20MACOS%20%7C%20LINUX-2d2d2d?style=for-the-badge" alt="Platform">
  <a href="LICENSE"><img src="https://img.shields.io/badge/LICENSE-AGPL--3.0-28a745?style=for-the-badge" alt="License"></a>
</p>

## Overview & Features

Ombracrux is a network-isolated, cross-platform graphical application for Horcrux-style threshold secret sharing. It utilizes Shamir's Secret Sharing (SSSS) alongside post-quantum resilient stream ciphers to shatter sensitive files and directories into distributed cryptographic shares (`.ombracrx`). A user-defined threshold of these shares must be combined to reconstruct the original data, ensuring absolute data privacy and preventing a single point of failure without relying on external infrastructure or cloud services.

<p align="center">
  <img src="images/screenshot.png" alt="Ombracrux Interface" width="450">
</p>

* **Cross-Platform:** Native installers generated via automated CI/CD for Linux, Windows, and macOS.
* **Network-Isolated Execution:** No telemetry, no cloud accounts, and no internet connection required.
* **Threshold Cryptography:** Distributed M-of-N architecture (e.g., require 3 out of 5 shares to reconstruct the payload).
* **Transparent Archiving:** On-the-fly tarball streaming seamlessly bundles entire folders and preserves original metadata without permanently writing unencrypted archives to disk.

## Engineered for Extreme Threat Models

* **Shamir's Secret Sharing:** Shatters the master cryptographic key into mathematically distributed fragments. The payload cannot be decrypted unless the exact threshold of shares is physically brought together.
* **1-to-1 Stream Ciphering:** Utilizes the XChaCha20-Poly1305 AEAD stream cipher to process large payloads with zero data bloat and extreme speed, while maintaining a microscopic memory footprint.
* **Memory-Safe Chunk Processing:** Employs a strict chunked streaming architecture, allowing the encryption of massive files and folders on resource-constrained hardware without exhausting active RAM.
* **Safe File Handling Protocol:** Restoration writes to a hidden temporary draft file (`.tmp`). The engine only finalizes the reconstruction if the Poly1305 authentication tags pass perfectly, ensuring existing files are never overwritten by corrupted or tampered payloads.
* **Zero-Trust Separation:** The UI (React/Tauri) and the cryptographic engine (`ombracrux-core`) exist in entirely separate, strictly bound workspaces.

## Security & Threat Model

Transparency is paramount in cryptographic tooling. Ombracrux is strictly designed to secure data at rest against modern physical and digital threats, operating under the assumption that the host environment itself is secure.

**In Scope:**
*   **Distributed Trust:** Protecting sensitive payloads by distributing risk across multiple physical locations, devices, or trusted individuals.
*   **Post-Quantum Resilience:** Defending payloads against future quantum computing attacks by using 256-bit symmetric stream ciphers.
*   **Tamper Evidence:** Utilizing Poly1305 authentication tags to instantly detect and reject any bit-level manipulation of an `.ombracrx` share.
*   **Supply Chain Integrity:** Ensuring transparent, verifiable release binaries through automated GitHub Actions CI/CD.

**Out of Scope:**
*   **Endpoint Compromise:** Defending against active keyloggers, memory scraping, screen-recording malware, or inherently compromised host operating systems.
*   **Data Recovery Below Threshold:** Retrieving encrypted payloads if the user loses access to the required threshold of shares. Our zero-knowledge architecture means there are absolutely no backdoors or recovery mechanisms.

## Known Limitations & Mitigation Best Practices

Ombracrux is designed with strict security parameters, but users must understand its operational boundaries. 

### 1. Operational & Environmental Risks
*   **Crash Data Remanence (`.tmp.tar` Vulnerability):** To encrypt large directories without exhausting RAM, the engine dynamically bundles your selected files into a temporary `.tmp.tar` file on your local disk. If your computer loses power or the OS forcefully kills the process mid-encryption, the secure cleanup protocol will not execute, leaving the unencrypted archive exposed on your drive.
    *   *Best Practice:* If an unexpected crash occurs during encryption, manually inspect the target directory and securely delete any lingering `.tmp.tar` files.
*   **Endpoint Compromise:** Ombracrux assumes the host OS is secure. It provides zero protection against rootkits or memory-scraping malware.
    *   *Best Practice:* Execute Ombracrux strictly on trusted, malware-free machines or an air-gapped Live USB environment for extreme threat models.

### 2. Cryptographic & Human Factors
*   **Storage Multiplication:** If the threshold (T) is less than the total shares (N), the underlying XChaCha20 ciphertext is duplicated across the shares to allow recovery from partial data loss. Your total storage footprint will scale linearly with the number of shares.
*   **Zero-Knowledge Absolute Data Loss:** If you generate 5 shares with a threshold of 3, and you permanently lose 3 shares, your data is mathematically unrecoverable. 

## System Requirements

**Minimum Specifications**
* **OS:** Windows 10+ / macOS 11+ / Ubuntu 20.04+ (or equivalent distros)
* **Processor:** 64-bit dual-core CPU
* **Memory:** 4 GB RAM
* **Storage:** Must have free space equal to 2x the target payload size (to accommodate the temporary `.tmp.tar` streaming mechanism).

## Download & Installation

Download the latest stable release from our [Releases Page](https://github.com/ABiswasDev/Ombracrux/releases).

* **Linux:** Download and install the `.deb` package or run the `AppImage`.
* **Windows:** Download and run the `.exe` or `.msi` setup file.
* **macOS:** Mount the `.dmg` image.

## Author & Contributors

* **Abhishek Biswas** – *Lead Maintainer* – [@ABiswasDev](https://github.com/ABiswasDev)

## License & Legal Disclaimer

**AGPL-3.0 License:** Ombracrux is open-source and licensed under the GNU Affero General Public License v3.0 (AGPL-3.0). This prevents proprietary capture or closed-source commercialization of the project. Any violation of these terms—including the unauthorized distribution or monetization of closed-source derivatives—constitutes copyright infringement and will be met with strict legal enforcement.

## Developer Guide: Building from Source

Ombracrux utilizes a Tauri v2 workspace architecture, bridging a React/TypeScript web frontend with an independent, highly optimized Rust cryptographic core.

**1. Prerequisites**
*   [Node.js](https://nodejs.org/) (v22 or higher)
*   [Rust & Cargo](https://rustup.rs/) (latest stable toolchain)
*   Platform-specific Tauri dependencies (C++ Build Tools for Windows, Xcode Tools for macOS, `libwebkit2gtk-4.1-dev` for Linux).

**2. Local Setup & Execution**
```bash
# Clone the repository
git clone [https://github.com/ABiswasDev/Ombracrux.git](https://github.com/ABiswasDev/Ombracrux.git)
cd Ombracrux

# Install frontend dependencies
npm install

# Launch the application in development mode
npm run tauri dev
**3. Building for Production**
```bash
npm run tauri build
```

## Project Structure

```plaintext
ombracrux/
├── package.json              # Node dependencies, scripts, and build runners
├── src/                      # Frontend Presentation Layer (React / TypeScript)
│   ├── App.tsx               # Main application layout, state management, and IPC bridge
│   ├── App.css               # Dark-mode UI styling and progress bar animations
│   └── main.tsx              # React DOM entry point
│
└── src-tauri/                # Tauri Bridge & GUI Capabilities
    ├── Cargo.toml            # App dependencies (tauri, tar, dialog plugins)
    ├── tauri.conf.json       # Tauri system configuration and build targets
    ├── capabilities/         # Strict permission scopes (dialog, opener)
    ├── src/
    │   └── lib.rs            # IPC command router, live progress emitters, and tarball streams
    │
    └── crates/core/          # Independent Cryptographic Engine (ombracrux-core)
        ├── Cargo.toml        # Isolated crypto dependencies (sharks, chacha20poly1305)
        └── src/
            ├── split.rs      # SSSS key generation and file chunking logic
            ├── restore.rs    # SSSS key reconstruction and tamper-validation
            ├── crypto.rs     # XChaCha20-Poly1305 AEAD streaming implementation
            └── format.rs     # Custom V2 binary format & OMBRACRX magic byte serialization
```

---

### ⚠️ IMPORTANT WARNING: R&D STATUS
**This project is currently under active experimentation and heavy Research & Development.** 

Ombracrux is provided strictly for educational and personal data-protection exploration. The algorithms, file formats (`.ombracrx`), and system architectures are subject to rapid, breaking changes. Artifacts encrypted with early builds may not be compatible with future releases. The developer and maintainers assume zero responsibility or liability for data loss, corrupted payloads, or any misuse of this software. Always test the split and restore pipeline with non-critical data before committing sensitive files to the vault.