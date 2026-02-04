# HyperKey: Deterministic Password Generator

[![Python CI - Hyperkey](https://github.com/leonardomarino/hyperkey/actions/workflows/ci.yml/badge.svg)](https://github.com/leonardomarino/hyperkey/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**HyperKey** is a command-line utility for generating cryptographically secure, **deterministic passwords**. Unlike traditional password managers that store your secrets in an encrypted database (which can be stolen, corrupted, or synced to the cloud), HyperKey **calculates** your password on the fly using a combination of a seed file and a passphrase.

If you lose your database in a traditional manager, you lose your passwords. With HyperKey, as long as you have your seed file (e.g., a photo, a song, a random binary file) and your memory, you can recover your credentials anywhere.

---

## 🚀 Features

* **Robust Cryptography:**
    * **Key Derivation:** Uses **Scrypt** (Memory-Hard) to neutralize GPU/ASIC cracking attacks.
    * **Hashing:** Uses **SHA-3-512** for seed file hashing and **HMAC-SHA-3-512** for entropy mixing.
    * **DRBG:** Replaces Python's standard random generator with a **ChaCha20 Stream Cipher** seeded via **HKDF-SHA-3-512**.
    * **Domain Separation:** Service and passphrase keys are derived independently with tagged inputs.
* **Deterministic:** The same inputs (*Seed File + Service Name + Passphrase*) always produce the exact same password.
* **Stateless:** No database file to sync, back up, or lose.
* **Cross-Platform:** Works on macOS (Apple Silicon optimized), Linux, and Windows.
* **Secure Policies:** Pre-defined complexity rules (Green, Yellow, Red) to match different security needs.
* **Automatic Clipboard Clearing:** Configurable timeout to automatically clear clipboard after copying password (default: 30 seconds).

---

## 📦 Installation

### Prerequisites

* Python 3.8 or higher
* `pip` package manager

### 1. Clone the Repository

```bash
git clone https://github.com/leonardomarino/hyperkey.git
cd hyperkey
```

### 2. Install Dependencies

It is recommended to use a virtual environment to manage dependencies:

```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography pyperclip
```

---

## 🛠️ Usage

The basic command syntax is:

```bash
./hyperkey.py [SEED_FILE] [POLICY] [SERVICE_NAME] [PASSPHRASE] [OPTIONS]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `SEED_FILE` | Any file on your computer (image, song, random bytes). This acts as your "Master Key File." Can also be an HTTPS URL. |
| `POLICY` | The complexity level (`green`, `yellow`, `red`, `legacy`). |
| `SERVICE_NAME` | The identifier for the account (e.g., `gmail`, `twitter`, `bank`). (Optional, will prompt if not provided) |
| `PASSPHRASE` | Your memorized master password. (Optional, will prompt securely if not provided) |

### Options

| Option | Description |
|--------|-------------|
| `--clipboard-timeout SECONDS` | Seconds to wait before automatically clearing clipboard (default: 30, range: 1-3600) |
| `--no-clipboard-clear` | Disable automatic clipboard clearing (password remains until manually overwritten) |
| `-h, --help` | Show help message and exit |

### Examples

**Basic usage:**
```bash
./hyperkey.py my_photo.jpg red google
```

**Custom clipboard timeout (20 seconds):**
```bash
./hyperkey.py my_photo.jpg yellow banking --clipboard-timeout 20
```

**Disable clipboard clearing:**
```bash
./hyperkey.py my_photo.jpg green email --no-clipboard-clear
```

**Remote seed file with custom timeout:**
```bash
./hyperkey.py https://example.com/seed.jpg red crypto-wallet --clipboard-timeout 10
```

**What happens:**

1. The script hashes `my_photo.jpg` using SHA-3-512 and splits it into salt + seed digest.
2. It prompts you for your passphrase (hidden input).
3. It derives two domain-separated keys using Scrypt (128MB RAM for "red" policy).
4. It combines all entropy via HMAC-SHA-3-512 and initializes a ChaCha20 DRBG.
5. It generates a 32-character complex password and copies it to your clipboard.
6. It displays a countdown timer and automatically clears the clipboard after the specified timeout (default: 30 seconds).
7. You can press Enter at any time to exit early and skip clipboard clearing.

---

## 🛡️ Security Policies

The policy determines the password length, complexity, and the computational cost required to generate it.

| Policy | Length | Min Upper | Min Numeric | Min Symbol | Scrypt Cost (RAM) | Use Case |
|--------|--------|-----------|-------------|------------|-------------------|----------|
| Green | 14 | 2 | 2 | 1 | 2¹⁵ (32 MB) | Daily accounts, standard logins. |
| Yellow | 20 | 4 | 4 | 2 | 2¹⁶ (64 MB) | Financial, Email, Important logins. |
| Red | 32 | 8 | 6 | 4 | 2¹⁷ (128 MB) | Root passwords, Crypto wallets, Master keys. |
| Legacy | 8 | 2 | 2 | 1 | 2¹⁵ (32 MB) | Old systems with strict length limits. |

**Note:** Yellow and Red policies use "secure mode" which continues sampling all character classes throughout generation, typically exceeding the minimums shown above.

---

## 🧠 Theory of Operation

HyperKey implements a "Stateless Password Manager" model using the following cryptographic pipeline:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ENTROPY SOURCES                                │
├─────────────────┬─────────────────────┬─────────────────────────────────┤
│   Seed File     │   Service Name      │   Passphrase                    │
│   (any file)    │   (e.g. "gmail")    │   (memorized)                   │
└────────┬────────┴──────────┬──────────┴──────────────┬──────────────────┘
         │                   │                         │
         ▼                   │                         │
   ┌───────────┐             │                         │
   │ SHA-3-512 │             │                         │
   └─────┬─────┘             │                         │
         │                   │                         │
    ┌────┴────┐              │                         │
    ▼         ▼              ▼                         ▼
┌───────┐ ┌────────┐   ┌──────────┐             ┌──────────┐
│ Salt  │ │ Seed   │   │ Scrypt   │             │ Scrypt   │
│(16 B) │ │ Digest │   │ (k1)     │             │ (k2)     │
└───┬───┘ └────┬───┘   │ domain:  │             │ domain:  │
    │          │       │ service  │             │ passphrase│
    │          │       └────┬─────┘             └─────┬────┘
    │          │            │                        │
    │          │            └───────────┬────────────┘
    │          │                        │
    │          │                        ▼
    │          │              ┌───────────────────┐
    │          └─────────────►│ HMAC-SHA-3-512    │
    │                         │ key = k1 || k2    │
    │                         └─────────┬─────────┘
    │                                   │
    │                                   ▼
    │                         ┌───────────────────┐
    │                         │  Master Secret    │
    │                         │    (64 bytes)     │
    │                         └─────────┬─────────┘
    │                                   │
    │                                   ▼
    │                         ┌───────────────────┐
    │                         │ HKDF-SHA-3-512    │
    │                         │ info: drbg-setup  │
    │                         └─────────┬─────────┘
    │                                   │
    │                              ┌────┴────┐
    │                              ▼         ▼
    │                         ┌───────┐ ┌───────┐
    │                         │ Key   │ │ Nonce │
    │                         │(32 B) │ │(16 B) │
    │                         └───┬───┘ └───┬───┘
    │                             │         │
    │                             └────┬────┘
    │                                  ▼
    │                         ┌───────────────────┐
    │                         │    ChaCha20       │
    │                         │     DRBG          │
    │                         └─────────┬─────────┘
    │                                   │
    │                                   ▼
    │                         ┌───────────────────┐
    │                         │ Password Generator│
    │                         │ (rejection sample)│
    │                         └─────────┬─────────┘
    │                                   │
    │                                   ▼
    │                            ┌────────────┐
    └─────────(salt)────────────►│  PASSWORD  │
                                 └────────────┘
```

### Cryptographic Components

1. **Entropy Collection (SHA-3-512):**
   - Hashes the entire Seed File using SHA-3-512.
   - Splits the 64-byte digest: first 16 bytes for salt, remaining 48 bytes for seed digest.

2. **Key Derivation (Scrypt with Domain Separation):**
   - Derives `k1` from `hyperkey-service:<service_name>` with the salt.
   - Derives `k2` from `hyperkey-passphrase:<passphrase>` with the salt.
   - Scrypt Parameters: N=2¹⁵⁻¹⁷, r=8, p=1, dklen=64.
   - Domain separation ensures that even identical service/passphrase inputs produce independent keys.

3. **Entropy Mixing (HMAC-SHA-3-512):**
   - Combines k1, k2, and seed digest via HMAC-SHA-3-512.
   - Produces a 64-byte Master Secret.

4. **DRBG Initialization (HKDF + ChaCha20):**
   - Expands Master Secret via HKDF-SHA-3-512 into 32-byte key + 16-byte nonce.
   - Initializes ChaCha20 stream cipher as a deterministic random bit generator.

5. **Password Generation:**
   - Uses unbiased rejection sampling to select characters.
   - Ensures minimum character class requirements are met.
   - Secure mode (Yellow/Red) continues sampling all classes for higher entropy.

---

## 🔒 Security Considerations

### Why SHA-3?

While Scrypt internally uses SHA-256 (per RFC 7914), we "sandwich" it with SHA-3 operations:
- **Input:** Seed file hashed with SHA-3-512 before being split into salt/digest.
- **Output:** Keys mixed with HMAC-SHA-3-512, then expanded with HKDF-SHA-3-512.

This provides defense-in-depth against potential future weaknesses in SHA-2 family functions.

### Memory Cleanup

The implementation attempts to securely erase sensitive values:
- Service name and passphrase are stored in mutable `bytearray` objects and zeroed after use.
- Derived keys are explicitly deleted and garbage collection is triggered.
- Note: Python's memory model makes guaranteed secure erasure impossible; this is a best-effort mitigation.

### Clipboard Security

By default, HyperKey automatically clears the clipboard after 30 seconds to minimize password exposure:
- A countdown timer shows the remaining time before clearing.
- Press Enter at any time to exit early without clearing (useful if you've already pasted the password).
- Use `--clipboard-timeout` to adjust the timeout (1-3600 seconds).
- Use `--no-clipboard-clear` to disable automatic clearing entirely.

**Important Clipboard Considerations:**
- Some password managers and cloud sync services may log clipboard contents.
- Clipboard history tools may store passwords even after clearing.
- For maximum security, disable clipboard history features in your operating system.
- The clipboard clearing feature provides an additional layer of security but is not foolproof.

### Remote Seed Files

- Only HTTPS URLs are accepted for remote seed files.
- SSL certificate verification is enforced.
- For maximum security, use local seed files only.

---

## 🧪 Development

### Running Tests

This repository includes a comprehensive unit test suite using Python's unittest framework. The tests use mocking to simulate file inputs and system dependencies, so no external seed files are required.

```bash
python3 -m unittest discover tests
```

### CI/CD

The project uses GitHub Actions to automatically test the code against Python 3.8, 3.10, and 3.12 on every push to the main branch.

---

## 📋 Changelog

### v2.2 (Current)
- **Automatic Clipboard Clearing:** Added configurable timeout to automatically clear clipboard after copying password (default: 30 seconds).
- **Clipboard Security Options:** New `--clipboard-timeout` and `--no-clipboard-clear` command-line options.
- **Enhanced Argument Parsing:** Switched to argparse for better command-line interface and help messages.
- **Improved User Experience:** Countdown timer with early exit option when clipboard clearing is active.
- **Comprehensive Test Coverage:** Added 5 new tests for clipboard functionality (17 total tests).

### v2.1
- **SHA-3 Throughout:** Upgraded from SHA-512 to SHA-3-512 for file hashing, HMAC, and HKDF.
- **Domain Separation:** Service and passphrase now use tagged inputs (`hyperkey-service:`, `hyperkey-passphrase:`).
- **Improved Rejection Sampling:** Optimized random number generation to reduce bias and improve efficiency.
- **Memory Cleanup:** Added explicit zeroing of mutable secrets and garbage collection.
- **HTTPS Enforcement:** Remote seed files now require HTTPS with certificate verification.
- **Better Error Handling:** Specific SSL/TLS error messages for certificate failures.

### v2.0
- Initial SHA-3 integration.
- ChaCha20-based DRBG replacing previous implementation.

### v1.x (Legacy)
- Original implementation using SHA-512 and HMAC-SHA-512.

---

## 📜 License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

---

## ⚠️ Important Notes

- **Breaking Change:** v2.x produces different passwords than v1.x due to the SHA-3 upgrade and domain separation. If you need legacy passwords, use the v1.x branch.
- **Seed File Integrity:** Any modification to your seed file (even a single byte) will produce completely different passwords. Keep backups!
- **Passphrase Strength:** HyperKey's security ultimately depends on your passphrase entropy. Use a strong, memorable passphrase.
