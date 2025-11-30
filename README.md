# HyperKey: Deterministic Password Generator

[![Python CI - Hyperkey](https://github.com/leonardomarino/hyperkey/actions/workflows/ci.yml/badge.svg)](https://github.com/leonardomarino/hyperkey/actions/workflows/ci.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

**HyperKey** is a command-line utility for generating cryptographically secure, **deterministic passwords**. Unlike traditional password managers that store your secrets in an encrypted database (which can be stolen, corrupted, or synced to the cloud), HyperKey **calculates** your password on the fly using a combination of a seed file and a passphrase.

If you lose your database in a traditional manager, you lose your passwords. With HyperKey, as long as you have your seed file (e.g., a photo, a song, a random binary file) and your memory, you can recover your credentials anywhere.

---

## 🚀 Features

* **Robust Cryptography:**
    * **Algorithm:** Uses **Scrypt** (Memory-Hard) for key derivation to neutralize GPU/ASIC cracking attacks.
    * **Entropy Source:** Replaces Python's standard random generator with a **ChaCha20 Stream Cipher DRBG**.
    * **Hashing:** Uses **SHA-3-512 (Keccak)** and **HMAC-SHA-3** for mixing entropy sources, providing immunity to length-extension attacks.
* **Deterministic:** The same inputs (*Seed File + Service Name + Passphrase*) always produce the exact same password.
* **Stateless:** No database file to sync, back up, or lose.
* **Cross-Platform:** Works on macOS (Apple Silicon optimized), Linux, and Windows.
* **Secure Policies:** Pre-defined complexity rules (Green, Yellow, Red) to match different security needs.

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
./hyperkey.py [SEED_FILE] [POLICY] [SERVICE_NAME] [PASSPHRASE]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `SEED_FILE` | Any file on your computer (image, song, random bytes). This acts as your "Master Key File." |
| `POLICY` | The complexity level (`green`, `yellow`, `red`, `legacy`). |
| `SERVICE_NAME` | The identifier for the account (e.g., `gmail`, `twitter`, `bank`). |
| `PASSPHRASE` | Your memorized master password. (If omitted, you will be prompted securely). |

### Example
```bash
./hyperkey.py my_photo.jpg red google
```

**What happens:**

1. The script hashes `my_photo.jpg` and mixes it with the service name "google".
2. It prompts you for your passphrase (hidden input).
3. It performs a memory-hard Scrypt calculation (using 128MB RAM for the "red" policy).
4. It generates a 32-character complex password and automatically copies it to your clipboard.

---

## 🛡️ Security Policies

The policy determines the password length, complexity, and the computational "Cost" required to generate it.

| Policy | Length | Composition | Scrypt Cost (RAM) | Use Case |
|--------|--------|-------------|-------------------|----------|
| Green | 14 | Upper, Num, Sym | 2¹⁵ (32 MB) | Daily accounts, standard logins. |
| Yellow | 20 | High Complexity | 2¹⁶ (64 MB) | Financial, Email, Important logins. |
| Red | 32 | Extreme Complexity | 2¹⁷ (128 MB) | Root passwords, Crypto wallets, Master keys. |
| Legacy | 8 | Upper, Num, Sym | 2¹⁵ (32 MB) | Old systems with strict length limits. |

---

## 🧠 Theory of Operation

HyperKey implements a "Stateless Password Manager" model using the following cryptographic pipeline:

1. **Entropy Collection:**
   - Hashes the entire Seed File using SHA-3-512 to ensure uniform entropy distribution.
   - Extracts the first 16 bytes of the hash to use as a unique Salt (avoiding file header/magic byte collisions).
   - Uses the remaining hash bytes as the secret for the final mixing step.

2. **Key Derivation (KDF):**
   - Uses Scrypt to derive keys from the Service Name and Passphrase.
   - Scrypt Parameters: N=2¹⁵⁻¹⁷, r=8, p=1. This forces the attacker to use massive amounts of RAM for every single guess, making GPU cracking economically unfeasible.

3. **Mixing:**
   - Uses HMAC-SHA-3-512 to combine the file hash and derived keys into a single 512-bit Master Secret.

4. **Deterministic Generation (DRBG):**
   - Initializes a ChaCha20 stream cipher using the Master Secret.
   - Generates an infinite stream of cryptographically secure random bytes.
   - Uses these bytes to select password characters based on the chosen Policy.

---

## 🧪 Development

### Running Tests

This repository includes a deterministic test suite to ensure algorithm stability across updates and platforms.

**Run the test:**
```bash
python3 test.py
```

The test verifies that the algorithm produces the expected deterministic output:
```python
# Test parameters
Seed file: ./test.txt
Policy: red (32 chars)
Service: gmail
Passphrase: iamastrangeloop

# Expected output
Expected: ';m8la,ehNVX|mswKjG32i6aTIgAi@7g7'
```

If the test passes, you'll see:
```
[+] Test succeeded! Output matches expected deterministic password.
```

### CI/CD

The project uses GitHub Actions to automatically test the code against Python 3.8, 3.10, and 3.12 on every push to the main branch.

---

## 📜 License

This project is licensed under the GPLv3 License. See the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This tool is provided "as is" without warranty of any kind. While it uses industry-standard cryptographic primitives (Scrypt, ChaCha20, SHA-3-512), you are responsible for the safe storage of your Seed File and Passphrase. **If you lose your Seed File, your passwords cannot be recovered.** Backup your seed file securely!
