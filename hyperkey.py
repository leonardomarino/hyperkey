#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" hyperkey - SOTA Password Generator (Scrypt + SHA-3 + ChaCha20-DRBG)
    Optimized for Apple Silicon (M-Series)
"""

import sys
import string
import struct
import hashlib
from getpass import getpass
from urllib.request import urlopen
from io import BytesIO

# --- Modern Cryptography Imports ---
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Optional Imports
try:
    import pyperclip
    CLIPBOARD_ENABLED = True
except ImportError:
    CLIPBOARD_ENABLED = False

try:
    import android
    droid = android.Android()
    DROID_ENABLED = True
except ImportError:
    DROID_ENABLED = False

from sys import argv

# Policy: (length, uppercase, numeric, symbol, scrypt_cost_power, secure)
# scrypt_cost_power: Power of 2 for 'N' parameter (Memory Cost).
# Green (15) = 32MB, Yellow (16) = 64MB, Red (17) = 128MB.
POLICIES = {
    "green": (14, 2, 2, 1, 15, False),
    "yellow": (20, 4, 4, 2, 16, True),
    "red": (32, 8, 6, 4, 17, True),
    "legacy": (8, 2, 2, 1, 15, False)
}

# --- Cryptographic Core ---

class CryptoRNG:
    """
    A Deterministic Random Bit Generator (DRBG) based on ChaCha20.
    Provides an infinite stream of cryptographically secure bytes.
    """
    def __init__(self, master_secret):
        # 1. Expand master secret into Key (32 bytes) and Nonce (16 bytes)
        # UPGRADE: Using SHA-3-512 for the HKDF expansion
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=48,
            salt=None,
            info=b'hyperkey-drbg-setup',
        )
        expanded_secret = hkdf.derive(master_secret)
        
        key = expanded_secret[:32]
        nonce = expanded_secret[32:] 

        # 2. Initialize ChaCha20 Stream Cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        self.encryptor = cipher.encryptor()

    def _get_bytes(self, n):
        """Retreives n bytes from the infinite stream."""
        return self.encryptor.update(b'\x00' * n)

    def randrange(self, start, stop):
        """Unbiased secure random number in range."""
        width = stop - start
        if width <= 0:
            raise ValueError("Range must be positive")
            
        bytes_needed = (width.bit_length() + 7) // 8
        
        while True:
            random_bytes = self._get_bytes(bytes_needed)
            val = int.from_bytes(random_bytes, 'big')
            
            # Rejection sampling to avoid modulo bias
            if val < width:
                return start + val

    def choice(self, seq):
        """Secure random choice from sequence."""
        return seq[self.randrange(0, len(seq))]


def derive_master_key(password, salt, cost_power):
    """
    STATE OF THE ART: Scrypt (Native)
    Memory-Hard Key Derivation Function.
    
    Uses hashlib.scrypt (OpenSSL backed).
    Note: Scrypt uses SHA-256 internally per RFC 7914.
    We mitigate this by sandwiching it with SHA-3 operations externally.
    """
    n_val = 2 ** cost_power
    
    return hashlib.scrypt(
        password,
        salt=salt,
        n=n_val,   
        r=8,       
        p=1,       
        dklen=64,
        maxmem=1024 * 1024 * 1024 # 1GB Limit
    )


def pwgen(policy, rng):
    """
    Generates password using the CryptoRNG instance.
    """
    u, n, s = 0, 0, 0
    length, uppercase, numeric, symbols, iterations, secure = policy
    
    p = ""
    
    # Deterministic loop with Rejection Sampling
    while (u, n, s) != (uppercase, numeric, symbols):
        p = ""
        u, n, s = 0, 0, 0 
        for i in range(length):
            
            if s != symbols or secure:
                if rng.randrange(0, 10) == 9:
                    p += rng.choice(string.punctuation)
                    s += 1
                    continue
            
            if u != uppercase or secure:
                if rng.randrange(0, 5) == 4:
                    p += rng.choice(string.ascii_uppercase)
                    u += 1
                    continue
            
            if n != numeric or secure:
                if rng.randrange(0, 5) == 4:
                    p += rng.choice(string.digits)
                    n += 1
                    continue
            
            p += rng.choice(string.ascii_lowercase)
            
    return p


def main(argv, output=print, passphrase=True, clipboard_enabled=CLIPBOARD_ENABLED):
    output("[!] HyperKey (SOTA): Scrypt + SHA-3 + ChaCha20-DRBG")
    try:
        filename = argv[1]
        
        if filename.lower().startswith("http"):
            output("[!] retreiving seedfile via http")
            with urlopen(filename) as response:
                seed_data = BytesIO(response.read())
        else:
            with open(filename, "rb") as file_handle:
                seed_data = BytesIO(file_handle.read())
                
        if argv[2].lower() in POLICIES:
            policy = POLICIES[argv[2].lower()]
        else:
            output("[!] policy defaulting to green")
            policy = POLICIES["green"]
            
        if len(argv) >= 4:
            service = argv[3]
        else:
            service = getpass("service: ")
            
        if len(argv) >= 5:
            passphrase = argv[4]
        else:
            passphrase = getpass("[?] passphrase: ")
            
    except IndexError:
        output("[?] usage: hyperkey seedfile policy [service] [passphrase]")
        sys.exit(1)
    except Exception as e:
        output(f"Error during setup: {e}")
        sys.exit(1)

    # CONFIG: Scrypt Cost (Power of 2)
    cost_power = policy[4]
    
    # 1. Entropy Collection (Hash-then-Split)
    print(f"[+] hashing seed (SHA-3)...", end='', flush=True)
    seed_content = seed_data.read()
    file_hasher = hashes.Hash(hashes.SHA3_512())
    file_hasher.update(seed_content)
    full_file_digest = file_hasher.finalize()
    print("done.")

    # Split: First 16 bytes for salt, rest for secret
    salt = full_file_digest[:16]
    seed_digest = full_file_digest[16:]

    # 2. Derive Keys (Scrypt)
    ram_mb = (128 * (2**cost_power) * 8) / (1024*1024)
    print(f"[+] deriving keys (Scrypt, N=2^{cost_power}, ~{int(ram_mb)}MB RAM)...", end='', flush=True)
    
    k1 = derive_master_key(bytes(service, "utf-8"), salt, cost_power)
    k2 = derive_master_key(bytes(passphrase, "utf-8"), salt, cost_power)
    
    print("done.")

    # 3. Combine Entropy (HMAC-SHA-3-512)
    # UPGRADE: Using HMAC-SHA-3-512 for mixing
    h = hmac.HMAC(k1 + k2, hashes.SHA3_512())
    h.update(seed_digest)
    master_secret = h.finalize()

    # 4. Initialize RNG (ChaCha20 Stream) with SHA-3 HKDF
    rng = CryptoRNG(master_secret)

    # 5. Generate Password
    p = pwgen(policy, rng)

    output(f"[!] generated password: {p}")
    if clipboard_enabled:
        try:
            pyperclip.copy(p)
            output("[+] copied to clipboard")
        except Exception as e:
            output(f"[!] Failed to copy to clipboard: {e}")
            
    output("[!] done")
    return p

def droidMain():
    sys.exit(0)

if __name__ == "__main__":
    if not DROID_ENABLED:
        p = main(argv) 
    else:
        p = droidMain()
    
    sys.exit(0)
