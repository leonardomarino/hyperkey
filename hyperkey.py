#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" hyperkey - SOTA Password Generator (Scrypt + ChaCha20-DRBG)
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
# Green  (15) = 32MB  | 14 chars (Modern Baseline)
# Yellow (16) = 64MB  | 20 chars (Strong)
# Red    (17) = 128MB | 32 chars (Paranoid)
# Legacy (15) = 32MB  | 8 chars  (Only for old systems with length limits)

POLICIES = {
    # "Green": 14 chars. Enough for 99% of sites, very strong against brute force.
    "green": (14, 2, 2, 1, 15, False),

    # "Yellow": 20 chars. Excellent for banking/crypto logins.
    "yellow": (20, 4, 4, 2, 16, True),

    # "Red": 32 chars. Maximum security. 
    # Increased symbols to 4 to ensure high entropy density.
    "red": (32, 8, 6, 4, 17, True),
    
    # "Legacy": 8 chars. Keep this only for dumb websites that limit passwords to 8-10 chars.
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
        hkdf = HKDF(
            algorithm=hashes.SHA512(),
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
    - n: 2^cost_power (Memory Cost)
    - r: 8 (Block size)
    - p: 1 (Parallelism)
    - maxmem: Set to 1GB (1073741824 bytes). 
              This allows Red policy (128MB) but stays under the 2GB signed integer limit.
    """
    n_val = 2 ** cost_power
    
    return hashlib.scrypt(
        password,
        salt=salt,
        n=n_val,   
        r=8,       
        p=1,       
        dklen=64,
        maxmem=1024 * 1024 * 1024 # FIX: Set to 1GB to avoid overflow
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
    output("[!] HyperKey (SOTA): Scrypt + ChaCha20-DRBG")
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
    
    salt = seed_data.read(16) 
    seed_rest = seed_data.read()

    # 1. Initial Hash
    print(f"[+] hashing seed...", end='', flush=True)
    seed_hash = hashes.Hash(hashes.SHA3_512())
    seed_hash.update(seed_rest)
    seed_digest = seed_hash.finalize()
    print("done.")

    # 2. Derive Keys (Scrypt)
    # Display actual RAM usage: 128 * N * r bytes (roughly)
    ram_mb = (128 * (2**cost_power) * 8) / (1024*1024)
    print(f"[+] deriving keys (Scrypt, N=2^{cost_power}, ~{int(ram_mb)}MB RAM)...", end='', flush=True)
    
    k1 = derive_master_key(bytes(service, "utf-8"), salt, cost_power)
    k2 = derive_master_key(bytes(passphrase, "utf-8"), salt, cost_power)
    
    print("done.")

    # 3. Combine Entropy (HMAC-SHA512)
    h = hmac.HMAC(k1 + k2, hashes.SHA3_512())
    h.update(seed_digest)
    master_secret = h.finalize()

    # 4. Initialize RNG (ChaCha20 Stream)
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
