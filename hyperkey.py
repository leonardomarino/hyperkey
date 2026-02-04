#!/usr/bin/env python3
# -*- coding: utf-8 -*-
""" hyperkey - SOTA Password Generator (Scrypt + SHA-3 + ChaCha20-DRBG)
    Optimized for Apple Silicon (M-Series)

    v2.3 - Latest improvements:
    - Removed clipboard functionality for enhanced security
    - Passwords are now only displayed on screen, not copied to clipboard
    - Eliminates clipboard logging risks from password managers and sync services
    - Removed Android/Termux support (was not implemented)
    - Simplified codebase by removing ~125 lines of unused/insecure code

    v2.2 - Previous improvements:
    - Added automatic clipboard clearing with configurable timeout (default: 30s)
    - New command-line options: --clipboard-timeout, --no-clipboard-clear
    - Enhanced argument parsing with argparse for better UX

    v2.1 - Earlier improvements:
    - Fixed rejection sampling efficiency in CryptoRNG
    - Added domain separation for key derivation
    - Clarified password generation logic with explicit minimum vs. continue-sampling
    - Added memory cleanup for sensitive values (bytearray for mutable secrets)
    - Enforced HTTPS for remote seedfiles with specific SSL error handling
    - ChaCha20 nonce handling documented
"""

import sys
import string
import hashlib
import gc
import ssl
import argparse
from getpass import getpass
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from io import BytesIO

# --- Modern Cryptography Imports ---
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from sys import argv

# Safe subset of symbols
SAFE_SYMBOLS = '#@$%^!*+=_'

# Policy: (length, uppercase, numeric, symbol, scrypt_cost_power, secure)
# scrypt_cost_power: Power of 2 for 'N' parameter (Memory Cost).
# Green (15) = 32MB, Yellow (16) = 64MB, Red (17) = 128MB.
#
# secure=False: Stop adding character class after minimum quota met
# secure=True:  Continue sampling all character classes throughout generation
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
    
    Note on ChaCha20 nonce handling:
    The cryptography library expects a 16-byte nonce, which it internally
    treats as a 4-byte little-endian counter (bytes 0-3) and 12-byte nonce
    (bytes 4-15). We derive 16 bytes from HKDF and let the library manage
    counter increments as we consume the keystream via encrypt(zeros).
    
    This is safe because:
    - Single-use RNG instance per password generation
    - Minimal keystream consumption (<1KB typically)
    - No risk of counter wraparound (would need >256GB)
    """
    def __init__(self, master_secret):
        # Expand master secret into Key (32 bytes) and Nonce (16 bytes)
        hkdf = HKDF(
            algorithm=hashes.SHA3_512(),
            length=48,
            salt=None,
            info=b'hyperkey-drbg-setup',
        )
        expanded_secret = hkdf.derive(master_secret)
        
        key = expanded_secret[:32]
        nonce = expanded_secret[32:]  # 16 bytes: 4-byte counter + 12-byte nonce

        # Initialize ChaCha20 Stream Cipher
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        self.encryptor = cipher.encryptor()
        
        # Cleanup intermediate values
        del expanded_secret, key, nonce
        gc.collect()

    def _get_bytes(self, n):
        """Retrieves n bytes from the infinite keystream."""
        return self.encryptor.update(b'\x00' * n)

    def randrange(self, start, stop):
        """
        Unbiased secure random number in range [start, stop).
        
        Uses optimized rejection sampling that only rejects values
        in the incomplete final "bucket" rather than all values >= width.
        This reduces rejection rate from up to 50% to typically <1%.
        """
        width = stop - start
        if width <= 0:
            raise ValueError("Range must be positive")
            
        bytes_needed = (width.bit_length() + 7) // 8
        max_value = 256 ** bytes_needed
        
        # Calculate limit to avoid modulo bias
        # Values >= limit would fall into incomplete final bucket
        limit = (max_value // width) * width
        
        while True:
            random_bytes = self._get_bytes(bytes_needed)
            val = int.from_bytes(random_bytes, 'big')
            
            if val < limit:
                return start + (val % width)

    def choice(self, seq):
        """Secure random choice from sequence."""
        return seq[self.randrange(0, len(seq))]


def derive_master_key(password, salt, cost_power, domain):
    """
    Memory-Hard Key Derivation using Scrypt with Domain Separation.
    
    Uses hashlib.scrypt (OpenSSL backed).
    Note: Scrypt uses SHA-256 internally per RFC 7914.
    We mitigate this by sandwiching it with SHA-3 operations externally.
    
    Args:
        password: The password/service bytes (bytes or bytearray)
        salt: Salt bytes
        cost_power: Power of 2 for N parameter
        domain: Domain separation tag (e.g., b'service' or b'passphrase')
    
    Returns:
        64-byte derived key
    """
    n_val = 2 ** cost_power
    
    # Domain separation ensures keys for different purposes are unique
    domain_separated_input = b'hyperkey-' + domain + b':' + bytes(password)
    
    return hashlib.scrypt(
        domain_separated_input,
        salt=salt,
        n=n_val,   
        r=8,       
        p=1,       
        dklen=64,
        maxmem=1024 * 1024 * 1024  # 1GB Limit
    )


def pwgen(policy, rng, max_iterations=100000):
    """
    Generates password using the CryptoRNG instance.
    
    The generation logic distinguishes between:
    - Minimum requirements: Each character class must appear at least N times
    - Secure mode: If enabled, continues sampling all classes after minimums met
    
    Args:
        policy: Tuple of (length, uppercase, numeric, symbols, cost_power, secure)
        rng: CryptoRNG instance
        max_iterations: Safety limit to prevent infinite loops
    
    Returns:
        Generated password string
        
    Raises:
        RuntimeError: If unable to generate valid password within iteration limit
    """
    length, min_uppercase, min_numeric, min_symbols, _, secure_mode = policy
    
    for iteration in range(max_iterations):
        password_chars = []
        count_upper = 0
        count_numeric = 0
        count_symbols = 0
        used_symbols = set()  # Track which symbols have been used
        
        for _ in range(length):
            # Determine eligibility for each character class
            # In secure mode: always eligible (continues sampling)
            # In non-secure mode: eligible only until minimum quota met
            can_add_symbol = secure_mode or (count_symbols < min_symbols)
            can_add_upper = secure_mode or (count_upper < min_uppercase)
            can_add_numeric = secure_mode or (count_numeric < min_numeric)
            
            # Check if we still have unused symbols available
            available_symbols = [s for s in SAFE_SYMBOLS if s not in used_symbols]
            
            # Probabilistic selection with rejection sampling
            # Symbols: 10% chance when eligible AND unused symbols available
            if can_add_symbol and available_symbols and rng.randrange(0, 10) == 9:
                chosen_symbol = rng.choice(available_symbols)
                password_chars.append(chosen_symbol)
                used_symbols.add(chosen_symbol)
                count_symbols += 1
                continue
            
            # Uppercase: 20% chance when eligible
            if can_add_upper and rng.randrange(0, 5) == 4:
                password_chars.append(rng.choice(string.ascii_uppercase))
                count_upper += 1
                continue
            
            # Numeric: 20% chance when eligible
            if can_add_numeric and rng.randrange(0, 5) == 4:
                password_chars.append(rng.choice(string.digits))
                count_numeric += 1
                continue
            
            # Default: lowercase
            password_chars.append(rng.choice(string.ascii_lowercase))
        
        # Validate minimum requirements
        if (count_upper >= min_uppercase and 
            count_numeric >= min_numeric and 
            count_symbols >= min_symbols):
            return ''.join(password_chars)
    
    raise RuntimeError(
        f"Failed to generate password meeting requirements after {max_iterations} iterations. "
        f"Policy may be too restrictive for password length."
    )


def secure_zero(byte_obj):
    """
    Best-effort secure memory cleanup for mutable bytearrays.

    Note: This only works on bytearray objects. Immutable bytes objects
    from hashlib/hmac cannot be zeroed; we can only delete references
    and hope garbage collection clears them promptly.
    """
    if isinstance(byte_obj, bytearray):
        for i in range(len(byte_obj)):
            byte_obj[i] = 0


def validate_inputs(service, passphrase, policy):
    """
    Validate inputs meet basic security and feasibility requirements.

    Args:
        service: Service name string
        passphrase: Master passphrase string
        policy: Policy tuple (length, min_upper, min_numeric, min_symbols, cost, secure)

    Raises:
        ValueError: If inputs don't meet requirements
    """
    # Validate service name
    if not service or len(service) < 1:
        raise ValueError("Service name cannot be empty")
    if len(service) > 256:
        raise ValueError("Service name must not exceed 256 characters")

    # Check for path traversal attempts
    if '..' in service or '/' in service or '\\' in service:
        raise ValueError("Service name contains invalid characters")

    # Validate passphrase strength
    if not passphrase or len(passphrase) < 8:
        raise ValueError("Passphrase must be at least 8 characters for security")
    if len(passphrase) > 1024:
        raise ValueError("Passphrase must not exceed 1024 characters")

    # Validate policy requirements are achievable
    length, min_upper, min_numeric, min_symbols, _, _ = policy

    if min_symbols > len(SAFE_SYMBOLS):
        raise ValueError(
            f"Policy requires {min_symbols} unique symbols but only "
            f"{len(SAFE_SYMBOLS)} are available"
        )

    # Check that minimum requirements don't exceed password length
    min_required = min_upper + min_numeric + min_symbols
    if min_required > length:
        raise ValueError(
            f"Policy requirements ({min_required} characters) exceed "
            f"password length ({length})"
        )


def main(argv, output=print, passphrase=True):
    output("[!] HyperKey (SOTA v2.3): Scrypt + SHA-3 + ChaCha20-DRBG")

    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='HyperKey - Stateless password generator using Scrypt + SHA-3 + ChaCha20-DRBG',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./hyperkey.py seed.jpg green gmail
  ./hyperkey.py seed.jpg yellow banking
  ./hyperkey.py seed.jpg red root-account
  ./hyperkey.py https://example.com/seed.jpg green email

Policies:
  green  - 14 chars, 32MB RAM (daily accounts)
  yellow - 20 chars, 64MB RAM (financial/email)
  red    - 32 chars, 128MB RAM (root/crypto)
  legacy - 8 chars,  32MB RAM (legacy systems)
        """
    )

    parser.add_argument('seedfile', help='Path to seed file or HTTPS URL')
    parser.add_argument('policy', choices=['green', 'yellow', 'red', 'legacy'],
                       help='Security policy (green/yellow/red/legacy)')
    parser.add_argument('service', nargs='?', help='Service name (optional, will prompt if not provided)')
    parser.add_argument('passphrase_arg', nargs='?', metavar='passphrase',
                       help='Master passphrase (optional, will prompt if not provided)')

    # Parse arguments (skip program name)
    try:
        args = parser.parse_args(argv[1:])
    except SystemExit:
        # argparse calls sys.exit() on error, we just re-raise
        raise

    # Track mutable sensitive values for cleanup
    sensitive_values = []

    try:
        filename = args.seedfile

        if filename.lower().startswith("http"):
            # Normalize URL to lowercase for security validation
            normalized_url = filename.lower()

            if not normalized_url.startswith("https://"):
                output("[!] ERROR: Remote seedfiles must use HTTPS")
                output("[!] Change URL from http:// to https://")
                sys.exit(1)

            # Validate it's actually a proper HTTPS URL
            if not filename.startswith("https://") and not filename.startswith("HTTPS://"):
                output("[!] ERROR: URL validation failed - mixed case in protocol")
                sys.exit(1)

            output("[!] Retrieving seedfile via HTTPS")
            output("[!] WARNING: Remote seed files should be used with caution")
            ssl_context = ssl.create_default_context()

            # Use normalized https:// URL to prevent bypass attempts
            if not filename.startswith("https://"):
                filename = "https://" + filename[8:]  # Replace HTTPS:// with https://

            with urlopen(filename, context=ssl_context) as response:
                seed_data = BytesIO(response.read())
        else:
            with open(filename, "rb") as file_handle:
                seed_data = BytesIO(file_handle.read())

        policy = POLICIES[args.policy.lower()]

        if args.service:
            service = args.service
        else:
            service = getpass("service: ")

        if args.passphrase_arg:
            passphrase_input = args.passphrase_arg
        else:
            passphrase_input = getpass("[?] passphrase: ")
    except ssl.SSLError as e:
        output(f"[!] SSL/TLS Error: {e}")
        output("[!] Could not verify remote server certificate")
        sys.exit(1)
    except HTTPError as e:
        output(f"[!] HTTP Error: {e.code} - {e.reason}")
        output("[!] Could not retrieve remote seed file")
        sys.exit(1)
    except URLError as e:
        output(f"[!] URL Error: {e.reason}")
        output("[!] Could not connect to remote server")
        sys.exit(1)
    except ValueError as e:
        output(f"[!] Validation Error: {e}")
        sys.exit(1)
    except FileNotFoundError:
        output(f"[!] Error: Seed file not found: {filename}")
        sys.exit(1)
    except PermissionError:
        output(f"[!] Error: Permission denied accessing: {filename}")
        sys.exit(1)
    except Exception as e:
        output(f"[!] Error during setup: {e}")
        sys.exit(1)

    # Validate inputs before proceeding with cryptographic operations
    try:
        validate_inputs(service, passphrase_input, policy)
    except ValueError as e:
        output(f"[!] Input Validation Failed: {e}")
        sys.exit(1)

    cost_power = policy[4]
    
    try:
        # 1. Entropy Collection (SHA-3)
        print(f"[+] Hashing seed (SHA-3)...", end='', flush=True)
        seed_content = seed_data.read()
        file_hasher = hashes.Hash(hashes.SHA3_512())
        file_hasher.update(seed_content)
        full_file_digest = file_hasher.finalize()
        print("done.")

        # Split: First 16 bytes for salt, rest for secret
        salt = full_file_digest[:16]
        seed_digest = full_file_digest[16:]

        # 2. Derive Keys (Scrypt) with Domain Separation
        ram_mb = (128 * (2**cost_power) * 8) / (1024*1024)
        print(f"[+] Deriving keys (Scrypt, N=2^{cost_power}, ~{int(ram_mb)}MB RAM)...", end='', flush=True)
        
        # Use bytearray for inputs so they can be securely zeroed
        service_bytes = bytearray(service, "utf-8")
        passphrase_bytes = bytearray(passphrase_input, "utf-8")
        sensitive_values.extend([service_bytes, passphrase_bytes])
        
        # Domain-separated key derivation
        k1 = derive_master_key(service_bytes, salt, cost_power, b'service')
        k2 = derive_master_key(passphrase_bytes, salt, cost_power, b'passphrase')
        
        # Note: k1, k2 are immutable bytes from hashlib; can only del, not zero
        
        print("done.")

        # 3. Combine Entropy (HMAC-SHA-3-512)
        h = hmac.HMAC(k1 + k2, hashes.SHA3_512())
        h.update(seed_digest)
        master_secret = h.finalize()

        # 4. Initialize RNG (ChaCha20 Stream)
        rng = CryptoRNG(master_secret)

        # 5. Generate Password
        p = pwgen(policy, rng)

        output(f"[!] Generated password: {p}")
        output("[!] Done")
        return p
        
    finally:
        # Memory cleanup - zero mutable secrets
        for val in sensitive_values:
            secure_zero(val)
        
        # Delete references to immutable secrets
        try:
            del k1, k2, master_secret, seed_digest, seed_content
        except UnboundLocalError:
            pass  # Variables may not exist if error occurred early
            
        gc.collect()


if __name__ == "__main__":
    p = main(argv)
    sys.exit(0)