import unittest
import sys
import os
import string
import time
from unittest.mock import patch, MagicMock, call

# Add parent directory to path so we can import hyperkey
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import hyperkey

class TestHyperKey(unittest.TestCase):

    def setUp(self):
        # Create a dummy seed file for testing (32 bytes of zeros)
        self.dummy_seed_content = b'\x00' * 32
        # A dummy master secret for RNG testing
        self.dummy_secret = b'A' * 64

    # --- 1. Test CryptoRNG (ChaCha20) ---
    def test_rng_determinism(self):
        """Ensure the RNG produces the same sequence for the same secret."""
        print("\n[TEST] Verifying RNG Determinism...")
        rng1 = hyperkey.CryptoRNG(self.dummy_secret)
        val1 = rng1.randrange(0, 1000)
        rng2 = hyperkey.CryptoRNG(self.dummy_secret)
        val2 = rng2.randrange(0, 1000)
        self.assertEqual(val1, val2, "RNG should be deterministic")
        print("[TEST] RNG Determinism: OK")

    def test_rng_unbiased_range(self):
        """Basic check that randrange respects bounds."""
        print("\n[TEST] Verifying RNG Bounds...")
        rng = hyperkey.CryptoRNG(self.dummy_secret)
        for _ in range(100):
            val = rng.randrange(5, 10)
            self.assertGreaterEqual(val, 5)
            self.assertLess(val, 10)
        print("[TEST] RNG Bounds: OK")

    # --- 2. Test Key Derivation (Scrypt) ---
    def test_domain_separation(self):
        """Ensure different domains produce different keys."""
        print("\n[TEST] Verifying Domain Separation...")
        salt = b'salt123456789012'
        cost_power = 2 
        k1 = hyperkey.derive_master_key(b'password', salt, cost_power, b'domain_A')
        k2 = hyperkey.derive_master_key(b'password', salt, cost_power, b'domain_B')
        self.assertNotEqual(k1, k2, "Keys must differ if domains differ")
        print("[TEST] Domain Separation: OK")

    # --- 3. Test Password Generation Logic ---
    def test_pwgen_length_and_content(self):
        """Verify password meets policy length and character classes."""
        print("\n[TEST] Verifying Password Complexity Logic...")
        rng = hyperkey.CryptoRNG(self.dummy_secret)
        policy = (12, 2, 2, 2, 1, True)
        password = hyperkey.pwgen(policy, rng)
        
        self.assertEqual(len(password), 12)
        self.assertTrue(any(c.isupper() for c in password), "Must contain uppercase")
        self.assertTrue(any(c.isdigit() for c in password), "Must contain numbers")
        self.assertTrue(any(c in string.punctuation for c in password), "Must contain symbols")
        print("[TEST] Password Complexity: OK")

    # --- 4. Integration Test (Main Function) ---
    @patch('hyperkey.getpass')
    def test_main_deterministic_output(self, mock_getpass):
        """
        Full integration test.
        Now runs in VERBOSE mode so you can see the script output.
        """
        print("\n[TEST] Starting Full Integration Test...")
        mock_getpass.return_value = "passphrase123"

        # Mock file opening
        with patch('builtins.open', unittest.mock.mock_open(read_data=self.dummy_seed_content)):

            # Reduce Scrypt cost for speed
            original_policy = hyperkey.POLICIES['green']
            hyperkey.POLICIES['green'] = (14, 2, 2, 1, 1, False)

            try:
                args = ['hyperkey.py', 'dummy_seed.bin', 'green', 'myservice']

                print("--> Running Main() Iteration 1:")
                # CHANGE: output=print (Real printing!)
                p1 = hyperkey.main(args, output=print)

                print("\n--> Running Main() Iteration 2:")
                p2 = hyperkey.main(args, output=print)

                # Check consistency
                self.assertEqual(p1, p2)
                self.assertTrue(len(p1) > 0)

            finally:
                # Restore state
                hyperkey.POLICIES['green'] = original_policy
        print("[TEST] Integration Test: OK")

    # --- 5. Error Handling ---
    def test_invalid_args(self):
        """Ensure script exits gracefully on missing args."""
        print("\n[TEST] Verifying Error Handling...")
        # Use a dummy printer for this one to keep the error log clean-ish
        dummy_print = MagicMock()
        with self.assertRaises(SystemExit) as cm:
            hyperkey.main(['hyperkey.py'], output=dummy_print)
        # argparse exits with code 2 for argument errors
        self.assertEqual(cm.exception.code, 2)
        print("[TEST] Error Handling: OK")

    # --- 6. Input Validation Tests ---
    def test_validate_empty_service(self):
        """Test that empty service name is rejected."""
        print("\n[TEST] Testing Empty Service Validation...")
        policy = hyperkey.POLICIES['green']
        with self.assertRaises(ValueError) as cm:
            hyperkey.validate_inputs('', 'validpassphrase123', policy)
        self.assertIn("cannot be empty", str(cm.exception))
        print("[TEST] Empty Service Validation: OK")

    def test_validate_service_path_traversal(self):
        """Test that path traversal attempts are rejected."""
        print("\n[TEST] Testing Path Traversal Protection...")
        policy = hyperkey.POLICIES['green']

        with self.assertRaises(ValueError) as cm:
            hyperkey.validate_inputs('../etc/passwd', 'validpassphrase123', policy)
        self.assertIn("invalid characters", str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            hyperkey.validate_inputs('service/name', 'validpassphrase123', policy)
        self.assertIn("invalid characters", str(cm.exception))

        print("[TEST] Path Traversal Protection: OK")

    def test_validate_weak_passphrase(self):
        """Test that weak passphrases are rejected."""
        print("\n[TEST] Testing Weak Passphrase Rejection...")
        policy = hyperkey.POLICIES['green']

        with self.assertRaises(ValueError) as cm:
            hyperkey.validate_inputs('myservice', 'short', policy)
        self.assertIn("at least 8 characters", str(cm.exception))
        print("[TEST] Weak Passphrase Rejection: OK")

    def test_validate_excessive_lengths(self):
        """Test that excessively long inputs are rejected."""
        print("\n[TEST] Testing Length Limits...")
        policy = hyperkey.POLICIES['green']

        # Service name too long
        long_service = 'a' * 300
        with self.assertRaises(ValueError) as cm:
            hyperkey.validate_inputs(long_service, 'validpassphrase123', policy)
        self.assertIn("must not exceed 256", str(cm.exception))

        # Passphrase too long
        long_passphrase = 'a' * 2000
        with self.assertRaises(ValueError) as cm:
            hyperkey.validate_inputs('myservice', long_passphrase, policy)
        self.assertIn("must not exceed 1024", str(cm.exception))

        print("[TEST] Length Limits: OK")

    def test_validate_impossible_policy(self):
        """Test that policies with impossible requirements are rejected."""
        print("\n[TEST] Testing Impossible Policy Detection...")

        # Policy requiring more symbols than available
        impossible_policy = (14, 2, 2, 15, 15, False)  # 15 symbols but only 10 available
        with self.assertRaises(ValueError) as cm:
            hyperkey.validate_inputs('myservice', 'validpassphrase123', impossible_policy)
        self.assertIn("only", str(cm.exception))

        # Policy where minimums exceed length
        too_restrictive = (10, 5, 5, 5, 15, False)  # 15 chars needed but length is 10
        with self.assertRaises(ValueError) as cm:
            hyperkey.validate_inputs('myservice', 'validpassphrase123', too_restrictive)
        self.assertIn("exceed password length", str(cm.exception))

        print("[TEST] Impossible Policy Detection: OK")

    def test_validate_valid_inputs(self):
        """Test that valid inputs pass validation."""
        print("\n[TEST] Testing Valid Input Acceptance...")
        policy = hyperkey.POLICIES['green']

        # Should not raise any exceptions
        try:
            hyperkey.validate_inputs('myservice', 'validpassphrase123', policy)
            hyperkey.validate_inputs('gmail', 'this-is-a-secure-passphrase', policy)
            hyperkey.validate_inputs('My_Service123', 'P@ssw0rd!SecurePhrase', policy)
        except ValueError as e:
            self.fail(f"Valid inputs were rejected: {e}")

        print("[TEST] Valid Input Acceptance: OK")

if __name__ == '__main__':
    unittest.main()
