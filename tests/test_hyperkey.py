import unittest
import sys
import os
import string
from unittest.mock import patch, MagicMock

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
        
        # Mock Clipboard (Logic verification only)
        mock_clip = MagicMock()
        
        # Robust Fix: Inject mock if library is missing
        original_clip = getattr(hyperkey, 'pyperclip', None)
        hyperkey.pyperclip = mock_clip
        
        # Mock file opening
        with patch('builtins.open', unittest.mock.mock_open(read_data=self.dummy_seed_content)):
            
            # Reduce Scrypt cost for speed
            original_policy = hyperkey.POLICIES['green']
            hyperkey.POLICIES['green'] = (14, 2, 2, 1, 1, False) 
            
            try:
                args = ['hyperkey.py', 'dummy_seed.bin', 'green', 'myservice']
                
                print("--> Running Main() Iteration 1:")
                # CHANGE: output=print (Real printing!)
                p1 = hyperkey.main(args, output=print, clipboard_enabled=True)
                
                print("\n--> Running Main() Iteration 2:")
                p2 = hyperkey.main(args, output=print, clipboard_enabled=True)
                
                # Check consistency
                self.assertEqual(p1, p2)
                self.assertTrue(len(p1) > 0)
                
                # Verify clipboard
                if mock_clip.copy.called:
                    print("\n[TEST] Clipboard Logic: OK (Copy attempted)")
                else:
                    self.fail("Clipboard copy was not attempted")
                
            finally:
                # Restore state
                hyperkey.POLICIES['green'] = original_policy
                if original_clip:
                    hyperkey.pyperclip = original_clip
                else:
                    del hyperkey.pyperclip
        print("[TEST] Integration Test: OK")

    # --- 5. Error Handling ---
    def test_invalid_args(self):
        """Ensure script exits gracefully on missing args."""
        print("\n[TEST] Verifying Error Handling...")
        # Use a dummy printer for this one to keep the error log clean-ish
        dummy_print = MagicMock() 
        with self.assertRaises(SystemExit) as cm:
            hyperkey.main(['hyperkey.py'], output=dummy_print)
        self.assertEqual(cm.exception.code, 1)
        print("[TEST] Error Handling: OK")

if __name__ == '__main__':
    unittest.main()
