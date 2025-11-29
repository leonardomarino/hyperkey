#!/usr/bin/python3

from hyperkey import main
args = ["hyperkey","./test.txt", "red", "gmail", "iamastrangeloop"]

# Policy: red (24 chars, 8 upper, 3 num, 3 sym)
# Inputs: Seed=./test.txt, Service=gmail, Passphrase=iamastrangeloop

print(f"Testing with {len(args)} arguments: {args}")

# Run main function, disabling interactive input and clipboard
p = main(args, clipboard_enabled=False)

try:
    # This is the expected output string based on your original file's contents
    expected = "4zRfjGU"v*apsxO+r-83SKnI16c9ravY"
    assert p == expected
    print("\n[+] Test succeeded! Output matches expected deterministic password.")
except AssertionError:
    print("\n[!] Test failed!")
    print(f"[!] Expected: {expected}")
    print(f"[!] Got:      {p}")
