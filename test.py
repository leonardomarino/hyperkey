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
    expected = 'lg8vRV7F0ops1!#6Vj1uK[QC;kYknzT:'
    assert p == expected
    print("\n[+] Test succeeded! Output matches expected deterministic password.")
except AssertionError:
    print("\n[!] Test failed!")
    print(f"[!] Expected: {expected}")
    print(f"[!] Got:      {p}")
