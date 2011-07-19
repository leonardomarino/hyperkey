#!/usr/bin/python
""" hyperkey - a generative approach to password management

  Generate a password given:

  * Seed file
  * Service identifier (login, whatever)
  * Passphrase 
"""
DEBUG = False
from hashlib import sha256
from getpass import getpass
import random
import string
from pbkdf import pbkdf

if DEBUG:
    import pdb

try:
    import pyperclip
    clipboard = True
except:
    clipboard = False

from sys import argv


print "[*] hyperkey 0.2 - a thoughtcrime project"
# policy: (length, uppercase, numeric, symbol, secure)
green =  ( 8, 2, 1, 0, False)
yellow = (12, 2, 2, 1, False)
red =    (24, 8, 3, 3, False)

def generate(policy):
    u,n,s = 0,0,0
    length, uppercase, numeric, symbols, secure = policy
    while (u, n, s) != (uppercase, numeric, symbols):
        p = ""
        u, n, s = 0,0,0 
        for i in range(0, length):
            if s != symbols or secure:
                if random.randrange(0,10) == 9:
                    p += random.choice(string.punctuation)
                    s += 1
                    continue
            if u != uppercase or secure:
                if random.randrange(0,5) == 4:
                    p += random.choice(string.uppercase)
                    u += 1
                    continue
            if n != numeric or secure:
                if random.randrange(0,5) == 4:
                    p += random.choice(string.digits)
                    n += 1
                    continue
            p += random.choice(string.lowercase)
    return p

filename = argv[1]
try:
    f = open(argv[1])
    if argv[2].lower()  in ["green", "yellow", "red"]:
        exec "policy = %s"%argv[2].lower()
    else:
        print "[!] policy defaulting to green"
        policy = green
    if len(argv) == 3:
        service = getpass("service:")
    else:
        service = argv[3]
except:
    print "[?] usage: hyperkey seedfile policy [service]"
    raise SystemExit

passphrase = getpass("[?] passphrase: ")
if DEBUG: pdb.set_trace()
salt = f.read(8)
print "[+] hashing: ",
s = sha256("".join(f.readlines()))
print "done. iterating:  ",
if DEBUG: pdb.set_trace()
s.update(pbkdf(service, salt))
if DEBUG: pdb.set_trace()
s.update(pbkdf(passphrase, salt))
print "done."
random.seed(int(s.hexdigest(),16))

print "[+] generating:",
p = generate(policy)
print "done."

print "[!] generated password: %s"%p
if clipboard:
    pyperclip.setcb(p)
    print "[+] copied to clipboard"
print "[/] we're done here"
