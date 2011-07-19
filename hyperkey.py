#!/usr/bin/python
""" hyperkey - a generative approach to password management

  Generates a password given:

  * Seed file
  * Service identifier (login, whatever)
  * Passphrase 
"""
DEBUG = False
from hashlib import sha256
from getpass import getpass
from urllib2 import urlopen
from StringIO import StringIO
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
# policy: (length, uppercase, numeric, symbol, workfactor, secure)
green =  ( 8, 2, 1, 0, 7, False)
yellow = (12, 2, 2, 1, 9, True)
red =    (24, 8, 3, 3, 10, True)

def generate(policy):
    u,n,s = 0,0,0
    length, uppercase, numeric, symbols, iterations, secure = policy
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
    if filename[:4] == "http":
        print "[!] retreiving seedfile via http"
        f = StringIO(urlopen(filename).read())
    else:
        f = open(filename)
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
itercount = policy[4]**5

salt = f.read(8)
print "[+] hashing:",
s = sha256("".join(f.readlines()))
print "done.\n[+] iterating: ",
s.update(pbkdf(service, salt, itercount))
s.update(pbkdf(passphrase, salt, itercount))
print "done."
random.seed(int(s.hexdigest(),16))

p = generate(policy)

print "[!] generated password: %s"%p
if clipboard:
    pyperclip.setcb(p)
    print "[+] copied to clipboard"
print "[!] we're done here"
