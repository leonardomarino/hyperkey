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

# policy: (length, uppercase, numeric, symbol, workfactor, secure)
green =  ( 8, 2, 1, 0, 7, False)
yellow = (12, 2, 2, 1, 9, True)
red =    (24, 8, 3, 3, 10, True)

def _print(x):
    print x

def _noprint(x):
    pass

def pwgen(policy):
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

def main(argv, output=_print, passphrase=True):
    try:
        filename = argv[1]
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
        if len(argv) >= 4:
            service = argv[3]
        else:
            service = getpass("service:")
        if len(argv) == 6:
            passphrase = argv[5]
        else:
            passphrase = getpass("[?] passphrase: ")
    except:
        print "[?] usage: hyperkey seedfile policy [service]"
        raise SystemExit
    itercount = policy[4]**5

    salt = f.read(8)
    print "[+] hashing:",
    s = sha256("".join(f.readlines()))
    print "done."
    print "[+] iterating: ",
    s.update(pbkdf(service, salt, itercount))
    s.update(pbkdf(passphrase, salt, itercount))
    print "done."
    random.seed(int(s.hexdigest(),16))

    p = pwgen(policy)

    print "[!] generated password: %s"%p
    if clipboard:
        pyperclip.setcb(p)
        print "[+] copied to clipboard"
    print "[!] we're done here"
    return p

if __name__ == "__main__":
    p = main(argv)
