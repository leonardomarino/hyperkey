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
import sys

if DEBUG:
    import pdb

try:
    import pyperclip
    clipboard = True
except:
    clipboard = False

try:
    import android
    droid = android.Android()
    Droid = True
except :
    Droid = False

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

def main(argv, output=_print, passphrase=True, clipboard=clipboard):
    print "[!] this is hyperkey, a thoughtcrime project"
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
        if len(argv) == 5:
            passphrase = argv[4]
        else:
            passphrase = getpass("[?] passphrase: ")
    except:
        print "[?] usage: hyperkey seedfile policy [service] [passphrase]"
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

def droidMain():
    """shitty droid frontend"""

    droid.dialogCreateAlert("Policy")
    policies = ["green", "yellow", "red"]
    droid.dialogSetItems(policies)
    droid.dialogSetPositiveButtonText("OK")
    droid.dialogShow()
    result = droid.dialogGetResponse().result
    policy = policies[result['item']]

    
    droid.dialogGetPassword("","Service ID:")
    droid.dialogSetPositiveButtonText("OK")
    droid.dialogShow()
    result = droid.dialogGetResponse().result
    if result['which'] == 'positive':
        sid = result['value']
    else:
        sys.exit()
    
    droid.dialogGetPassword("","Passphrase")
    droid.setPositiveButtonText("OK")
    droid.dialogShow()
    result = droid.dialogGetResponse().result
    if result['which'] == 'positive':
        pw = result['value']
    else:
        raise SystemExit

    droid.dialogCreateSpinnerProgress("Hashing...")
    droid.dialogShow()
    p = main([str("hyperkey"), str("/sdcard/sl4a/scripts/hyperkey.py"), str(policy), str(sid), str(pw)])
    droid.dialogDismiss()

    droid.setClipboard(p)
    droid.dialogCreateAlert("Copied to Clipboard","\n%s\n"%p)
    droid.dialogSetPositiveButtonText("w00t")
    droid.dialogShow()
    result = droid.dialogGetResponse()
    sys.exit()

if __name__ == "__main__":
    p = main(argv) if not Droid else droidMain()
    raise SystemExit 
