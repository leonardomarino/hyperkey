#!/usr/bin/python

from hyperkey import main
args = ["hyperkey","./test.txt", "red", "gmail", "iamastrangeloop"]
print len(args)
p = main(args, passphrase=False, clipboard=False)

try:
    assert p == "lt*xCy2tw/IoAXKO8Zld_Jy8"
    print "[+] test succeeded"
except:
    print "[!] test failed"
