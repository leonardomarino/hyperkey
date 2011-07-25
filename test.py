#!/usr/bin/python

from hyperkey import main

p = main(["hyperkey","./test.txt", "red", "gmail", "this is the oficial test of hyperkey", "iamastrangeloop"],passphrase=False)

try:
    assert p == "lt*xCy2tw/IoAXKO8Zld_Jy8"
    print "[+] test succeeded"
except:
    print "[!] test failed"
