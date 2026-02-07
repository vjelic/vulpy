#!/usr/bin/env python3

import shlex
import subprocess
import sys

program = shlex.quote(sys.argv[1])
username = shlex.quote(sys.argv[2])

passwords = [
    '1',
    '12',
    '123',
    '1234',
    '12345',
    '123456',
    '12345678',
    '123123123',
]

for password in passwords:
    quoted_password = shlex.quote(password)
    result = subprocess.run([program, username, quoted_password], stdout=subprocess.DEVNULL)
    if result.returncode == 0:
        print("cracked! user: {} password: {}".format(username, password))
        break

