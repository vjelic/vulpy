#!/usr/bin/env python3

import re
import sys
import os

def main():
    # Accept file path as command-line argument
    if len(sys.argv) < 2:
        print("Usage: cutpasswd.py <password_file>", file=sys.stderr)
        print("Filters passwords to show only those meeting complexity requirements:", file=sys.stderr)
        print("  - At least 12 characters", file=sys.stderr)
        print("  - Contains lowercase letters", file=sys.stderr)
        print("  - Contains uppercase letters", file=sys.stderr)
        print("  - Contains digits", file=sys.stderr)
        sys.exit(1)
    
    password_file = sys.argv[1]
    
    # Validate that the file exists and is readable
    if not os.path.isfile(password_file):
        print(f"Error: File '{password_file}' does not exist", file=sys.stderr)
        sys.exit(1)
    
    if not os.access(password_file, os.R_OK):
        print(f"Error: File '{password_file}' is not readable", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(password_file, 'r') as f:
            for password in f.readlines():
                password = password.strip()

                if len(password) < 12:
                    continue

                if len(re.findall(r'[a-z]', password)) < 1:
                    continue

                if len(re.findall(r'[A-Z]', password)) < 1:
                    continue

                if len(re.findall(r'[0-9]', password)) < 1:
                    continue

                print(password)
    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()

