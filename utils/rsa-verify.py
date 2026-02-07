#!/usr/bin/env python3

import sys
import os

from binascii import unhexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

msg = sys.argv[1].encode()
signature = unhexlify(sys.argv[2])

# Use environment variable or command-line argument for key file path
# Default to /tmp/acme.pub for backward compatibility (not secure)
key_file_path = os.environ.get('RSA_PUBLIC_KEY_PATH', sys.argv[3] if len(sys.argv) > 3 else '/tmp/acme.pub')

with open(key_file_path, "rb") as key_file:
    public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend()
    )

chosen_hash = hashes.SHA256()
hasher = hashes.Hash(chosen_hash, default_backend())
hasher.update(msg)
digest = hasher.finalize()

try:
    public_key.verify(
        signature,
        msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print('Verified')
except InvalidSignature:
    print('Error')
