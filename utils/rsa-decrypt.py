#!/usr/bin/env python3

import sys
import os

from binascii import unhexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

ciphertext = unhexlify(sys.argv[1].encode())

# Use command-line argument if provided, else environment variable, else default
# Default to /tmp/acme.key for backward compatibility (not secure)
key_file_path = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('RSA_PRIVATE_KEY_PATH', '/tmp/acme.key')

with open(key_file_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

msg = private_key.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
    )
)

print(msg.decode())
