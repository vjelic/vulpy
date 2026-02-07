#!/usr/bin/env python3

import sys

from binascii import unhexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

if len(sys.argv) < 3:
    print("Usage: rsa-verify.py <message> <signature_hex> [public_key_file]")
    sys.exit(1)

msg = sys.argv[1].encode()
signature = unhexlify(sys.argv[2])
public_key_file = sys.argv[3] if len(sys.argv) > 3 else "/tmp/acme.pub"

with open(public_key_file, "rb") as key_file:
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
