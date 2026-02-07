#!/usr/bin/env python3

import sys
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

pem_public = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Use command-line arguments for output paths
# Default to /tmp/acme.key and /tmp/acme.pub for backward compatibility (not secure)
private_key_path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/acme.key'
public_key_path = sys.argv[2] if len(sys.argv) > 2 else '/tmp/acme.pub'

with open(private_key_path, 'wb') as out:
    out.write(pem_private)

with open(public_key_path, 'wb') as out:
    out.write(pem_public)

print(f'Created files in {private_key_path} and {public_key_path}')

