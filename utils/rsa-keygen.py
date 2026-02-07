#!/usr/bin/env python3

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

# Securely create private key file with restricted permissions (owner read/write only)
# Check for symlinks to prevent symlink attacks
private_key_path = '/tmp/acme.key'
if os.path.islink(private_key_path):
    raise OSError(f"Refusing to overwrite symlink at {private_key_path}")

fd_private = os.open(private_key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd_private, 'wb') as out:
    out.write(pem_private)

# Securely create public key file with appropriate permissions
# Check for symlinks to prevent symlink attacks
public_key_path = '/tmp/acme.pub'
if os.path.islink(public_key_path):
    raise OSError(f"Refusing to overwrite symlink at {public_key_path}")

fd_public = os.open(public_key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
with os.fdopen(fd_public, 'wb') as out:
    out.write(pem_public)

print('Created files in /tmp/acme.key and /tmp/acme.pub')

