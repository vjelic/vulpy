#!/usr/bin/env python3

import tempfile
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

# Create a secure temporary directory with unpredictable name
temp_dir = tempfile.mkdtemp()
key_path = os.path.join(temp_dir, 'acme.key')
pub_path = os.path.join(temp_dir, 'acme.pub')

with open(key_path, 'wb') as out:
    out.write(pem_private)

with open(pub_path, 'wb') as out:
    out.write(pem_public)

print(f'Created files in {key_path} and {pub_path}')
print(f'Note: Files will persist until you manually delete them or the system cleans /tmp/')


