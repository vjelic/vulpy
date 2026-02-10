#!/usr/bin/env python3

import sys

from binascii import hexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils

if len(sys.argv) < 2:
    print("Usage: rsa-sign.py <message> [key_file]")
    print("  message: The message to sign")
    print("  key_file: Path to private key file (default: /tmp/acme.key)")
    sys.exit(1)

msg = sys.argv[1].encode()
key_file_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/acme.key"

try:
    with open(key_file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
except FileNotFoundError:
    print(f"Error: Key file not found at '{key_file_path}'")
    print("Generate a key first with rsa-keygen.py or specify a valid key file path.")
    sys.exit(1)
except PermissionError:
    print(f"Error: Permission denied accessing key file '{key_file_path}'")
    sys.exit(1)
except ValueError as e:
    print(f"Error: Invalid key format in '{key_file_path}': {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error reading key file '{key_file_path}': {e}")
    sys.exit(1)

chosen_hash = hashes.SHA256()
hasher = hashes.Hash(chosen_hash, default_backend())
hasher.update(msg)
digest = hasher.finalize()

sig = private_key.sign(
    digest,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    utils.Prehashed(chosen_hash)
)

print(msg.decode(), hexlify(sig).decode())

