#!/usr/bin/env python3

import datetime
import sys
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

# Accept key file path as command-line argument to avoid hardcoded insecure paths
if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <key-file> [output-csr-file]", file=sys.stderr)
    print("Error: Key file path is required", file=sys.stderr)
    sys.exit(1)

key_file_path = sys.argv[1]
csr_file_path = sys.argv[2] if len(sys.argv) > 2 else None

# If no output path specified, use same directory as key file
if csr_file_path is None:
    output_dir = os.path.dirname(key_file_path) or "."
    csr_file_path = os.path.join(output_dir, "acme.csr")

try:
    with open(key_file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
except FileNotFoundError:
    print(f"Error: Key file not found: {key_file_path}", file=sys.stderr)
    sys.exit(1)
except PermissionError:
    print(f"Error: Permission denied reading key file: {key_file_path}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"Error: Failed to load key file: {e}", file=sys.stderr)
    sys.exit(1)

# Generate a CSR
csr = x509.CertificateSigningRequestBuilder()
csr = csr.subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "BA"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Buenos Aires"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ACME CORP"),
    x509.NameAttribute(NameOID.COMMON_NAME, "acme.com"),
    ])
)

# Sign the CSR with our private key.
csr = csr.sign(private_key, hashes.SHA256(), default_backend())

# Write our CSR out to disk.
with open(csr_file_path, "wb") as out:
    out.write(csr.public_bytes(serialization.Encoding.PEM))

print(f'Created {csr_file_path}')

