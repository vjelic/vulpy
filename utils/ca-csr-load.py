#!/usr/bin/env python3

"""
Certificate Signing Utility

This script loads CA certificate, CSR, and CA private key to sign and create
a certificate. 

SECURITY NOTE: This script uses predictable file paths in the system temp directory,
which still presents a potential security risk in multi-user environments. The symlink
validation helps mitigate some attacks, but for production use, consider:
1. Using tempfile.NamedTemporaryFile() with unique filenames
2. Implementing file locking mechanisms
3. Running in a dedicated, access-controlled directory
"""

import datetime
import sys
import os
import tempfile

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


# Use secure temporary directory instead of hardcoded /tmp
temp_dir = tempfile.gettempdir()

# Construct secure paths
ca_cert_path = os.path.join(temp_dir, "ca.cert")
acme_csr_path = os.path.join(temp_dir, "acme.csr")
ca_key_path = os.path.join(temp_dir, "ca.key")
acme_cert_path = os.path.join(temp_dir, "acme.cert")

# Validate that input files exist and are regular files (not symlinks)
for path in [ca_cert_path, acme_csr_path, ca_key_path]:
    if not os.path.exists(path):
        print(f"Error: Required file not found: {path}", file=sys.stderr)
        sys.exit(1)
    # Check for symlinks first to prevent symlink attacks
    if os.path.islink(path):
        print(f"Error: Path is a symbolic link (potential security risk): {path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(path):
        print(f"Error: Path is not a regular file: {path}", file=sys.stderr)
        sys.exit(1)

with open(ca_cert_path, "rb") as ca_cert_file:
    ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read(), default_backend())

with open(acme_csr_path, "rb") as csr_file:
    csr = x509.load_pem_x509_csr(csr_file.read(), default_backend())

with open(ca_key_path, "rb") as key_file:
    private_key = serialization.load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

cert = x509.CertificateBuilder().subject_name(csr.subject)
cert = cert.issuer_name(ca_cert.subject)
cert = cert.public_key(csr.public_key())
cert = cert.serial_number(x509.random_serial_number())
cert = cert.not_valid_before(datetime.datetime.utcnow())
cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
cert = cert.sign(private_key, hashes.SHA256(), default_backend())

# Write our certificate out to disk.
with open(acme_cert_path, 'wb') as out:
    out.write(cert.public_bytes(serialization.Encoding.PEM))

print(f'Created {acme_cert_path}')
