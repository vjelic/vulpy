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


# Accept file paths as command-line arguments for security
# Usage: ca-csr-load.py [ca_cert_path] [csr_path] [ca_key_path] [output_cert_path]
# 
# All arguments are optional and positional. Either provide all 4 arguments or none.
# When no arguments are provided, defaults to /tmp paths for backward compatibility.
# 
# Security: Using custom paths in a secure directory with proper permissions is
# recommended over the default /tmp paths to prevent symlink attacks and race conditions.
#
# Example with custom paths:
#   ./ca-csr-load.py ~/certs/ca.cert ~/certs/acme.csr ~/certs/ca.key ~/certs/acme.cert
#
if len(sys.argv) > 1 and len(sys.argv) != 5:
    print("Error: Either provide all 4 file path arguments or none.", file=sys.stderr)
    print("Usage: ca-csr-load.py [ca_cert_path] [csr_path] [ca_key_path] [output_cert_path]", file=sys.stderr)
    print("  ca_cert_path    - Path to CA certificate file", file=sys.stderr)
    print("  csr_path        - Path to Certificate Signing Request file", file=sys.stderr)
    print("  ca_key_path     - Path to CA private key file", file=sys.stderr)
    print("  output_cert_path - Path where the signed certificate will be written", file=sys.stderr)
    sys.exit(1)

use_custom_paths = len(sys.argv) == 5
ca_cert_path = sys.argv[1] if use_custom_paths else "/tmp/ca.cert"
csr_path = sys.argv[2] if use_custom_paths else "/tmp/acme.csr"
ca_key_path = sys.argv[3] if use_custom_paths else "/tmp/ca.key"
output_cert_path = sys.argv[4] if use_custom_paths else "/tmp/acme.cert"

# Validate that input files exist and are regular files (not symlinks)
for path in [ca_cert_path, csr_path, ca_key_path]:
    # Check for symlinks first to prevent symlink attacks
    if os.path.islink(path):
        print(f"Error: Symlinks are not allowed for security reasons: {path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.exists(path):
        print(f"Error: Input file does not exist: {path}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(path):
        print(f"Error: Path is not a regular file: {path}", file=sys.stderr)
        sys.exit(1)

with open(ca_cert_path, "rb") as ca_cert_file:
    ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read(), default_backend())

with open(csr_path, "rb") as csr_file:
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
with open(output_cert_path, 'wb') as out:
    out.write(cert.public_bytes(serialization.Encoding.PEM))

print(f'Created {output_cert_path}')
