#!/usr/bin/env python3
"""
CA Certificate Creation Script

This script creates a self-signed CA certificate, private key, and public key
using secure temporary files to prevent symlink attacks and race conditions.

The actual file paths are printed to stdout. If you need to use these files
with other scripts (e.g., ca-csr-load.py), you will need to update those
scripts with the generated file paths.
"""

import datetime
import sys
import tempfile

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

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

try:
    # Create secure temporary file for private key
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, prefix='ca-', suffix='.key') as out:
        out.write(pem_private)
        key_path = out.name

    # Create secure temporary file for public key
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, prefix='ca-', suffix='.pub') as out:
        out.write(pem_public)
        pub_path = out.name
except Exception as e:
    print(f"Error creating key files: {e}", file=sys.stderr)
    sys.exit(1)

# Various details about who we are. For a self-signed certificate the
# subject and issuer are always the same.
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "AR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "BA"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Buenos Aires"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vulpy by Securetia"),
    x509.NameAttribute(NameOID.COMMON_NAME, "www.securetia.com"),
])

cert = x509.CertificateBuilder().subject_name(subject)
cert = cert.issuer_name(issuer)
cert = cert.public_key(public_key)
cert = cert.serial_number(x509.random_serial_number())
cert = cert.not_valid_before(datetime.datetime.utcnow())
cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
cert = cert.sign(private_key, hashes.SHA256(), default_backend())

# Write our certificate out to disk using secure temporary file
try:
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, prefix='ca-', suffix='.cert') as out:
        out.write(cert.public_bytes(serialization.Encoding.PEM))
        cert_path = out.name
    
    print(f'Created files: {key_path} {pub_path} {cert_path}')
except Exception as e:
    print(f"Error creating certificate file: {e}", file=sys.stderr)
    sys.exit(1)

