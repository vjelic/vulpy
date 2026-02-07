#!/usr/bin/env python3

import datetime
import tempfile
import os

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

# Create a secure temporary directory
temp_dir = tempfile.mkdtemp(prefix='ca_')

ca_key_path = os.path.join(temp_dir, 'ca.key')
ca_pub_path = os.path.join(temp_dir, 'ca.pub')
ca_cert_path = os.path.join(temp_dir, 'ca.cert')

with open(ca_key_path, 'wb') as out:
    out.write(pem_private)

with open(ca_pub_path, 'wb') as out:
    out.write(pem_public)

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

# Write our certificate out to disk.
with open(ca_cert_path, 'wb') as out:
    out.write(cert.public_bytes(serialization.Encoding.PEM))

print(f'Successfully created CA files in directory: {temp_dir}')
print(f'  - Private key: {ca_key_path}')
print(f'  - Public key: {ca_pub_path}')
print(f'  - Certificate: {ca_cert_path}')
print(f'\nNote: Files are in a secure temporary directory. Copy them if needed before system cleanup.')

