#!/usr/bin/env python3

import datetime
import argparse
import os
import tempfile

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def main():
    parser = argparse.ArgumentParser(description='Sign a CSR with a CA certificate')
    parser.add_argument('--ca-cert', default=os.environ.get('CA_CERT', '/tmp/ca.cert'),
                        help='Path to CA certificate file (default: /tmp/ca.cert or $CA_CERT)')
    parser.add_argument('--ca-key', default=os.environ.get('CA_KEY', '/tmp/ca.key'),
                        help='Path to CA private key file (default: /tmp/ca.key or $CA_KEY)')
    parser.add_argument('--csr', default=os.environ.get('CSR_FILE', '/tmp/acme.csr'),
                        help='Path to CSR file (default: /tmp/acme.csr or $CSR_FILE)')
    parser.add_argument('--output', default=os.environ.get('OUTPUT_CERT', '/tmp/acme.cert'),
                        help='Path to output certificate file (default: /tmp/acme.cert or $OUTPUT_CERT)')
    args = parser.parse_args()

    with open(args.ca_cert, "rb") as ca_cert_file:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_file.read(), default_backend())

    with open(args.csr, "rb") as csr_file:
        csr = x509.load_pem_x509_csr(csr_file.read(), default_backend())

    with open(args.ca_key, "rb") as key_file:
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
    with open(args.output, 'wb') as out:
        out.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f'Created {args.output}')


if __name__ == '__main__':
    main()
