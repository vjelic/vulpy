#!/usr/bin/env python3

import sys

from binascii import unhexlify

import click

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


@click.command()
@click.argument('key')
@click.argument('nonce')
@click.argument('message')
@click.argument('tag')
def aes_decrypt(key, nonce, message, tag):

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key.encode())
    key_digest = digest.finalize()

    try:
        cipher = Cipher(algorithms.AES(key_digest), modes.GCM(unhexlify(nonce), unhexlify(tag)), backend=default_backend())
        decryptor = cipher.decryptor()
        plain = decryptor.update(unhexlify(message)) + decryptor.finalize()
        print(plain.decode(errors='ignore'))
    except InvalidTag:
        print("Error: Authentication failed. The ciphertext or tag has been tampered with or is invalid.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    aes_decrypt()

