#!/usr/bin/env python3

import sys

from binascii import unhexlify

import click

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


@click.command()
@click.argument('key')
@click.argument('iv')
@click.argument('message')
@click.argument('tag')
def aes_decrypt(key, iv, message, tag):

    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(key.encode())
    key_digest = digest.finalize()

    try:
        cipher = Cipher(algorithms.AES(key_digest), modes.GCM(unhexlify(iv), unhexlify(tag)), backend=default_backend())
        decryptor = cipher.decryptor()
        plain = decryptor.update(unhexlify(message)) + decryptor.finalize()

        print(plain.decode(errors='ignore'))
    except Exception as e:
        # Handle authentication failures with a clear error message
        if "InvalidTag" in str(type(e).__name__):
            print(f"Error: Authentication failed. The message has been tampered with or the key/tag is incorrect.", file=sys.stderr)
            sys.exit(1)
        else:
            raise


if __name__ == '__main__':
    aes_decrypt()

