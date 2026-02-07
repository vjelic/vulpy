# SSL/TLS Certificates Directory

This directory is intended to store SSL/TLS certificates and private keys for the Vulpy SSL server.

## Security

This directory has restricted permissions (700) to prevent unauthorized access to sensitive certificate and key files.

## Usage

Place your SSL certificate and private key files here:
- `acme.cert` - SSL certificate file
- `acme.key` - Private key file

These files are referenced in `vulpy-ssl.py` for HTTPS configuration.

## Note

Certificate and key files are not included in version control for security reasons.
