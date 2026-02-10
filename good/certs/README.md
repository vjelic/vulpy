# SSL Certificates Directory

This directory should contain SSL certificate files for the secure version of Vulpy.

Place your SSL certificate files here:
- `acme.cert` - SSL certificate file
- `acme.key` - SSL private key file

**Note**: Certificate files should have restricted permissions (e.g., 600 for key files) and should not be world-readable.

For testing purposes, you can generate self-signed certificates using:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -out acme.cert -keyout acme.key -days 365
```

**Security**: This directory is NOT world-writable like `/tmp/`, providing better security for SSL certificate storage.
