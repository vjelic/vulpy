# RSA Utilities Security Fix

## Security Vulnerability Fixed

**CWE-377: Insecure Temporary File**

The RSA utility scripts previously used hardcoded temporary file paths (`/tmp/acme.pub` and `/tmp/acme.key`), which could be exploited through symlink attacks where an attacker could:
1. Predict the temporary file path
2. Create a symbolic link at that location pointing to a sensitive file
3. Cause the script to read/write the attacker's chosen file instead

## Changes Made

All RSA utility scripts now support configurable key file paths:

### Scripts Modified:
1. **rsa-keygen.py** - Generate RSA key pairs
2. **rsa-encrypt.py** - Encrypt messages using public key
3. **rsa-decrypt.py** - Decrypt messages using private key
4. **rsa-sign.py** - Sign messages using private key
5. **rsa-verify.py** - Verify signatures using public key

## Usage

### Option 1: Command-Line Arguments (Recommended for explicit control)

```bash
# Generate keys in a secure location
./utils/rsa-keygen.py ~/secure/my.key ~/secure/my.pub

# Encrypt with specific public key
./utils/rsa-encrypt.py "secret message" ~/secure/my.pub

# Decrypt with specific private key
./utils/rsa-decrypt.py <ciphertext> ~/secure/my.key

# Sign with specific private key
./utils/rsa-sign.py "message to sign" ~/secure/my.key

# Verify with specific public key
./utils/rsa-verify.py "message" <signature> ~/secure/my.pub
```

### Option 2: Environment Variables (Recommended for convenience)

```bash
# Set environment variables
export RSA_PUBLIC_KEY_PATH=~/secure/my.pub
export RSA_PRIVATE_KEY_PATH=~/secure/my.key

# Use utilities without specifying paths
./utils/rsa-encrypt.py "secret message"
./utils/rsa-decrypt.py <ciphertext>
./utils/rsa-sign.py "message to sign"
./utils/rsa-verify.py "message" <signature>
```

### Option 3: Default Behavior (Backward Compatible, Not Secure)

```bash
# Still works but not recommended for production
./utils/rsa-keygen.py
./utils/rsa-encrypt.py "secret message"
./utils/rsa-decrypt.py <ciphertext>
```

**Note:** Default behavior uses `/tmp/acme.*` paths and is maintained only for backward compatibility. It should not be used in production environments.

## Argument Precedence

The order of precedence for determining key file paths is:
1. **Command-line argument** (highest priority)
2. **Environment variable**
3. **Default path** (lowest priority, `/tmp/acme.*`)

This allows command-line arguments to override environment variables for maximum flexibility.

## Security Best Practices

1. **Always specify custom paths** for production use
2. **Use secure directories** with appropriate permissions (e.g., `~/.ssh/`, `~/secure/`)
3. **Never use `/tmp/` for sensitive key storage** in production
4. **Set proper file permissions** on key files (e.g., `chmod 600` for private keys)

## Testing

The fix has been tested with:
- ✅ Custom paths via command-line arguments
- ✅ Environment variable configuration
- ✅ Backward compatibility with default paths
- ✅ Argument precedence (CLI > ENV > Default)
- ✅ Full encrypt/decrypt workflow
- ✅ Full sign/verify workflow
- ✅ CodeQL security scan (0 vulnerabilities found)

## References

- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)
- [OWASP - Insecure Temporary File](https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File)
