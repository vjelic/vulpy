#!/usr/bin/env python3
"""
Test for ca-csr-create.py to verify secure temporary file usage.
"""

import os
import sys
import tempfile
import subprocess
from pathlib import Path

# Add utils to path
utils_path = Path(__file__).parent.parent / 'utils'
sys.path.insert(0, str(utils_path))


def test_csr_uses_secure_temp_file():
    """Test that CSR creation uses secure temporary files, not predictable paths."""
    
    # First, create the required key file
    keygen_script = utils_path / 'rsa-keygen.py'
    result = subprocess.run([sys.executable, str(keygen_script)], 
                          capture_output=True, text=True)
    assert result.returncode == 0, f"Key generation failed: {result.stderr}"
    
    # Run the CSR creation script
    csr_script = utils_path / 'ca-csr-create.py'
    result = subprocess.run([sys.executable, str(csr_script)], 
                          capture_output=True, text=True)
    
    assert result.returncode == 0, f"CSR creation failed: {result.stderr}"
    
    # Extract the created file path from output
    output = result.stdout.strip()
    assert output.startswith('Created /tmp/acme-'), \
        f"Output should start with 'Created /tmp/acme-', got: {output}"
    
    # Extract the file path
    csr_path = output.replace('Created ', '')
    
    # Verify the file exists
    assert os.path.exists(csr_path), f"CSR file {csr_path} does not exist"
    
    # Verify it's in /tmp directory
    assert csr_path.startswith('/tmp/acme-'), \
        f"CSR should be in /tmp with acme- prefix, got: {csr_path}"
    
    # Verify it has .csr extension
    assert csr_path.endswith('.csr'), \
        f"CSR should have .csr extension, got: {csr_path}"
    
    # Verify the file name is not the predictable "/tmp/acme.csr"
    assert csr_path != '/tmp/acme.csr', \
        "CSR path should not be the predictable /tmp/acme.csr"
    
    # Verify the file has secure permissions (should be 0600 or similar)
    stat_info = os.stat(csr_path)
    mode = stat_info.st_mode & 0o777
    # tempfile creates files with 0600 permissions
    assert mode == 0o600, f"File should have 0600 permissions, got: {oct(mode)}"
    
    # Verify the content is valid PEM
    with open(csr_path, 'r') as f:
        content = f.read()
        assert content.startswith('-----BEGIN CERTIFICATE REQUEST-----'), \
            "CSR file should contain valid PEM certificate request"
    
    # Clean up
    try:
        os.unlink(csr_path)
        os.unlink('/tmp/acme.key')
        os.unlink('/tmp/acme.pub')
    except Exception:
        pass
    
    print("✓ Test passed: CSR creation uses secure temporary files")


if __name__ == '__main__':
    test_csr_uses_secure_temp_file()
