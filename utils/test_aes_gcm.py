#!/usr/bin/env python3
"""
Test suite for AES-GCM encryption and decryption utilities.
Tests authentication, encryption/decryption, and tampering detection.
"""

import os
import sys
import subprocess
from binascii import hexlify, unhexlify

# Test cases for AES-GCM
def run_encrypt(key, message):
    """Run aes-encrypt.py and return IV, ciphertext, and tag"""
    result = subprocess.run(
        ['python3', 'utils/aes-encrypt.py', key, message],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        raise Exception(f"Encryption failed: {result.stderr}")
    
    parts = result.stdout.strip().split()
    # Handle case where ciphertext might be empty (results in 2 parts instead of 3)
    if len(parts) == 2:
        # Empty ciphertext case: IV, tag
        return parts[0], "", parts[1]
    elif len(parts) == 3:
        return parts[0], parts[1], parts[2]
    else:
        raise Exception(f"Expected 2 or 3 parts, got {len(parts)}: {parts}")

def run_decrypt(key, iv, ciphertext, tag):
    """Run aes-decrypt.py and return plaintext"""
    result = subprocess.run(
        ['python3', 'utils/aes-decrypt.py', key, iv, ciphertext, tag],
        capture_output=True,
        text=True
    )
    return result.returncode, result.stdout.strip(), result.stderr

def test_basic_encryption_decryption():
    """Test basic encryption and decryption"""
    print("Test 1: Basic encryption/decryption...", end=" ")
    key = "test_key"
    message = "Hello, World!"
    
    iv, ciphertext, tag = run_encrypt(key, message)
    returncode, plaintext, stderr = run_decrypt(key, iv, ciphertext, tag)
    
    if returncode != 0:
        print(f"FAILED: {stderr}")
        return False
    
    if plaintext == message:
        print("PASSED")
        return True
    else:
        print(f"FAILED: Expected '{message}', got '{plaintext}'")
        return False

def test_authentication_with_tampered_ciphertext():
    """Test that tampered ciphertext is detected"""
    print("Test 2: Tampered ciphertext detection...", end=" ")
    key = "test_key"
    message = "Secret message"
    
    iv, ciphertext, tag = run_encrypt(key, message)
    
    # Tamper with ciphertext (flip a bit)
    tampered = list(ciphertext)
    tampered[0] = '0' if tampered[0] != '0' else '1'
    tampered_ciphertext = ''.join(tampered)
    
    returncode, plaintext, stderr = run_decrypt(key, iv, tampered_ciphertext, tag)
    
    if returncode != 0 and "InvalidTag" in stderr:
        print("PASSED")
        return True
    else:
        print(f"FAILED: Expected InvalidTag error, got returncode={returncode}")
        return False

def test_authentication_with_wrong_tag():
    """Test that wrong authentication tag is detected"""
    print("Test 3: Wrong authentication tag detection...", end=" ")
    key = "test_key"
    message = "Another secret"
    
    iv, ciphertext, tag = run_encrypt(key, message)
    
    # Use a wrong tag (all zeros)
    wrong_tag = "00000000000000000000000000000000"
    
    returncode, plaintext, stderr = run_decrypt(key, iv, ciphertext, wrong_tag)
    
    if returncode != 0 and "InvalidTag" in stderr:
        print("PASSED")
        return True
    else:
        print(f"FAILED: Expected InvalidTag error, got returncode={returncode}")
        return False

def test_different_keys():
    """Test that decryption with wrong key fails"""
    print("Test 4: Wrong key detection...", end=" ")
    key1 = "correct_key"
    key2 = "wrong_key"
    message = "Confidential data"
    
    iv, ciphertext, tag = run_encrypt(key1, message)
    returncode, plaintext, stderr = run_decrypt(key2, iv, ciphertext, tag)
    
    if returncode != 0 and "InvalidTag" in stderr:
        print("PASSED")
        return True
    else:
        print(f"FAILED: Expected InvalidTag error with wrong key, got returncode={returncode}")
        return False

def test_empty_message():
    """Test encryption/decryption of empty message"""
    print("Test 5: Empty message...", end=" ")
    key = "test_key"
    message = ""
    
    iv, ciphertext, tag = run_encrypt(key, message)
    returncode, plaintext, stderr = run_decrypt(key, iv, ciphertext, tag)
    
    if returncode != 0:
        print(f"FAILED: {stderr}")
        return False
    
    if plaintext == message:
        print("PASSED")
        return True
    else:
        print(f"FAILED: Expected empty string, got '{plaintext}'")
        return False

def test_long_message():
    """Test encryption/decryption of long message"""
    print("Test 6: Long message...", end=" ")
    key = "test_key"
    message = "A" * 1000  # 1000 character message
    
    iv, ciphertext, tag = run_encrypt(key, message)
    returncode, plaintext, stderr = run_decrypt(key, iv, ciphertext, tag)
    
    if returncode != 0:
        print(f"FAILED: {stderr}")
        return False
    
    if plaintext == message:
        print("PASSED")
        return True
    else:
        print(f"FAILED: Message length mismatch")
        return False

def main():
    print("=" * 60)
    print("AES-GCM Encryption/Decryption Test Suite")
    print("=" * 60)
    print()
    
    tests = [
        test_basic_encryption_decryption,
        test_authentication_with_tampered_ciphertext,
        test_authentication_with_wrong_tag,
        test_different_keys,
        test_empty_message,
        test_long_message,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"FAILED: {e}")
            failed += 1
    
    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return 0 if failed == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
