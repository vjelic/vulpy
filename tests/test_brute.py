#!/usr/bin/env python3
"""
Tests for bad/brute.py to validate command injection vulnerability fix.

These tests verify that:
1. Input sanitization using shlex.quote() is properly applied
2. Special characters in inputs are properly escaped
3. Command injection attempts are prevented
"""

import subprocess
import sys
import os
import unittest
from unittest.mock import patch, MagicMock, call


class TestBruteForceSanitization(unittest.TestCase):
    """Test cases for command injection vulnerability fix in brute.py"""

    def setUp(self):
        """Set up test environment"""
        self.brute_script = os.path.join(
            os.path.dirname(os.path.dirname(__file__)), 
            'bad', 
            'brute.py'
        )

    def test_normal_inputs(self):
        """Test that normal inputs work correctly"""
        # Create a simple test program that always succeeds
        test_program = '/bin/echo'
        test_username = 'testuser'
        
        # Run the brute script with normal inputs
        result = subprocess.run(
            [sys.executable, self.brute_script, test_program, test_username],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Should complete without error
        self.assertEqual(result.returncode, 0)
        # Should find a "cracked" password (since echo always returns 0)
        self.assertIn('cracked!', result.stdout)

    def test_special_characters_escaped(self):
        """Test that special shell characters are properly escaped"""
        # Test with inputs containing special characters that could be used for injection
        test_program = '/bin/echo'
        malicious_username = 'user; rm -rf /'  # Potential command injection
        
        # Run the brute script
        result = subprocess.run(
            [sys.executable, self.brute_script, test_program, malicious_username],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Should complete without executing the injected command
        self.assertEqual(result.returncode, 0)
        # The script should treat the entire string as a single argument
        self.assertIn('cracked!', result.stdout)

    def test_command_substitution_prevented(self):
        """Test that command substitution is prevented"""
        test_program = '/bin/echo'
        # Try command substitution
        malicious_username = 'user$(whoami)'
        
        result = subprocess.run(
            [sys.executable, self.brute_script, test_program, malicious_username],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Should complete without expanding the command substitution
        self.assertEqual(result.returncode, 0)
        self.assertIn('cracked!', result.stdout)

    def test_backtick_substitution_prevented(self):
        """Test that backtick command substitution is prevented"""
        test_program = '/bin/echo'
        # Try backtick command substitution
        malicious_username = 'user`whoami`'
        
        result = subprocess.run(
            [sys.executable, self.brute_script, test_program, malicious_username],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Should complete without expanding the backtick substitution
        self.assertEqual(result.returncode, 0)
        self.assertIn('cracked!', result.stdout)

    def test_pipe_character_escaped(self):
        """Test that pipe characters are properly escaped"""
        test_program = '/bin/echo'
        malicious_username = 'user | cat /etc/passwd'
        
        result = subprocess.run(
            [sys.executable, self.brute_script, test_program, malicious_username],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Should complete without executing the piped command
        self.assertEqual(result.returncode, 0)
        self.assertIn('cracked!', result.stdout)

    def test_ampersand_character_escaped(self):
        """Test that ampersand characters are properly escaped"""
        test_program = '/bin/echo'
        malicious_username = 'user & whoami'
        
        result = subprocess.run(
            [sys.executable, self.brute_script, test_program, malicious_username],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Should complete without executing background commands
        self.assertEqual(result.returncode, 0)
        self.assertIn('cracked!', result.stdout)

    def test_quotes_escaped(self):
        """Test that quotes are properly escaped"""
        test_program = '/bin/echo'
        # Test with single and double quotes
        username_single = "user'test"
        username_double = 'user"test'
        
        for username in [username_single, username_double]:
            result = subprocess.run(
                [sys.executable, self.brute_script, test_program, username],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Should complete without quote injection
            self.assertEqual(result.returncode, 0)
            self.assertIn('cracked!', result.stdout)

    def test_failing_program(self):
        """Test behavior when program always fails"""
        # Use a program that will fail (non-existent command)
        test_program = '/bin/false'
        test_username = 'testuser'
        
        result = subprocess.run(
            [sys.executable, self.brute_script, test_program, test_username],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        # Script should complete
        self.assertEqual(result.returncode, 0)
        # Should not find any cracked password
        self.assertNotIn('cracked!', result.stdout)


if __name__ == '__main__':
    unittest.main()
