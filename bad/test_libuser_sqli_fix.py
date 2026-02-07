#!/usr/bin/env python3
"""
Test suite to verify SQL injection fix in libuser.py
This test verifies that parameterized queries prevent SQL injection attacks.
"""

import os
import sys
import sqlite3
import tempfile
import unittest

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import libuser


class TestSQLInjectionFix(unittest.TestCase):
    """Test that SQL injection is prevented in libuser functions"""

    def setUp(self):
        """Set up a test database before each test"""
        # Create a temporary database for testing
        self.db_file = 'test_db_users.sqlite'
        
        # Remove if exists
        try:
            os.remove(self.db_file)
        except FileNotFoundError:
            pass
        
        # Create test database
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()
        c.execute("CREATE TABLE users (username text, password text, failures int, mfa_enabled int, mfa_secret text)")
        c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES (?, ?, ?, ?, ?)", 
                  ('testuser', 'testpass', 0, 0, ''))
        c.execute("INSERT INTO users (username, password, failures, mfa_enabled, mfa_secret) VALUES (?, ?, ?, ?, ?)", 
                  ('admin', 'adminpass', 0, 0, ''))
        conn.commit()
        conn.close()
        
        # Temporarily rename the database files
        self.original_db = 'db_users.sqlite'
        self.original_exists = os.path.exists(self.original_db)
        if self.original_exists:
            os.rename(self.original_db, self.original_db + '.backup')
        os.rename(self.db_file, self.original_db)

    def tearDown(self):
        """Clean up after each test"""
        # Restore original database
        if os.path.exists(self.original_db):
            os.remove(self.original_db)
        if self.original_exists:
            os.rename(self.original_db + '.backup', self.original_db)

    def test_normal_login(self):
        """Test that normal login works correctly"""
        result = libuser.login('testuser', 'testpass')
        self.assertEqual(result, 'testuser')
        
        result = libuser.login('admin', 'adminpass')
        self.assertEqual(result, 'admin')

    def test_failed_login(self):
        """Test that failed login returns False"""
        result = libuser.login('testuser', 'wrongpass')
        self.assertFalse(result)
        
        result = libuser.login('nonexistent', 'somepass')
        self.assertFalse(result)

    def test_sql_injection_login_bypass_attempt(self):
        """Test that SQL injection attempts in login are prevented"""
        # Classic SQL injection attempt to bypass authentication
        # With vulnerable code: username = "' OR '1'='1" would return all users
        result = libuser.login("' OR '1'='1", "anything")
        self.assertFalse(result)
        
        # Another injection attempt
        result = libuser.login("admin' --", "")
        self.assertFalse(result)
        
        # Injection in password field
        result = libuser.login("testuser", "' OR '1'='1")
        self.assertFalse(result)

    def test_sql_injection_with_special_characters(self):
        """Test that special SQL characters are properly escaped"""
        # Test with single quotes
        result = libuser.login("test'user", "pass'word")
        self.assertFalse(result)  # Should not crash, just return False
        
        # Test with double quotes
        result = libuser.login('test"user', 'pass"word')
        self.assertFalse(result)
        
        # Test with semicolons (potential query separator)
        result = libuser.login("test;DROP TABLE users;--", "password")
        self.assertFalse(result)

    def test_create_user_normal(self):
        """Test that user creation works normally"""
        libuser.create('newuser', 'newpass')
        
        # Verify user was created
        result = libuser.login('newuser', 'newpass')
        self.assertEqual(result, 'newuser')

    def test_create_user_sql_injection_attempt(self):
        """Test that SQL injection in create is prevented"""
        # Attempt injection in username
        libuser.create("'; DROP TABLE users; --", "password")
        
        # Verify database is still intact
        result = libuser.login('testuser', 'testpass')
        self.assertEqual(result, 'testuser')

    def test_password_change_normal(self):
        """Test that password change works normally"""
        result = libuser.password_change('testuser', 'newpassword')
        self.assertTrue(result)
        
        # Verify new password works
        result = libuser.login('testuser', 'newpassword')
        self.assertEqual(result, 'testuser')

    def test_password_change_sql_injection_attempt(self):
        """Test that SQL injection in password_change is prevented"""
        # Attempt injection in password field
        libuser.password_change('testuser', "'; DROP TABLE users; --")
        
        # Verify database is still intact
        result = libuser.login('admin', 'adminpass')
        self.assertEqual(result, 'admin')

    def test_userlist(self):
        """Test that userlist works correctly"""
        users = libuser.userlist()
        self.assertIn('testuser', users)
        self.assertIn('admin', users)
        self.assertEqual(len(users), 2)


if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2)
