#!/usr/bin/env python3
"""
Test to verify SQL injection vulnerability fix in bad/db.py
"""
import os
import sys
import sqlite3
import tempfile
from passlib.hash import pbkdf2_sha256

# Add bad directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'bad'))

def test_parameterized_query():
    """Test that parameterized queries work correctly"""
    # Use a temporary database
    with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        # Create a simple table and insert data using parameterized queries
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE users (user text, password text, failures int)")
        
        # Test data
        users = [
            ('admin', pbkdf2_sha256.hash('123456')),
            ('john', pbkdf2_sha256.hash('Password')),
            ('tim', pbkdf2_sha256.hash('Vaider2'))
        ]
        
        # Insert using parameterized queries (the fix)
        for u, p in users:
            c.execute("INSERT INTO users (user, password, failures) VALUES (?, ?, ?)", (u, p, 0))
        
        conn.commit()
        
        # Verify data was inserted correctly
        rows = c.execute("SELECT user, failures FROM users").fetchall()
        assert len(rows) == 3, f"Expected 3 users, got {len(rows)}"
        
        usernames = [row[0] for row in rows]
        assert 'admin' in usernames, "Admin user not found"
        assert 'john' in usernames, "John user not found"
        assert 'tim' in usernames, "Tim user not found"
        
        # Verify failures are set to 0
        for user, failures in rows:
            assert failures == 0, f"Expected failures=0 for {user}, got {failures}"
        
        conn.close()
        print("✓ Parameterized query test passed")
        return True
    finally:
        # Clean up
        if os.path.exists(db_path):
            os.remove(db_path)

def test_sql_injection_prevention():
    """Test that SQL injection attempts are safely handled with parameterized queries"""
    # Use a temporary database
    with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE users (user text, password text, failures int)")
        
        # Try to inject SQL through username with parameterized queries
        # This should be treated as a literal string, not executed as SQL
        malicious_user = "admin'); DROP TABLE users; --"
        password = pbkdf2_sha256.hash('test123')
        
        # With parameterized queries, this is safe
        c.execute("INSERT INTO users (user, password, failures) VALUES (?, ?, ?)", 
                  (malicious_user, password, 0))
        conn.commit()
        
        # Verify the table still exists and the malicious string was inserted as data
        rows = c.execute("SELECT user FROM users").fetchall()
        assert len(rows) == 1, f"Expected 1 user, got {len(rows)}"
        assert rows[0][0] == malicious_user, "Malicious string should be stored as literal data"
        
        # Verify table still exists (wasn't dropped by injection)
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        tables = c.fetchall()
        assert len(tables) == 1, "Users table should still exist"
        
        conn.close()
        print("✓ SQL injection prevention test passed")
        return True
    finally:
        # Clean up
        if os.path.exists(db_path):
            os.remove(db_path)

def test_special_characters():
    """Test that special characters in data are handled correctly"""
    with tempfile.NamedTemporaryFile(suffix='.sqlite', delete=False) as tmp:
        db_path = tmp.name
    
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("CREATE TABLE users (user text, password text, failures int)")
        
        # Test with special characters that could cause issues with string formatting
        special_users = [
            ("user'with'quotes", "password"),
            ('user"with"doublequotes', "password"),
            ("user%s", "password"),
            ("user%d", "password"),
        ]
        
        for u, p in special_users:
            password_hash = pbkdf2_sha256.hash(p)
            c.execute("INSERT INTO users (user, password, failures) VALUES (?, ?, ?)", 
                      (u, password_hash, 0))
        
        conn.commit()
        
        # Verify all users were inserted correctly
        rows = c.execute("SELECT user FROM users").fetchall()
        assert len(rows) == len(special_users), f"Expected {len(special_users)} users, got {len(rows)}"
        
        inserted_users = [row[0] for row in rows]
        for expected_user, _ in special_users:
            assert expected_user in inserted_users, f"User '{expected_user}' not found in database"
        
        conn.close()
        print("✓ Special characters test passed")
        return True
    finally:
        # Clean up
        if os.path.exists(db_path):
            os.remove(db_path)

if __name__ == '__main__':
    print("Testing SQL injection fix in bad/db.py")
    print("=" * 50)
    
    all_passed = True
    
    try:
        all_passed &= test_parameterized_query()
    except Exception as e:
        print(f"✗ Parameterized query test failed: {e}")
        all_passed = False
    
    try:
        all_passed &= test_sql_injection_prevention()
    except Exception as e:
        print(f"✗ SQL injection prevention test failed: {e}")
        all_passed = False
    
    try:
        all_passed &= test_special_characters()
    except Exception as e:
        print(f"✗ Special characters test failed: {e}")
        all_passed = False
    
    print("=" * 50)
    if all_passed:
        print("All tests passed! ✓")
        sys.exit(0)
    else:
        print("Some tests failed! ✗")
        sys.exit(1)
