import unittest
import sqlite3
import time
import sys
from pathlib import Path
from http.server import HTTPServer
from unittest.mock import patch, MagicMock
import requests
import datetime
import base64
from threading import Thread
import jwt
from pathlib import Path
from threading import Thread


# Import the server module to test
from server import HOSTNAME, SERVERPORT, MyServer, create_open_db, store_person, int_to_base64, store_private_key, get_valid_keys
sys.path.append(str(Path(__file__).parent.resolve()))
BASE_URL = 'http://localhost:8080'


class TestJWTServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up the test server in a separate thread."""
        cls.db_path = "test_server.db"
        create_open_db(cls.db_path)
        cls.server = HTTPServer((HOSTNAME, SERVERPORT), MyServer)
        cls.server_thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(1)  # Allow server to start

    @classmethod
    def tearDownClass(cls):
        """Clean up the server and database after tests."""
        cls.server.shutdown()
        cls.server.server_close()
        Path(cls.db_path).unlink(missing_ok=True)

    def setUp(self):
        """Set up a fresh database connection for each test."""
        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()

    def tearDown(self):
        """Close the database connection after each test."""
        self.conn.close()

    def test_register_existing_user(self):
        """Test attempting to register an already existing user."""
        payload = {
            "username": "testuser",
            "password": "securepassword"
        }
        requests.post(f"http://{HOSTNAME}:{SERVERPORT}/register", json=payload)
        response = requests.post(f"http://{HOSTNAME}:{SERVERPORT}/register", json=payload)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json().get("message"), "User already exists.")

    def test_rate_limiting(self):
        """Test rate limiting by sending too many requests."""
        for _ in range(10):
            response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/.well-known/jwks.json")

        response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 429)

    def test_jwks_endpoint(self):
        """Test the JWKS endpoint for public key retrieval."""
        response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        self.assertIn("keys", jwks)
        self.assertGreater(len(jwks["keys"]), 0)

    def test_invalid_jwt(self):
        """Test invalid JWT token handling"""
        invalid_token = "invalid.token.here"
        headers = {"Authorization": f"Bearer {invalid_token}"}
        response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/protected-endpoint", headers=headers)
        self.assertEqual(response.status_code, 401)

    def test_expired_jwt(self):
        """Test expired JWT token handling"""
        payload = {
            "username": "testuser",
            "exp": datetime.datetime.utcnow() - datetime.timedelta(hours=1)  # Expired token
        }
        expired_token = jwt.encode(payload, expired_pem, algorithm="RS256", headers={"kid": "expiredKID"})
        headers = {"Authorization": f"Bearer {expired_token}"}
        response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/protected-endpoint", headers=headers)
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json().get("message"), "Token expired.")
    
    def test_rate_limiting_different_ips(self):
        """Test rate limiting for different IP addresses"""
        ip1 = "192.168.1.1"
        ip2 = "192.168.1.2"

        # First IP makes 10 requests (within limit)
        for _ in range(10):
            response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/.well-known/jwks.json", headers={"X-Forwarded-For": ip1})
        response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/.well-known/jwks.json", headers={"X-Forwarded-For": ip1})
        self.assertEqual(response.status_code, 429)  # Should be rate-limited

        # Second IP makes 10 requests (within limit)
        for _ in range(10):
            response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/.well-known/jwks.json", headers={"X-Forwarded-For": ip2})
        response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/.well-known/jwks.json", headers={"X-Forwarded-For": ip2})
        self.assertEqual(response.status_code, 429)  # Should be rate-limited

    def test_jwks_no_expired_keys(self):
        """Test that expired private keys are not returned in the JWKS response"""
        response = requests.get(f"http://{HOSTNAME}:{SERVERPORT}/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)
        jwks = response.json()
        expired_keys = [key for key in jwks["keys"] if key["kid"] == "expiredKID"]
        self.assertEqual(len(expired_keys), 0)  # No expired keys should be present
    
    @patch('sqlite3.connect')
    def test_store_person(self, mock_connect):
        # Set up the mock connection and cursor
        mock_cursor = mock_connect.return_value.cursor.return_value
        mock_connect.return_value.commit.return_value = None  # Mock commit

        store_person('test.db', 'user1', 'email@example.com', 'hashed_password')

        # Check that the execute method was called with the correct query
        mock_cursor.execute.assert_called_with(
            """INSERT INTO users(username, email, password_hash) VALUES (?, ?, ?);""",
            ('user1', 'email@example.com', 'hashed_password')
        )
        # Check that commit was called
        mock_connect.return_value.commit.assert_called_once()

    def test_auth_valid_credentials(self):
        response = requests.post(f'{BASE_URL}/auth', json={"username": "test", "password": "test"})
        assert response.status_code == 200
        assert 'ey' in response.text

    def test_auth_expired_token(self):
        response = requests.post(f'{BASE_URL}/auth?expired=true', json={"username": "test", "password": "test"})
        assert response.status_code == 200
        jwt_token = response.text
        payload = jwt.decode(jwt_token, options={"verify_signature": False})
        assert payload['exp'] < datetime.datetime.utcnow().timestamp()

    def test_invalid_endpoint(self):
        response = requests.put(f'{BASE_URL}/auth')
        assert response.status_code == 405

    def test_head_request(self):
        response = requests.head(f'{BASE_URL}/auth')
        assert response.status_code == 405

    def test_delete_request(self):
        response = requests.delete(f'{BASE_URL}/auth')
        assert response.status_code == 405

    def test_patch_request(self):
        response = requests.patch(f'{BASE_URL}/auth')
        assert response.status_code == 405

    def test_int_to_base64_basic(self):
        """Test basic integer to base64 encoding"""
        value = 12345
        expected_result = base64.urlsafe_b64encode(bytes.fromhex('3039')).rstrip(b'=').decode('utf-8')
        result = int_to_base64(value)
        self.assertEqual(result, expected_result)

    def test_int_to_base64_single_byte(self):
        """Test integer that fits in a single byte"""
        value = 255
        expected_result = base64.urlsafe_b64encode(bytes.fromhex('ff')).rstrip(b'=').decode('utf-8')
        result = int_to_base64(value)
        self.assertEqual(result, expected_result)

    def test_int_to_base64_large_value(self):
        """Test a large integer value"""
        value = 987654321
        expected_result = base64.urlsafe_b64encode(bytes.fromhex('3ade68b1')).rstrip(b'=').decode('utf-8')
        result = int_to_base64(value)
        self.assertEqual(result, expected_result)
    
    def test_get_valid_keys_no_keys(self):
        """Test that no keys are returned when the table is empty."""
        valid_keys = get_valid_keys(self.db_path)
        self.assertEqual(valid_keys, [])

    def test_get_valid_keys_single_valid_key(self):
        """Test that a single valid key is returned correctly."""
        valid_key = "valid_key_1"
        expiration_time = int(datetime.datetime.utcnow().timestamp()) + 3600  # Expires in 1 hour
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?);", (valid_key, expiration_time))
        self.conn.commit()

        valid_keys = get_valid_keys(self.db_path)
        self.assertEqual(valid_keys, [valid_key])

    def test_get_valid_keys_single_expired_key(self):
        """Test that an expired key is not returned."""
        expired_key = "expired_key_1"
        expiration_time = int(datetime.datetime.utcnow().timestamp()) - 3600  # Expired 1 hour ago
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?);", (expired_key, expiration_time))
        self.conn.commit()

        valid_keys = get_valid_keys(self.db_path)
        self.assertEqual(valid_keys, [])

    def test_get_valid_keys_multiple_keys(self):
        """Test that only valid keys are returned when there are multiple keys."""
        valid_key_1 = "valid_key_1"
        valid_exp_time = int(datetime.datetime.utcnow().timestamp()) + 3600  # Expires in 1 hour
        expired_key_1 = "expired_key_1"
        expired_exp_time = int(datetime.datetime.utcnow().timestamp()) - 3600  # Expired 1 hour ago

        # Insert both valid and expired keys
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?);", (valid_key_1, valid_exp_time))
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?);", (expired_key_1, expired_exp_time))
        self.conn.commit()

        valid_keys = get_valid_keys(self.db_path)
        self.assertEqual(valid_keys, [valid_key_1])

    def test_get_valid_keys_no_expired_keys(self):
        """Test that no expired keys are returned when all keys are valid."""
        valid_key_1 = "valid_key_1"
        valid_key_2 = "valid_key_2"
        valid_exp_time = int(datetime.datetime.utcnow().timestamp()) + 3600  # Expires in 1 hour

        # Insert valid keys only
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?);", (valid_key_1, valid_exp_time))
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?);", (valid_key_2, valid_exp_time))
        self.conn.commit()

        valid_keys = get_valid_keys(self.db_path)
        self.assertEqual(valid_keys, [valid_key_1, valid_key_2])

    def test_get_valid_keys_all_expired_keys(self):
        """Test that no keys are returned when all keys are expired."""
        expired_key_1 = "expired_key_1"
        expired_key_2 = "expired_key_2"
        expired_exp_time = int(datetime.datetime.utcnow().timestamp()) - 3600  # Expired 1 hour ago

        # Insert expired keys only
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?);", (expired_key_1, expired_exp_time))
        self.cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?);", (expired_key_2, expired_exp_time))
        self.conn.commit()

        valid_keys = get_valid_keys(self.db_path)
        self.assertEqual(valid_keys, [])

if __name__ == "__main__":
    unittest.main()
#used chatgpt prompt to create this. inserted server code and told it to create a test suite. then added more tests based on the coverage report by doing more chatgpt prompts using missing functions
