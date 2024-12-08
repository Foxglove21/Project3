import requests
import pytest
import jwt  # Add this import
import datetime  # Add this import
import main

BASE_URL = 'http://localhost:8080'

def test_auth_valid_credentials():
    response = requests.post(f'{BASE_URL}/auth', json={"username": "test", "password": "test"})
    assert response.status_code == 200
    assert 'ey' in response.text

def test_auth_invalid_credentials():
    response = requests.post(f'{BASE_URL}/auth', json={"username": "wrong", "password": "wrong"})
    assert response.status_code == 401
    assert response.json().get("message") == "Unauthorized"

def test_auth_expired_token():
    response = requests.post(f'{BASE_URL}/auth?expired=true', json={"username": "test", "password": "test"})
    assert response.status_code == 200
    jwt_token = response.text
    payload = jwt.decode(jwt_token, options={"verify_signature": False})
    assert payload['exp'] < datetime.datetime.utcnow().timestamp()

def test_jwks_endpoint():
    response = requests.get(f'{BASE_URL}/.well-known/jwks.json')
    assert response.status_code == 200
    keys = response.json().get('keys')
    assert isinstance(keys, list)
    assert len(keys) > 0

def test_invalid_endpoint():
    response = requests.put(f'{BASE_URL}/auth')
    assert response.status_code == 405

def test_head_request():
    response = requests.head(f'{BASE_URL}/auth')
    assert response.status_code == 405

def test_delete_request():
    response = requests.delete(f'{BASE_URL}/auth')
    assert response.status_code == 405

def test_patch_request():
    response = requests.patch(f'{BASE_URL}/auth')
    assert response.status_code == 405
