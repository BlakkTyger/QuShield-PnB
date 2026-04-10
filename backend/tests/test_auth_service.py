import pytest
from app.services.auth_service import get_password_hash, verify_password, create_access_token, decode_token

def test_password_hashing():
    password = "supersecretpassword123!"
    hashed = get_password_hash(password)
    
    assert hashed != password
    assert verify_password(password, hashed) is True
    assert verify_password("wrongpassword", hashed) is False

def test_jwt_lifecycle():
    data = {"sub": "1234-abcd", "email": "test@qushield.local"}
    token = create_access_token(data)
    
    assert token is not None
    decoded = decode_token(token)
    assert decoded["sub"] == "1234-abcd"
    assert decoded["email"] == "test@qushield.local"
    assert "exp" in decoded
