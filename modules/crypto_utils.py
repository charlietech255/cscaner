#!/usr/bin/env python3
"""
CSCAN — Lightweight Crypto Utilities
Uses Python stdlib only - Termux compatible, no external dependencies
"""

import hashlib
import hmac
import base64
import os
from datetime import datetime, timedelta


# ── Hash Functions (stdlib only) ───────────────────────────────────────────────
def hash_md5(data: str | bytes) -> str:
    """Generate MD5 hash (use only for non-security purposes like checksums)"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.md5(data).hexdigest()


def hash_sha1(data: str | bytes) -> str:
    """Generate SHA1 hash"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha1(data).hexdigest()


def hash_sha256(data: str | bytes) -> str:
    """Generate SHA256 hash (recommended for security)"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def hash_sha512(data: str | bytes) -> str:
    """Generate SHA512 hash (maximum security)"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha512(data).hexdigest()


# ── HMAC Signing (for authentication & integrity) ────────────────────────────
def hmac_sha256(message: str | bytes, key: str | bytes) -> str:
    """Generate HMAC-SHA256 signature"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def hmac_sha512(message: str | bytes, key: str | bytes) -> str:
    """Generate HMAC-SHA512 signature"""
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hmac.new(key, message, hashlib.sha512).hexdigest()


def verify_hmac(message: str | bytes, signature: str, key: str | bytes, algo: str = "sha256") -> bool:
    """Verify HMAC signature"""
    if algo == "sha256":
        computed = hmac_sha256(message, key)
    elif algo == "sha512":
        computed = hmac_sha512(message, key)
    else:
        return False
    
    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed, signature)


# ── Base64 Encoding/Decoding ───────────────────────────────────────────────────
def encode_base64(data: str | bytes) -> str:
    """Encode data to base64"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.b64encode(data).decode('ascii')


def decode_base64(data: str) -> str:
    """Decode base64 to string"""
    return base64.b64decode(data).decode('utf-8')


def encode_base64_url(data: str | bytes) -> str:
    """Encode data to URL-safe base64"""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('ascii')


def decode_base64_url(data: str) -> str:
    """Decode URL-safe base64"""
    return base64.urlsafe_b64decode(data).decode('utf-8')


# ── Random Token Generation ────────────────────────────────────────────────────
def generate_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return base64.urlsafe_b64encode(os.urandom(length)).decode('ascii')[:length]


def generate_nonce(length: int = 16) -> str:
    """Generate nonce (number used once) for authentication"""
    return base64.urlsafe_b64encode(os.urandom(length)).decode('ascii')[:length]


# ── Password Utilities ─────────────────────────────────────────────────────────
def hash_password(password: str, salt: bytes = None) -> tuple:
    """
    Hash password with salt using PBKDF2 (stdlib)
    Returns: (hashed_password, salt_hex)
    """
    if salt is None:
        salt = os.urandom(32)
    
    # PBKDF2 with 100,000 iterations
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    
    return (hashed.hex(), salt.hex())


def verify_password(password: str, stored_hash: str, salt_hex: str) -> bool:
    """Verify password against stored hash"""
    salt = bytes.fromhex(salt_hex)
    new_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(new_hash, stored_hash)


# ── Checksum Functions ─────────────────────────────────────────────────────────
def checksum_file(filepath: str, algo: str = "sha256", chunk_size: int = 65536) -> str:
    """Calculate file checksum"""
    if algo == "sha256":
        h = hashlib.sha256()
    elif algo == "sha512":
        h = hashlib.sha512()
    elif algo == "sha1":
        h = hashlib.sha1()
    else:
        h = hashlib.sha256()
    
    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    
    return h.hexdigest()


# ── Data Fingerprinting ────────────────────────────────────────────────────────
def fingerprint_data(data: str | bytes, algo: str = "sha256") -> str:
    """Create fingerprint of data (shorthand for hash)"""
    if algo == "sha256":
        return hash_sha256(data)[:16]  # First 16 chars
    elif algo == "sha512":
        return hash_sha512(data)[:16]
    else:
        return hash_sha256(data)[:16]


# ── JWT-like Token (simple implementation) ─────────────────────────────────────
def create_signed_token(payload: dict, secret: str) -> str:
    """
    Create a simple signed token (JWT-like but not full JWT)
    Format: base64(payload).timestamp.signature
    """
    import json
    
    # Create payload with timestamp
    token_payload = {
        **payload,
        "iat": datetime.now().isoformat(),
        "exp": (datetime.now() + timedelta(hours=24)).isoformat()
    }
    
    # Encode payload
    payload_json = json.dumps(token_payload, separators=(',', ':'))
    encoded_payload = encode_base64_url(payload_json)
    
    # Create signature
    signature = hmac_sha256(encoded_payload, secret)
    
    # Return combined token
    return f"{encoded_payload}.{signature[:32]}"


def verify_signed_token(token: str, secret: str) -> dict | None:
    """Verify and decode signed token"""
    import json
    from datetime import datetime, timezone
    
    try:
        parts = token.split('.')
        if len(parts) != 2:
            return None
        
        payload_b64, signature = parts
        
        # Verify signature
        expected_sig = hmac_sha256(payload_b64, secret)
        if not hmac.compare_digest(expected_sig[:32], signature):
            return None
        
        # Decode payload
        payload_json = decode_base64_url(payload_b64)
        payload = json.loads(payload_json)
        
        # Check expiration
        exp_time = datetime.fromisoformat(payload.get("exp", ""))
        if exp_time < datetime.now(timezone.utc).replace(tzinfo=None):
            return None
        
        return payload
    
    except Exception:
        return None


# ── Utility: Compare values securely ───────────────────────────────────────────
def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time (prevents timing attacks)"""
    return hmac.compare_digest(a, b)
