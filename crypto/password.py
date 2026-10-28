"""
Password Security Module for CryptoVote
Implements PBKDF2-HMAC-SHA256 with 100,000 iterations and 16-byte random salts.
Meets NIST and OWASP cryptographic password storage guidelines.
"""

import hashlib
import secrets

ITERATIONS = 100_000

def hash_password(password: str, salt_hex: str = None) -> tuple[str, str]:
    """
    Hashes a password with PBKDF2-HMAC-SHA256.
    Returns (password_hash_hex, salt_hex).
    """
    if salt_hex is None:
        salt_bytes = secrets.token_bytes(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)

    derived_key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt_bytes,
        iterations=ITERATIONS,
        dklen=32  # 256 bits output
    )

    return derived_key.hex(), salt_hex

def verify_password(stored_hash_hex: str, stored_salt_hex: str, provided_password: str) -> bool:
    """
    Verifies a password against the stored PBKDF2 hash using constant-time comparison
    to prevent timing attacks.
    """
    computed_hash_hex, _ = hash_password(provided_password, stored_salt_hex)
    return secrets.compare_digest(stored_hash_hex, computed_hash_hex)
