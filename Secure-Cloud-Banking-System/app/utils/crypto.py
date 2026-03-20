import os
import base64
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

def _get_key():
    key_b64 = current_app.config.get('ENCRYPTION_KEY')
    if not key_b64:
        raise ValueError("ENCRYPTION_KEY must be set for cryptography operations.")
    # Pad to correct base64 length if necessary
    return base64.urlsafe_b64decode(key_b64 + '=' * (-len(key_b64) % 4))

def encrypt_aes256(plaintext: str) -> str:
    """Encrypt a string using AES-256 GCM."""
    if not plaintext:
        return plaintext
    key = _get_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, str(plaintext).encode('utf-8'), None)
    # prepend nonce to ciphertext and b64 encode
    return base64.urlsafe_b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_aes256(ciphertext_b64: str) -> str:
    """Decrypt a base64 encoded string using AES-256 GCM."""
    if not ciphertext_b64:
        return ciphertext_b64
    try:
        key = _get_key()
        aesgcm = AESGCM(key)
        data = base64.urlsafe_b64decode(ciphertext_b64 + '=' * (-len(ciphertext_b64) % 4))
        nonce = data[:12]
        ciphertext = data[12:]
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception:
        # Return original if decryption fails (e.g. legacy plaintext data)
        return ciphertext_b64

def hash_sha256(data: str) -> str:
    """Return SHA-256 hex digest of the input string."""
    return hashlib.sha256(str(data).encode('utf-8')).hexdigest()
