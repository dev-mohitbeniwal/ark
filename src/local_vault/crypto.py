# ark/src/local_vault/crypto.py

import os
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# Constants
SALT_SIZE = 32
IV_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600000  # Adjusted for better security

def generate_salt():
    """Generate a random salt."""
    return os.urandom(SALT_SIZE)

def generate_iv():
    """Generate a random initialization vector."""
    return os.urandom(IV_SIZE)

def generate_encryption_key():
    """Generate a strong encryption key."""
    return os.urandom(KEY_SIZE)

def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Derive a key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def hash_password(password: str) -> bytes:
    """Hash the password with a salt using Argon2."""
    salt = generate_salt()
    # Note: In a production environment, consider using the argon2-cffi library
    # for Argon2 hashing. For this example, we'll use PBKDF2 as a substitute.
    key = derive_key(password, salt)
    return salt + key

def verify_password(stored_password: bytes, provided_password: str) -> bool:
    """Verify the provided password against the stored hash."""
    salt = stored_password[:SALT_SIZE]
    stored_key = stored_password[SALT_SIZE:]
    derived_key = derive_key(provided_password, salt)
    return hmac.compare_digest(derived_key, stored_key)

def encrypt(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag

def decrypt(encrypted_data: bytes, key: bytes) -> bytes:
    if len(encrypted_data) < IV_SIZE + TAG_SIZE:
        raise ValueError("Decryption failed: Invalid data")

    iv = encrypted_data[:IV_SIZE]
    ciphertext = encrypted_data[IV_SIZE:-TAG_SIZE]
    tag = encrypted_data[-TAG_SIZE:]

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        print(f"Debug: InvalidTag error. Encrypted data length: {len(encrypted_data)}")
        raise ValueError("Decryption failed: Invalid tag")

def generate_key_encryption_key(master_password: str, salt: bytes) -> bytes:
    """Generate a key encryption key from the master password."""
    return derive_key(master_password, salt, iterations=PBKDF2_ITERATIONS)

def encrypt_key(key: bytes, key_encryption_key: bytes) -> bytes:
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key_encryption_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(key) + encryptor.finalize()
    return iv + ciphertext + encryptor.tag

def decrypt_key(encrypted_key: bytes, key_encryption_key: bytes) -> bytes:
    iv = encrypted_key[:12]
    ciphertext = encrypted_key[12:-16]
    tag = encrypted_key[-16:]
    cipher = Cipher(algorithms.AES(key_encryption_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def generate_hmac(data: bytes, key: bytes) -> bytes:
    """Generate an HMAC for data integrity verification."""
    return hmac.new(key, data, hashlib.sha256).digest()

def verify_hmac(data: bytes, key: bytes, expected_hmac: bytes) -> bool:
    """Verify the HMAC for data integrity."""
    calculated_hmac = generate_hmac(data, key)
    return hmac.compare_digest(calculated_hmac, expected_hmac)

class EncryptionError(Exception):
    """Custom exception for encryption-related errors."""
    pass

class DecryptionError(Exception):
    """Custom exception for decryption-related errors."""
    pass

def encrypt_file(file_path: str, key: bytes) -> None:
    """Encrypt a file in place."""
    try:
        with open(file_path, 'rb') as file:
            data = file.read()
        encrypted_data = encrypt(data, key)
        with open(file_path, 'wb') as file:
            file.write(encrypted_data)
    except Exception as e:
        raise EncryptionError(f"Failed to encrypt file: {str(e)}")

def decrypt_file(file_path: str, key: bytes) -> None:
    """Decrypt a file in place."""
    try:
        with open(file_path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = decrypt(encrypted_data, key)
        with open(file_path, 'wb') as file:
            file.write(decrypted_data)
    except Exception as e:
        raise DecryptionError(f"Failed to decrypt file: {str(e)}")

def rotate_encryption_key(old_key: bytes, new_key: bytes, data: bytes) -> bytes:
    """Re-encrypt data with a new key."""
    try:
        decrypted_data = decrypt(data, old_key)
        return encrypt(decrypted_data, new_key)
    except Exception as e:
        raise EncryptionError(f"Failed to rotate encryption key: {str(e)}")