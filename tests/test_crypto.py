# ark/tests/test_crypto.py

import os
import pytest
from cryptography.exceptions import InvalidTag
from local_vault.crypto import (
    generate_salt, generate_iv, generate_encryption_key, derive_key,
    hash_password, verify_password, encrypt, decrypt,
    generate_key_encryption_key, encrypt_key, decrypt_key,
    generate_hmac, verify_hmac, EncryptionError, DecryptionError,
    encrypt_file, decrypt_file, rotate_encryption_key
)

def test_generate_salt():
    salt = generate_salt()
    assert isinstance(salt, bytes)
    assert len(salt) == 32

def test_generate_iv():
    iv = generate_iv()
    assert isinstance(iv, bytes)
    assert len(iv) == 12

def test_generate_encryption_key():
    key = generate_encryption_key()
    assert isinstance(key, bytes)
    assert len(key) == 32

def test_derive_key():
    password = "password123"
    salt = generate_salt()
    key = derive_key(password, salt)
    assert isinstance(key, bytes)
    assert len(key) == 32

def test_hash_and_verify_password():
    password = "password123"
    hashed_password = hash_password(password)
    assert verify_password(hashed_password, password)
    assert not verify_password(hashed_password, "wrongpassword")

def test_encrypt_and_decrypt():
    data = b"Secret message"
    key = generate_encryption_key()
    encrypted_data = encrypt(data, key)
    decrypted_data = decrypt(encrypted_data, key)
    assert decrypted_data == data

def test_decrypt_invalid_data():
    data = b"Invalid data"
    key = generate_encryption_key()
    with pytest.raises(ValueError, match="Decryption failed: Invalid data"):
        decrypt(data, key)

def test_generate_key_encryption_key():
    master_password = "master_password"
    salt = generate_salt()
    key_encryption_key = generate_key_encryption_key(master_password, salt)
    assert isinstance(key_encryption_key, bytes)
    assert len(key_encryption_key) == 32

def test_encrypt_and_decrypt_key():
    key = generate_encryption_key()
    key_encryption_key = generate_encryption_key()
    encrypted_key = encrypt_key(key, key_encryption_key)
    decrypted_key = decrypt_key(encrypted_key, key_encryption_key)
    assert decrypted_key == key

def test_generate_and_verify_hmac():
    data = b"Original data"
    key = generate_encryption_key()
    hmac = generate_hmac(data, key)
    assert verify_hmac(data, key, hmac)
    assert not verify_hmac(b"Modified data", key, hmac)

def test_encrypt_and_decrypt_file(tmpdir):
    file_path = os.path.join(tmpdir, "test.txt")
    original_data = b"Original file content"
    with open(file_path, 'wb') as file:
        file.write(original_data)
    
    key = generate_encryption_key()
    encrypt_file(file_path, key)
    with open(file_path, 'rb') as file:
        encrypted_data = file.read()
    assert encrypted_data != original_data
    
    decrypt_file(file_path, key)
    with open(file_path, 'rb') as file:
        decrypted_data = file.read()
    assert decrypted_data == original_data

def test_rotate_encryption_key():
    data = b"Original data"
    old_key = generate_encryption_key()
    new_key = generate_encryption_key()
    encrypted_data = encrypt(data, old_key)
    rotated_data = rotate_encryption_key(old_key, new_key, encrypted_data)
    decrypted_data = decrypt(rotated_data, new_key)
    assert decrypted_data == data