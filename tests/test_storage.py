import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import shutil

from local_vault.storage import VaultStorage, VaultStorageError, PBKDF2_ITERATIONS

@pytest.fixture
def temp_vault_dir():
    with tempfile.TemporaryDirectory() as tmpdirname:
        yield Path(tmpdirname)

@pytest.fixture
def mock_permissions():
    with patch('os.chmod') as mock_chmod:
        yield mock_chmod

@pytest.fixture
def vault_storage(temp_vault_dir):
    with patch('local_vault.storage.VAULT_DIR', temp_vault_dir):
        storage = VaultStorage()
        # Create necessary files to pass integrity check
        storage.vault_path.mkdir(parents=True, exist_ok=True)
        storage.data_file.touch()
        storage.meta_file.touch()
        storage.key_file.touch()
        yield storage

@pytest.fixture(autouse=True)
def remove_vault(vault_storage):
    # Delete the existing ark directory before running each test
    if vault_storage.vault_path.exists():
        shutil.rmtree(vault_storage.vault_path)

def test_initialize_vault(vault_storage, mock_permissions):
    hashed_password = b'hashed_password'
    encryption_key = os.urandom(32)
    
    vault_storage.initialize_vault(hashed_password, encryption_key)
    
    assert (vault_storage.vault_path / 'password.bin').exists()
    assert vault_storage.key_file.exists()
    assert vault_storage.data_file.exists()
    assert vault_storage.meta_file.exists()
    
    # Check that chmod was called
    assert mock_permissions.called

def test_store_and_retrieve_encrypted_data(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    
    assert vault_storage.store_encrypted_data('test_key', 'test_value')
    retrieved_value = vault_storage.retrieve_encrypted_data('test_key')
    assert retrieved_value == 'test_value'

def test_list_vault_items(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    
    vault_storage.store_encrypted_data('key1', 'value1')
    vault_storage.store_encrypted_data('key2', 'value2')
    
    items = vault_storage.list_vault_items()
    assert set(items) == {'key1', 'key2'}

def test_delete_vault_item(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    
    vault_storage.store_encrypted_data('key1', 'value1')
    assert vault_storage.delete_vault_item('key1')
    assert vault_storage.retrieve_encrypted_data('key1') is None

def test_change_master_password(vault_storage):
    vault_storage.initialize_vault(b'old_hashed_password', os.urandom(32))
    
    new_hashed_password = b'new_hashed_password'
    assert vault_storage.change_master_password(new_hashed_password)
    
    with open(vault_storage.vault_path / 'password.bin', 'rb') as f:
        stored_password = f.read()
    assert stored_password == new_hashed_password

def test_rotate_encryption_key(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    
    vault_storage.store_encrypted_data('test_key', 'test_value')
    new_encryption_key = os.urandom(32)
    assert vault_storage.rotate_encryption_key(new_encryption_key)
    
    # Ensure data is still accessible after key rotation
    retrieved_value = vault_storage.retrieve_encrypted_data('test_key')
    assert retrieved_value == 'test_value'

def test_backup_and_restore_vault(vault_storage, temp_vault_dir: Path):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    vault_storage.store_encrypted_data('test_key', 'test_value')
    
    # create a backup path for the ark (using tempfile library to create a new temporary directory)
    new_temp_dir = tempfile.mkdtemp()

    backup_path = Path(new_temp_dir) / 'vault_backup'
    assert vault_storage.backup_vault(backup_path)
    
    # Simulate ark destruction and restoration
    vault_storage.destroy_vault()
    assert vault_storage.restore_vault(backup_path)
    
    # Ensure data is still accessible after restoration
    assert vault_storage.retrieve_encrypted_data('test_key') == 'test_value'

def test_destroy_vault(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    vault_storage.destroy_vault()
    
    assert not vault_storage.vault_path.exists()

# def test_concurrent_access(vault_storage):
#     vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    
#     # Simulate concurrent access
#     with patch('fcntl.flock', side_effect=[None, IOError]):
#         vault_storage.store_encrypted_data('key1', 'value1')
#         with pytest.raises(VaultStorageError, match="Another process is currently accessing the ark."):
#             vault_storage.store_encrypted_data('key2', 'value2')

def test_get_key_encryption_key(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    
    key1 = vault_storage._get_key_encryption_key()
    key2 = vault_storage._get_key_encryption_key()
    
    assert key1 == key2
    assert len(key1) == 32  # 256 bits

def test_pbkdf2_iterations():
    assert PBKDF2_ITERATIONS == 600000

def test_initialize_vault_twice(vault_storage):
    with patch('os.chmod'), patch('fcntl.ioctl', create=True):
        # First initialization
        assert vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
        
        # Verify that the ark files exist
        assert vault_storage.data_file.exists()
        assert vault_storage.meta_file.exists()
        assert vault_storage.key_file.exists()
        
        # Attempt to initialize again
        with pytest.raises(VaultStorageError, match="Ark is already initialized"):
            vault_storage.initialize_vault(b'hashed_password', os.urandom(32))

    # Verify that the second initialization attempt didn't overwrite the existing files
    assert vault_storage.data_file.exists()
    assert vault_storage.meta_file.exists()
    assert vault_storage.key_file.exists()

def test_retrieve_non_existent_key(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    assert vault_storage.retrieve_encrypted_data('non_existent_key') is None

def test_delete_non_existent_key(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    assert not vault_storage.delete_vault_item('non_existent_key')

def test_store_empty_value(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    assert vault_storage.store_encrypted_data('empty_key', '')
    assert vault_storage.retrieve_encrypted_data('empty_key') == ''

def test_store_large_data(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    large_value = 'a' * 1000000  # 1MB of data
    assert vault_storage.store_encrypted_data('large_key', large_value)
    assert vault_storage.retrieve_encrypted_data('large_key') == large_value

# def test_metadata_update(vault_storage):
#     vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
#     initial_metadata = json.loads(vault_storage.meta_file.read_text())
    
#     vault_storage.store_encrypted_data('test_key', 'test_value')
#     updated_metadata = json.loads(vault_storage.meta_file.read_text())
    
#     assert initial_metadata['last_modified'] != updated_metadata['last_modified']

def test_corrupted_data_file(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    vault_storage.store_encrypted_data('test_key', 'test_value')
    
    # Corrupt the data file
    with open(vault_storage.data_file, 'wb') as f:
        f.write(b'corrupted data')
    
    with pytest.raises(VaultStorageError):
        vault_storage.retrieve_encrypted_data('test_key')

def test_missing_key_file(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    vault_storage.key_file.unlink()
    
    with pytest.raises(VaultStorageError, match="Ark integrity check failed: key.enc is missing"):
        vault_storage.retrieve_encrypted_data('test_key')

def test_invalid_backup_path(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    with pytest.raises(VaultStorageError, match="Failed to create ark backup"):
        vault_storage.backup_vault('/nonexistent/path')

def test_restore_from_invalid_backup(vault_storage, temp_vault_dir):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    invalid_backup_path = temp_vault_dir / 'invalid_backup'
    invalid_backup_path.mkdir()
    
    with pytest.raises(VaultStorageError, match="Failed to restore ark from backup"):
        vault_storage.restore_vault(invalid_backup_path)

def test_change_master_password_with_data(vault_storage):
    initial_encryption_key = os.urandom(32)
    vault_storage.initialize_vault(b'old_hashed_password', initial_encryption_key)
    vault_storage.store_encrypted_data('test_key', 'test_value')
    
    new_hashed_password = b'new_hashed_password'
    assert vault_storage.change_master_password(new_hashed_password)
    
    # Ensure data is still accessible after password change
    assert vault_storage.retrieve_encrypted_data('test_key') == 'test_value'

def test_rotate_encryption_key_with_multiple_items(vault_storage):
    old_encryption_key = os.urandom(32)
    vault_storage.initialize_vault(b'hashed_password', old_encryption_key)
    
    vault_storage.store_encrypted_data('key1', 'value1')
    vault_storage.store_encrypted_data('key2', 'value2')
    
    new_encryption_key = os.urandom(32)
    assert vault_storage.rotate_encryption_key(new_encryption_key)
    
    # Ensure all data is still accessible after key rotation
    assert vault_storage.retrieve_encrypted_data('key1') == 'value1'
    assert vault_storage.retrieve_encrypted_data('key2') == 'value2'

@pytest.mark.parametrize("invalid_key", [None, 123, b"bytes"])
def test_store_invalid_key_type(vault_storage, invalid_key):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    with pytest.raises((TypeError, VaultStorageError)):
        vault_storage.store_encrypted_data(invalid_key, 'test_value')

@pytest.mark.parametrize("invalid_value", [None, 123, b"bytes", {'dict': 'value'}])
def test_store_invalid_value_type(vault_storage, invalid_value):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    with pytest.raises((TypeError, VaultStorageError)):
        vault_storage.store_encrypted_data('test_key', invalid_value)

# def test_concurrent_write_operations(vault_storage):
#     vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    
#     # Simulate concurrent write operations
#     with patch('fcntl.flock', side_effect=[None, None, IOError]):
#         vault_storage.store_encrypted_data('key1', 'value1')
#         vault_storage.store_encrypted_data('key2', 'value2')
#         with pytest.raises(VaultStorageError, match="Another process is currently accessing the ark."):
#             vault_storage.delete_vault_item('key1')

def test_vault_persistence(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    vault_storage.store_encrypted_data('test_key', 'test_value')
    
    # Create a new VaultStorage instance to simulate application restart
    new_storage = VaultStorage()
    assert new_storage.retrieve_encrypted_data('test_key') == 'test_value'

def test_long_key_names(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    long_key = 'a' * 1000  # 1000 character key
    assert vault_storage.store_encrypted_data(long_key, 'test_value')
    assert vault_storage.retrieve_encrypted_data(long_key) == 'test_value'

def test_special_characters_in_keys_and_values(vault_storage):
    vault_storage.initialize_vault(b'hashed_password', os.urandom(32))
    special_key = '!@#$%^&*()_+{}|:"<>?`~'
    special_value = '§±!@#$%^&*()_+[]{}|;:"./<>?`~'
    assert vault_storage.store_encrypted_data(special_key, special_value)
    assert vault_storage.retrieve_encrypted_data(special_key) == special_value