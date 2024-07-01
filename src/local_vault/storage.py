# ark/src/local_vault/storage.py

import os
import json
import shutil
from pathlib import Path
from typing import Dict, List, Union, Optional
import fcntl
import stat
import tempfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

from .crypto import (
    encrypt, decrypt, generate_encryption_key, encrypt_key, decrypt_key,
    generate_hmac, verify_hmac, encrypt_file, decrypt_file,
    EncryptionError, DecryptionError
)
from .utils import secure_delete

# Constants
VAULT_DIR = Path.home() / '.local_vault'
VAULT_DATA_FILE = VAULT_DIR / 'vault_data.enc'
VAULT_META_FILE = VAULT_DIR / 'vault_meta.json'
KEY_FILE = VAULT_DIR / 'key.enc'
TEMP_DIR = VAULT_DIR / 'temp'
PBKDF2_ITERATIONS = 600000
AUTO_LOCK_DURATION = timedelta(minutes=5)

class VaultState:
    def __init__(self, vault_path):
        self.state_file = Path(vault_path) / '.vault_state'
        self.load_state()

    def load_state(self):
        if self.state_file.exists():
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            self.unlocked = state['unlocked']
            self.last_activity = datetime.fromisoformat(state['last_activity']) if state['last_activity'] else None
        else:
            self.unlocked = False
            self.last_activity = None

    def save_state(self):
        state = {
            'unlocked': self.unlocked,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None
        }
        with open(self.state_file, 'w') as f:
            json.dump(state, f)

    def unlock(self):
        self.unlocked = True
        self.last_activity = datetime.now()
        self.save_state()

    def lock(self):
        self.unlocked = False
        self.last_activity = None
        self.save_state()

    def is_unlocked(self):
        self.load_state()  # Reload state before checking
        if self.unlocked and self.last_activity:
            if (datetime.now() - self.last_activity) > timedelta(minutes=5):
                self.lock()
            else:
                self.last_activity = datetime.now()
                self.save_state()
        return self.unlocked

# Create a singleton instance
vault_state = VaultState(Path.home() / '.local_vault')

class VaultStorageError(Exception):
    """Custom exception for ark storage-related errors."""
    pass

class VaultStorage:
    def __init__(self):
        self.vault_path = VAULT_DIR
        self.data_file = VAULT_DATA_FILE
        self.meta_file = VAULT_META_FILE
        self.key_file = KEY_FILE
        self.temp_dir = TEMP_DIR
        self.lock_file = self.vault_path / 'ark.lock'

        # Ensure all necessary directories exist
        self.vault_path.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self._set_secure_permissions()

    def _set_secure_permissions(self):
        """Set secure permissions on the ark directory and files."""
        try:
            # Set directory permissions (read, write, execute only for owner)
            os.chmod(str(self.vault_path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            # Set file permissions (read, write only for owner)
            for file in [self.data_file, self.meta_file, self.key_file]:
                if file.exists():
                    os.chmod(str(file), stat.S_IRUSR | stat.S_IWUSR)

            # Attempt to set immutable flag on key files (Linux only)
            if os.name == 'posix':
                try:
                    import fcntl
                    for file in [self.data_file, self.meta_file, self.key_file]:
                        if file.exists():
                            with open(str(file), 'r') as f:
                                fcntl.ioctl(f.fileno(), 1123, 1)  # FS_IOC_SETFLAGS
                except (ImportError, IOError):
                    # fcntl might not be available or ioctl might not be supported
                    pass
        except Exception as e:
            raise VaultStorageError(f"Failed to set secure permissions: {str(e)}")
        
    def _check_integrity(self):
        """Check the integrity of ark files."""
        required_files = [self.data_file, self.meta_file, self.key_file]
        for file in required_files:
            if not file.exists():
                raise VaultStorageError(f"Ark integrity check failed: {file.name} is missing")

    def initialize_vault(self, hashed_password: bytes, encryption_key: bytes) -> bool:
        """Initialize the ark directory and store initial data."""
        try:
            # Check if the ark is already initialized
            if self.is_initialized():
                raise VaultStorageError("Ark is already initialized")

            # Create ark directory with restricted permissions
            self.vault_path.mkdir(parents=True, exist_ok=True)
            os.chmod(str(self.vault_path), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            # Create and secure temporary directory
            self.temp_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(str(self.temp_dir), stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

            # Store hashed password
            with open(self.vault_path / 'password.bin', 'wb') as f:
                f.write(hashed_password)

            # Generate and store key encryption key
            key_encryption_key = generate_encryption_key()
            encrypted_key = encrypt_key(encryption_key, key_encryption_key)

            # Store both the encrypted key and the key encryption key
            with open(self.key_file, 'wb') as f:
                f.write(key_encryption_key + encrypted_key)

            # Create an empty encrypted ark data file
            empty_data = encrypt(json.dumps({}).encode(), encryption_key)
            with open(self.data_file, 'wb') as f:
                f.write(empty_data)

            # Create metadata file
            metadata = {
                'version': '1.0',
                'created_at': str(Path(self.data_file).stat().st_ctime),
                'last_modified': str(Path(self.data_file).stat().st_mtime)
            }
            with open(self.meta_file, 'w') as f:
                json.dump(metadata, f)

            self._set_secure_permissions()
            return True
        except VaultStorageError:
            raise
        except Exception as e:
            raise VaultStorageError(f"Failed to initialize ark: {str(e)}")
        
    def is_initialized(self) -> bool:
        """Check if the ark is already initialized."""
        return (
            self.vault_path.exists() and
            self.data_file.exists() and
            self.key_file.exists() and
            self.meta_file.exists()
        )

    def _acquire_lock(self):
        self._check_integrity()  # Check integrity before acquiring lock
        """Acquire a file lock to ensure atomic operations."""
        self.lock_file.parent.mkdir(parents=True, exist_ok=True)
        self.lock_fd = os.open(self.lock_file, os.O_CREAT | os.O_RDWR)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            os.close(self.lock_fd)
            raise VaultStorageError("Another process is currently accessing the ark.")

    def _release_lock(self):
        self._check_integrity()  # Check integrity before acquiring lock
        """Release the file lock."""
        fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        os.close(self.lock_fd)

    def _read_encrypted_data(self) -> bytes:
        """Read encrypted data from the ark file."""
        try:
            self._check_integrity()  # Check integrity before acquiring lock
            with open(self.data_file, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return encrypt(json.dumps({}).encode(), self._get_encryption_key())

    def _write_encrypted_data(self, encrypted_data: bytes):
        """Write encrypted data to the ark file."""
        temp_file = tempfile.NamedTemporaryFile(dir=self.temp_dir, delete=False)
        try:
            self._check_integrity()  # Check integrity before acquiring lock
            with open(temp_file.name, 'wb') as f:
                f.write(encrypted_data)
            os.replace(temp_file.name, self.data_file)
        except Exception as e:
            os.unlink(temp_file.name)
            raise VaultStorageError(f"Failed to write encrypted data: {str(e)}")

    def _get_encryption_key(self) -> bytes:
        """Retrieve and decrypt the encryption key."""
        try:
            self._check_integrity()  # Check integrity before acquiring lock
            with open(self.key_file, 'rb') as f:
                data = f.read()
            key_encryption_key = data[:32]  # First 32 bytes
            encrypted_key = data[32:]  # Rest of the data
            decrypted_key = decrypt_key(encrypted_key, key_encryption_key)
            return decrypted_key
        except Exception as e:
            print(f"Debug: Exception in _get_encryption_key: {str(e)}")
            raise VaultStorageError(f"Failed to retrieve encryption key: {str(e)}")

    def _get_key_encryption_key(self) -> bytes:
        try:
            self._check_integrity()  # Check integrity before acquiring lock
            # Read the salt from a file
            salt_file = self.vault_path / 'kek_salt.bin'
            if not salt_file.exists():
                # If the salt doesn't exist, create a new one
                salt = os.urandom(32)
                with open(salt_file, 'wb') as f:
                    f.write(salt)
            else:
                with open(salt_file, 'rb') as f:
                    salt = f.read()

            # Read the master password hash
            with open(self.vault_path / 'password.bin', 'rb') as f:
                master_password_hash = f.read()

            # Use PBKDF2 to derive the key encryption key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=PBKDF2_ITERATIONS,
                backend=default_backend()
            )
            key_encryption_key = kdf.derive(master_password_hash)
            return key_encryption_key
        except Exception as e:
            raise VaultStorageError(f"Failed to derive key encryption key: {str(e)}")

    def store_encrypted_data(self, key: str, value: str) -> bool:
        """Store an encrypted key-value pair in the ark."""
        self._acquire_lock()
        try:
            # Type checking and validation for key
            if not isinstance(key, str):
                raise TypeError("Key must be a string")
            if not key:  # This checks for empty string as well
                raise ValueError("Key cannot be empty")

            # Type checking and validation for value
            if not isinstance(value, str):
                raise TypeError("Value must be a string")

            encrypted_data = self._read_encrypted_data()
            encryption_key = self._get_encryption_key()
            
            data = json.loads(decrypt(encrypted_data, encryption_key).decode('utf-8'))
            data[key] = value
            
            new_encrypted_data = encrypt(json.dumps(data, ensure_ascii=False).encode('utf-8'), encryption_key)
            self._write_encrypted_data(new_encrypted_data)
            
            self._update_metadata()
            return True
        except (TypeError, ValueError) as e:
            # Re-raise these specific exceptions to match the test expectations
            raise
        except Exception as e:
            raise VaultStorageError(f"Failed to store encrypted data: {str(e)}")
        finally:
            self._release_lock()

    def retrieve_encrypted_data(self, key: str) -> Optional[str]:
        """Retrieve a decrypted value from the ark."""
        self._acquire_lock()
        try:
            encrypted_data = self._read_encrypted_data()
            encryption_key = self._get_encryption_key()

            data = json.loads(decrypt(encrypted_data, encryption_key).decode('utf-8'))
            return data.get(key)
        except Exception as e:
            raise VaultStorageError(f"Failed to retrieve encrypted data: {str(e)}")
        finally:
            self._release_lock()

    def retrieve_user_password(self) -> bytes:
        """Retrieve the user's password from the password file. (and decrypt it)"""
        self._acquire_lock()
        try:
            with open(self.vault_path / 'password.bin', 'rb') as f:
                return f.read()
        except Exception as e:
            raise VaultStorageError(f"Failed to retrieve user password: {str(e)}")

    def list_vault_items(self) -> List[str]:
        """List all keys stored in the ark."""
        self._acquire_lock()
        try:
            encrypted_data = self._read_encrypted_data()
            encryption_key = self._get_encryption_key()
            
            data = json.loads(decrypt(encrypted_data, encryption_key).decode())
            return list(data.keys())
        except Exception as e:
            raise VaultStorageError(f"Failed to list ark items: {str(e)}")
        finally:
            self._release_lock()

    def delete_vault_item(self, key: str) -> bool:
        """Delete a key-value pair from the ark."""
        self._acquire_lock()
        try:
            # Type checking and validation for key
            if not isinstance(key, str):
                raise TypeError("Key must be a string")
            if not key:  # This checks for empty string as well
                raise ValueError("Key cannot be empty")

            encrypted_data = self._read_encrypted_data()
            encryption_key = self._get_encryption_key()
            
            data = json.loads(decrypt(encrypted_data, encryption_key).decode('utf-8'))
            if key in data:
                del data[key]
                new_encrypted_data = encrypt(json.dumps(data, ensure_ascii=False).encode('utf-8'), encryption_key)
                self._write_encrypted_data(new_encrypted_data)
                self._update_metadata()
                return True
            return False
        except (TypeError, ValueError) as e:
            # Re-raise these specific exceptions to match the test expectations
            raise
        except Exception as e:
            raise VaultStorageError(f"Failed to delete ark item: {str(e)}")
        finally:
            self._release_lock()

    def _update_metadata(self):
        """Update the metadata file with the latest modification time."""
        metadata = {
            'version': '1.0',
            'created_at': str(Path(self.data_file).stat().st_ctime),
            'last_modified': str(Path(self.data_file).stat().st_mtime)
        }
        with open(self.meta_file, 'w') as f:
            json.dump(metadata, f)

    def change_master_password(self, new_hashed_password: bytes) -> bool:
        """Change the master password of the ark."""
        self._acquire_lock()
        try:
            # Store new hashed password
            with open(self.vault_path / 'password.bin', 'wb') as f:
                f.write(new_hashed_password)

            # Generate and store a new salt for key encryption key derivation
            new_salt = os.urandom(32)
            with open(self.vault_path / 'kek_salt.bin', 'wb') as f:
                f.write(new_salt)

            # Re-encrypt the encryption key with a new key encryption key
            encryption_key = self._get_encryption_key()
            new_key_encryption_key = self._get_key_encryption_key()  # This will use the new salt
            new_encrypted_key = encrypt_key(encryption_key, new_key_encryption_key)
            with open(self.key_file, 'wb') as f:
                f.write(new_key_encryption_key + new_encrypted_key)

            return True
        except Exception as e:
            raise VaultStorageError(f"Failed to change master password: {str(e)}")
        finally:
            self._release_lock()

    def rotate_encryption_key(self, new_key: bytes) -> bool:
        """Rotate the encryption key of the ark."""
        self._acquire_lock()
        try:
            old_key = self._get_encryption_key()

            # Re-encrypt ark data with the new key
            encrypted_data = self._read_encrypted_data()
            decrypted_data = decrypt(encrypted_data, old_key)
            new_encrypted_data = encrypt(decrypted_data, new_key)
            self._write_encrypted_data(new_encrypted_data)

            # Generate a new key encryption key
            new_key_encryption_key = generate_encryption_key()
            
            # Encrypt the new encryption key
            encrypted_new_key = encrypt_key(new_key, new_key_encryption_key)
            
            # Store both the new key encryption key and the encrypted new key
            with open(self.key_file, 'wb') as f:
                f.write(new_key_encryption_key + encrypted_new_key)

            self._update_metadata()
            return True
        except Exception as e:
            print(f"Debug: Exception in rotate_encryption_key: {str(e)}")
            raise VaultStorageError(f"Failed to rotate encryption key: {str(e)}")
        finally:
            self._release_lock()

    def backup_vault(self, backup_path: Path) -> bool:
        """Create a backup of the entire ark."""
        self._acquire_lock()
        try:
            if backup_path.exists():
                shutil.rmtree(backup_path)
            shutil.copytree(self.vault_path, backup_path)
            return True
        except Exception as e:
            raise VaultStorageError(f"Failed to create ark backup: {str(e)}")
        finally:
            self._release_lock()

    def restore_vault(self, backup_path: Path) -> bool:
        """Restore the ark from a backup."""
        try:
            if not backup_path.is_dir():
                print(f"Debug: Backup path is not a directory")  # Debug print
                raise VaultStorageError("Invalid backup path")

            # Ensure the ark directory exists
            self.vault_path.mkdir(parents=True, exist_ok=True)
            
            # Now we can safely acquire the lock
            self._acquire_lock()
            try:
                # Remove existing ark contents
                for item in self.vault_path.iterdir():
                    if item != self.lock_file:  # Don't remove the lock file
                        if item.is_file():
                            os.unlink(item)
                        elif item.is_dir():
                            shutil.rmtree(item)
                
                # Copy backup contents to ark directory
                for item in backup_path.iterdir():
                    if item.is_file():
                        shutil.copy2(item, self.vault_path)
                    elif item.is_dir():
                        shutil.copytree(item, self.vault_path / item.name)
                
                return True
            finally:
                self._release_lock()
        except Exception as e:
            raise VaultStorageError(f"Failed to restore ark from backup: {str(e)}")

    def destroy_vault(self):
        """Securely destroy the entire ark."""
        self._acquire_lock()
        try:
            for root, dirs, files in os.walk(self.vault_path):
                for file in files:
                    secure_delete(Path(root) / file)
                for dir in dirs:
                    shutil.rmtree(Path(root) / dir)
            shutil.rmtree(self.vault_path)
        except Exception as e:
            raise VaultStorageError(f"Failed to destroy ark: {str(e)}")
        finally:
            self._release_lock()

vault_storage = VaultStorage()

# Wrapper functions for easier usage
def initialize_vault(hashed_password: bytes, encryption_key: bytes) -> bool:
    return vault_storage.initialize_vault(hashed_password, encryption_key)

def store_encrypted_data(key: str, value: str) -> bool:
    return vault_storage.store_encrypted_data(key, value)

def retrieve_user_password() -> bytes:
    return vault_storage.retrieve_user_password()

def retrieve_encrypted_data(key: str) -> Optional[str]:
    return vault_storage.retrieve_encrypted_data(key)

def list_vault_items() -> List[str]:
    return vault_storage.list_vault_items()

def delete_vault_item(key: str) -> bool:
    return vault_storage.delete_vault_item(key)

def change_master_password(new_hashed_password: bytes) -> bool:
    return vault_storage.change_master_password(new_hashed_password)

def rotate_encryption_key(new_key: bytes) -> bool:
    return vault_storage.rotate_encryption_key(new_key)

def backup_vault(backup_path: Path) -> bool:
    return vault_storage.backup_vault(backup_path)

def restore_vault(backup_path: Path) -> bool:
    return vault_storage.restore_vault(backup_path)

def destroy_vault():
    vault_storage.destroy_vault()

def is_vault_initialized() -> bool:
    """Check if the ark is initialized."""
    return VAULT_DIR.exists() and VAULT_DATA_FILE.exists() and KEY_FILE.exists()

def get_vault_path() -> Path:
    """Get the path of the ark directory."""
    return VAULT_DIR


__all__ = [
    'initialize_vault',
    'store_encrypted_data',
    'retrieve_encrypted_data',
    'list_vault_items',
    'delete_vault_item',
    'change_master_password',
    'rotate_encryption_key',
    'backup_vault',
    'restore_vault',
    'destroy_vault',
    'is_vault_initialized',
    'get_vault_path',
]