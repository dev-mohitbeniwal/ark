# ark/src/local_vault/utils.py

import os
import shutil
import secrets
import string
import re
from pathlib import Path
import subprocess
import tempfile
import platform
import ctypes

def secure_delete(path: Path, passes: int = 3):
    """
    Securely delete a file by overwriting it multiple times before deletion.
    
    :param path: Path to the file to be securely deleted
    :param passes: Number of overwrite passes (default is 3)
    """
    if not path.is_file():
        raise ValueError("The path must be a file")

    file_size = path.stat().st_size

    for _ in range(passes):
        with open(path, "wb") as f:
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())

    path.unlink()

def generate_random_password(length: int = 16, include_special: bool = True) -> str:
    """
    Generate a random password of specified length.
    
    :param length: Length of the password (default is 16)
    :param include_special: Whether to include special characters (default is True)
    :return: Random password string
    """
    charset = string.ascii_letters + string.digits
    if include_special:
        charset += string.punctuation

    return ''.join(secrets.choice(charset) for _ in range(length))

def validate_password_strength(password: str) -> bool:
    """
    Validate the strength of a given password.
    
    :param password: Password to validate
    :return: True if password meets strength requirements, False otherwise
    """
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

def clear_clipboard(timeout: int = 60):
    """
    Clear the clipboard after a specified timeout.
    
    :param timeout: Time in seconds before clearing the clipboard (default is 60)
    """
    import threading
    import pyperclip

    def clear():
        pyperclip.copy('')

    threading.Timer(timeout, clear).start()

def is_root() -> bool:
    """Check if the current process has root/administrator privileges."""
    return os.geteuid() == 0 if os.name != 'nt' else ctypes.windll.shell32.IsUserAnAdmin() != 0

def ensure_directory_permissions(path: Path, mode: int = 0o700):
    """
    Ensure the directory has the correct permissions.
    
    :param path: Path to the directory
    :param mode: Permission mode (default is 0o700, which is read/write/execute for owner only)
    """
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(mode)

def secure_temporary_file(mode: str = 'w+b', suffix: str = None, dir: Path = None) -> tempfile.NamedTemporaryFile:
    """
    Create a secure temporary file with restricted permissions.
    
    :param mode: File mode (default is 'w+b')
    :param suffix: File suffix
    :param dir: Directory to create the file in
    :return: NamedTemporaryFile object
    """
    fd, path = tempfile.mkstemp(suffix=suffix, dir=dir)
    os.close(fd)
    os.chmod(path, 0o600)  # Restrict permissions to owner only
    return tempfile.NamedTemporaryFile(mode=mode, suffix=suffix, dir=dir, delete=False)

def get_system_entropy() -> int:
    """
    Get the current system entropy.
    
    :return: Current system entropy or None if not available
    """
    if platform.system() == 'Linux':
        try:
            with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
                return int(f.read().strip())
        except:
            return None
    return None

def is_debugger_present() -> bool:
    """Check if a debugger is attached to the current process."""
    if platform.system() == 'Windows':
        import ctypes
        return ctypes.windll.kernel32.IsDebuggerPresent() != 0
    elif platform.system() == 'Linux':
        try:
            with open('/proc/self/status', 'r') as f:
                for line in f:
                    if line.startswith('TracerPid:'):
                        return int(line.split(':')[1].strip()) != 0
        except:
            pass
    return False

def secure_memset(ctypes_buffer, value: int = 0):
    """
    Securely overwrite a ctypes buffer.
    
    :param ctypes_buffer: A ctypes buffer object (e.g., ctypes.c_char_p or ctypes array)
    :param value: Value to overwrite with (default is 0)
    """
    if not isinstance(ctypes_buffer, (ctypes.c_char_p, ctypes.Array)):
        raise TypeError("Input must be a ctypes.c_char_p or ctypes array object")
    
    size = ctypes.sizeof(ctypes_buffer)
    ctypes.memset(ctypes.byref(ctypes_buffer), value, size)

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Perform a constant-time comparison of two byte strings.
    
    :param a: First byte string
    :param b: Second byte string
    :return: True if the strings are equal, False otherwise
    """
    return secrets.compare_digest(a, b)

def disable_core_dumps():
    """Attempt to disable core dumps."""
    if hasattr(os, 'setrlimit'):
        import resource
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        except:
            pass

def harden_process():
    """Apply various hardening measures to the current process."""
    disable_core_dumps()
    # Add more hardening measures as needed

def secure_random_bytes(n: int) -> bytes:
    """
    Generate secure random bytes.
    
    :param n: Number of bytes to generate
    :return: Secure random bytes
    """
    return os.urandom(n)

def lock_memory():
    """Attempt to lock the process memory to prevent swapping."""
    if platform.system() == 'Linux':
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            MCL_CURRENT = 1
            libc.mlockall(MCL_CURRENT)
        except:
            pass

def secure_delete_directory(path: Path):
    """Recursively and securely delete a directory and its contents."""
    for item in path.iterdir():
        if item.is_file():
            secure_delete(item)
        elif item.is_dir():
            secure_delete_directory(item)
    path.rmdir()