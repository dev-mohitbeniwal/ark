# ark/tests/test_utils.py

import os
import tempfile
import pytest
from pathlib import Path
import ctypes
import string
import platform

from local_vault.utils import (
    secure_delete, generate_random_password, validate_password_strength,
    is_root, ensure_directory_permissions, secure_temporary_file,
    get_system_entropy, is_debugger_present, secure_memset,
    constant_time_compare, disable_core_dumps, harden_process,
    secure_random_bytes, lock_memory, secure_delete_directory
)

def test_secure_delete(tmpdir):
    file_path = Path(tmpdir) / "test.txt"
    with open(file_path, "w") as f:
        f.write("Test data")
    secure_delete(file_path)
    assert not file_path.exists()

def test_secure_delete_invalid_path():
    with pytest.raises(ValueError):
        secure_delete(Path("nonexistent"))

def test_generate_random_password():
    password = generate_random_password(length=20)
    assert len(password) == 20
    assert any(c.isdigit() for c in password)
    assert any(c.isalpha() for c in password)
    assert any(c in string.punctuation for c in password)

def test_validate_password_strength():
    assert validate_password_strength("Str0ngP@ssw0rd!")
    assert not validate_password_strength("weakpassword")

def test_is_root(monkeypatch):
    monkeypatch.setattr("os.geteuid", lambda: 0)
    assert is_root()
    monkeypatch.setattr("os.geteuid", lambda: 1000)
    assert not is_root()

def test_ensure_directory_permissions(tmpdir):
    dir_path = Path(tmpdir) / "test_dir"
    ensure_directory_permissions(dir_path)
    assert dir_path.exists()
    assert oct(dir_path.stat().st_mode)[-3:] == "700"

def test_secure_temporary_file():
    with secure_temporary_file(mode='w+b', suffix='.txt') as f:
        f.write(b"Test data")
        f.flush()
        assert os.path.exists(f.name)
        assert oct(os.stat(f.name).st_mode)[-3:] == "600"

def test_get_system_entropy():
    entropy = get_system_entropy()
    if platform.system() == 'Linux':
        assert isinstance(entropy, int)
    else:
        assert entropy is None

def test_is_debugger_present():
    assert not is_debugger_present()

def test_secure_memset():
    data = ctypes.create_string_buffer(b"Test data")
    secure_memset(data)
    assert data.raw == b"\x00" * len(data.raw)

def test_secure_memset_invalid_input():
    with pytest.raises(TypeError):
        secure_memset("Not a ctypes string")

def test_constant_time_compare():
    assert constant_time_compare(b"test", b"test")
    assert not constant_time_compare(b"test", b"test1")

def test_disable_core_dumps():
    # This test doesn't have a direct assertion since the effect of disabling
    # core dumps is not easily observable. The test serves as a smoke test to
    # ensure that the function can be called without errors.
    disable_core_dumps()

def test_harden_process():
    # Similar to the disable_core_dumps test, this test serves as a smoke test.
    harden_process()

def test_secure_random_bytes():
    random_bytes = secure_random_bytes(16)
    assert len(random_bytes) == 16
    assert isinstance(random_bytes, bytes)

def test_lock_memory():
    # This test serves as a smoke test to ensure that the function can be called
    # without errors. The actual effect of locking memory is not easily observable.
    lock_memory()

def test_secure_delete_directory(tmpdir):
    dir_path = Path(tmpdir) / "test_dir"
    dir_path.mkdir()
    file_path = dir_path / "test.txt"
    with open(file_path, "w") as f:
        f.write("Test data")
    secure_delete_directory(dir_path)
    assert not dir_path.exists()