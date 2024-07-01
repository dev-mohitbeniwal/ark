import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock
from local_vault.cli import cli

@pytest.fixture
def runner():
    return CliRunner()

@pytest.fixture
def mock_vault_state():
    with patch('local_vault.cli.vault_state') as mock:
        yield mock

@pytest.fixture
def mock_storage():
    with patch('local_vault.cli.initialize_vault') as init_mock, \
         patch('local_vault.cli.store_encrypted_data') as store_mock, \
         patch('local_vault.cli.retrieve_encrypted_data') as retrieve_mock, \
         patch('local_vault.cli.retrieve_user_password') as retrieve_pass_mock, \
         patch('local_vault.cli.list_vault_items') as list_mock, \
         patch('local_vault.cli.delete_vault_item') as delete_mock, \
         patch('local_vault.cli.is_vault_initialized') as is_init_mock, \
         patch('local_vault.cli.get_vault_path') as get_path_mock:
        yield {
            'init': init_mock,
            'store': store_mock,
            'retrieve': retrieve_mock,
            'retrieve_pass': retrieve_pass_mock,
            'list': list_mock,
            'delete': delete_mock,
            'is_init': is_init_mock,
            'get_path': get_path_mock
        }

def test_init_command(runner, mock_storage):
    mock_storage['is_init'].return_value = False
    mock_storage['init'].return_value = True
    mock_storage['get_path'].return_value = '/fake/path'
    
    result = runner.invoke(cli, ['init'], input='StrongPassword123!\nStrongPassword123!\n')
    
    assert result.exit_code == 0
    assert "Ark initialized successfully." in result.output
    assert "Ark location: /fake/path" in result.output

def test_init_command_already_initialized(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    
    result = runner.invoke(cli, ['init'], input='StrongPassword123!\nStrongPassword123!\n')
    
    assert result.exit_code == 0
    assert "Error: Ark is already initialized." in result.output

def test_lock_command(runner, mock_vault_state):
    result = runner.invoke(cli, ['lock'])
    
    assert result.exit_code == 0
    assert "Ark locked." in result.output
    mock_vault_state.lock.assert_called_once()

def test_unlock_command_success(runner, mock_storage, mock_vault_state):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=True):
        result = runner.invoke(cli, ['unlock'], input='password\n')
    
    assert result.exit_code == 0
    assert "Ark unlocked successfully." in result.output
    mock_vault_state.unlock.assert_called_once()

def test_unlock_command_failure(runner, mock_storage, mock_vault_state):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=False):
        result = runner.invoke(cli, ['unlock'], input='wrong_password\n')
    
    assert result.exit_code == 0
    assert "Error: Incorrect password." in result.output
    mock_vault_state.unlock.assert_not_called()

@patch('local_vault.cli.vault_state')
def test_add_command(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['store'].return_value = True
    
    result = runner.invoke(cli, ['add', 'test_key', 'test_value'])
    
    assert result.exit_code == 0
    assert "Added 'test_key' to the ark." in result.output

@patch('local_vault.cli.vault_state')
def test_get_command(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['retrieve'].return_value = 'test_value'
    
    with patch('pyperclip.copy') as mock_copy:
        result = runner.invoke(cli, ['get', 'test_key'])
    
    assert result.exit_code == 0
    assert "Value for 'test_key' copied to clipboard." in result.output
    mock_copy.assert_called_once_with('test_value')

@patch('local_vault.cli.vault_state')
def test_list_command(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['list'].return_value = ['key1', 'key2']
    
    result = runner.invoke(cli, ['list'])
    
    assert result.exit_code == 0
    assert "Stored items:" in result.output
    assert "- key1" in result.output
    assert "- key2" in result.output

@patch('local_vault.cli.vault_state')
def test_delete_command(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['delete'].return_value = True
    
    result = runner.invoke(cli, ['delete', 'test_key', '--force'])
    
    assert result.exit_code == 0
    assert "Deleted 'test_key' from the ark." in result.output

def test_change_password_command(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['store'].return_value = True
    
    result = runner.invoke(cli, ['change-password'], input='NewStrongPassword123!\nNewStrongPassword123!\n')
    
    assert result.exit_code == 0
    assert "Password changed successfully." in result.output

from unittest.mock import patch, MagicMock

def test_destroy_command(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.secure_delete_directory') as mock_delete, \
         patch('local_vault.cli.verify_password', return_value=True) as mock_verify, \
         patch('local_vault.cli.retrieve_user_password', return_value=b'stored_password') as mock_retrieve:
        
        result = runner.invoke(cli, ['destroy', '--force'], input='correct_password\n')
        
        if result.exception:
            print(f"Exception: {result.exception}")
        
        assert result.exit_code == 0
        assert "Ark destroyed successfully." in result.output
        mock_delete.assert_called_once()
        mock_verify.assert_called_once_with(b'stored_password', 'correct_password')
        mock_retrieve.assert_called_once()

def test_init_command_weak_password(runner, mock_storage):
    mock_storage['is_init'].return_value = False
    
    result = runner.invoke(cli, ['init'], input='weak\nweak\n')
    
    assert result.exit_code == 0
    assert "Error: Password does not meet the requirements." in result.output

def test_init_command_initialization_failure(runner, mock_storage):
    mock_storage['is_init'].return_value = False
    mock_storage['init'].return_value = False
    
    result = runner.invoke(cli, ['init'], input='StrongPassword123!\nStrongPassword123!\n')
    
    assert result.exit_code == 0
    assert "Error: Failed to initialize ark." in result.output

def test_unlock_command_vault_not_initialized(runner, mock_storage):
    mock_storage['is_init'].return_value = False
    
    result = runner.invoke(cli, ['unlock'], input='password\n')
    
    assert result.exit_code == 0
    assert "Error: Ark is not initialized. Please run 'init' command first." in result.output

@patch('local_vault.cli.vault_state')
def test_add_command_vault_locked(mock_vault_state, runner):
    mock_vault_state.is_unlocked.return_value = False
    
    result = runner.invoke(cli, ['add', 'test_key', 'test_value'])
    
    assert result.exit_code == 0
    assert "Error: Ark is locked. Please unlock the ark first." in result.output

@patch('local_vault.cli.vault_state')
def test_add_command_storage_failure(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['store'].return_value = False
    
    result = runner.invoke(cli, ['add', 'test_key', 'test_value'])
    
    assert result.exit_code == 0
    assert "Error: Failed to add 'test_key' to the ark." in result.output

@patch('local_vault.cli.vault_state')
def test_get_command_key_not_found(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['retrieve'].return_value = None
    
    result = runner.invoke(cli, ['get', 'non_existent_key'])
    
    assert result.exit_code == 0
    assert "Error: No value found for 'non_existent_key'." in result.output

@patch('local_vault.cli.vault_state')
def test_list_command_empty_vault(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['list'].return_value = []
    
    result = runner.invoke(cli, ['list'])
    
    assert result.exit_code == 0
    assert "The ark is empty." in result.output

@patch('local_vault.cli.vault_state')
def test_delete_command_non_existent_key(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['delete'].return_value = False
    
    result = runner.invoke(cli, ['delete', 'non_existent_key', '--force'])
    
    assert result.exit_code == 0
    assert "Error: Failed to delete 'non_existent_key' from the ark." in result.output

def test_change_password_command_vault_not_initialized(runner, mock_storage):
    mock_storage['is_init'].return_value = False
    
    result = runner.invoke(cli, ['change-password'], input='NewPassword123!\nNewPassword123!\n')
    
    assert result.exit_code == 0
    assert "Error: Ark is not initialized. Please run 'init' command first." in result.output

def test_change_password_command_weak_password(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    
    result = runner.invoke(cli, ['change-password'], input='weak\nweak\n')
    
    assert result.exit_code == 0
    assert "Error: New password does not meet the requirements." in result.output

def test_change_password_command_storage_failure(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['store'].return_value = False
    
    result = runner.invoke(cli, ['change-password'], input='NewStrongPassword123!\nNewStrongPassword123!\n')
    
    assert result.exit_code == 0
    assert "Error: Failed to change password." in result.output

def test_destroy_command_vault_not_initialized(runner, mock_storage):
    mock_storage['is_init'].return_value = False
    
    result = runner.invoke(cli, ['destroy'], input='password\n')
    
    assert result.exit_code == 0
    assert "Error: Ark is not initialized." in result.output

def test_destroy_command_user_abort(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=True):
        result = runner.invoke(cli, ['destroy'], input='correct_password\nn\n')
    
    assert result.exit_code == 0
    assert "Ark destruction cancelled." in result.output

def test_destroy_command_deletion_error(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=True), \
         patch('local_vault.cli.secure_delete_directory', side_effect=Exception("Deletion error")):
        result = runner.invoke(cli, ['destroy', '--force'], input='correct_password\n')
    
    assert result.exit_code == 0
    assert "Error: Failed to destroy ark. Deletion error" in result.output

# Test for auto-lock functionality
@patch('local_vault.cli.vault_state')
def test_auto_lock(mock_vault_state, runner):
    mock_vault_state.is_unlocked.return_value = False
    
    result = runner.invoke(cli, ['list'])
    
    assert result.exit_code == 0
    assert "Error: Ark is locked. Please unlock the ark first." in result.output

# Test for handling of special characters in keys and values
@patch('local_vault.cli.vault_state')
def test_add_command_special_characters(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['store'].return_value = True
    
    result = runner.invoke(cli, ['add', 'special!@#$%^&*()_+{}|:"<>?`~', 'value!@#$%^&*()_+{}|:"<>?`~'])
    
    assert result.exit_code == 0
    assert "Added 'special!@#$%^&*()_+{}|:\"<>?`~' to the ark." in result.output

# Test for handling very long keys and values
@patch('local_vault.cli.vault_state')
def test_add_command_long_key_value(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['store'].return_value = True
    
    long_key = 'a' * 1000
    long_value = 'b' * 10000
    
    result = runner.invoke(cli, ['add', long_key, long_value])
    
    assert result.exit_code == 0
    assert f"Added '{long_key}' to the ark." in result.output

# Test for handling Unicode characters
@patch('local_vault.cli.vault_state')
def test_add_command_unicode(mock_vault_state, runner, mock_storage):
    mock_vault_state.is_unlocked.return_value = True
    mock_storage['store'].return_value = True
    
    result = runner.invoke(cli, ['add', '日本語', '中文'])
    
    assert result.exit_code == 0
    assert "Added '日本語' to the ark." in result.output


def test_destroy_command_incorrect_password(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=False):
        result = runner.invoke(cli, ['destroy'], input='wrong_password\n')
    
    assert result.exit_code == 0
    assert "Error: Incorrect password. Ark destruction cancelled." in result.output

def test_destroy_command_correct_password(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=True), \
         patch('local_vault.cli.secure_delete_directory') as mock_delete:
        result = runner.invoke(cli, ['destroy'], input='correct_password\ny\n')
    
    assert result.exit_code == 0
    assert "Are you sure you want to destroy the ark? This action cannot be undone." in result.output
    assert "Ark destroyed successfully." in result.output
    mock_delete.assert_called_once()

def test_destroy_command_correct_password_but_cancelled(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=True):
        result = runner.invoke(cli, ['destroy'], input='correct_password\nn\n')
    
    assert result.exit_code == 0
    assert "Are you sure you want to destroy the ark? This action cannot be undone." in result.output
    assert "Ark destruction cancelled." in result.output

def test_destroy_command_force_still_requires_password(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=True), \
         patch('local_vault.cli.secure_delete_directory') as mock_delete:
        result = runner.invoke(cli, ['destroy', '--force'], input='correct_password\n')
    
    assert result.exit_code == 0
    assert "Ark destroyed successfully." in result.output
    mock_delete.assert_called_once()

def test_destroy_command_force_incorrect_password(runner, mock_storage):
    mock_storage['is_init'].return_value = True
    mock_storage['retrieve_pass'].return_value = b'hashed_password'
    
    with patch('local_vault.cli.verify_password', return_value=False):
        result = runner.invoke(cli, ['destroy', '--force'], input='wrong_password\n')
    
    assert result.exit_code == 0
    assert "Error: Incorrect password. Ark destruction cancelled." in result.output
