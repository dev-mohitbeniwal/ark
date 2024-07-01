# ark/src/local_vault/cli.py

import click
import os
import sys
from pathlib import Path
from functools import wraps
from datetime import datetime, timedelta

from .crypto import hash_password, verify_password, generate_encryption_key
from .storage import (
    initialize_vault, 
    store_encrypted_data, 
    retrieve_encrypted_data, 
    retrieve_user_password,
    list_vault_items,
    delete_vault_item,
    is_vault_initialized,
    get_vault_path,
    vault_state
)

from .utils import validate_password_strength, secure_delete_directory

def vault_unlocked_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not vault_state.is_unlocked():
            click.echo("Error: Ark is locked. Please unlock the ark first.")
            return
        return f(*args, **kwargs)
    return decorated_function

@click.group()
def cli():
    """Local Ark CLI - Secure storage for sensitive information"""
    pass

@cli.command()
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def init(password):
    """Initialize the ark"""
    if is_vault_initialized():
        click.echo("Error: Ark is already initialized.")
        return

    if not validate_password_strength(password):
        click.echo("Error: Password does not meet the requirements.")
        click.echo("Password must be at least 12 characters long and contain:")
        click.echo("- At least one uppercase letter")
        click.echo("- At least one lowercase letter")
        click.echo("- At least one number")
        click.echo("- At least one special character")
        return
    
    hashed_password = hash_password(password)
    encryption_key = generate_encryption_key()
    
    if initialize_vault(hashed_password, encryption_key):
        click.echo("Ark initialized successfully.")
        click.echo(f"Ark location: {get_vault_path()}")
    else:
        click.echo("Error: Failed to initialize ark.")

@cli.command()
def lock():
    """Lock the ark"""
    vault_state.lock()
    click.echo("Ark locked.")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
def unlock(password):
    """Unlock the ark"""
    if not is_vault_initialized():
        click.echo("Error: Ark is not initialized. Please run 'init' command first.")
        return

    stored_password = retrieve_user_password()
    if verify_password(stored_password, password):
        vault_state.unlock()
        click.echo("Ark unlocked successfully.")
    else:
        click.echo("Error: Incorrect password.")


@cli.command()
@vault_unlocked_required
@click.argument('key')
@click.argument('value')
def add(key, value):
    """Add a key-value pair to the ark"""
    if store_encrypted_data(key, value):
        click.echo(f"Added '{key}' to the ark.")
    else:
        click.echo(f"Error: Failed to add '{key}' to the ark.")

@cli.command()
@vault_unlocked_required
@click.argument('key')
def get(key):
    """Retrieve a value from the ark and copy to clipboard"""
    value = retrieve_encrypted_data(key)
    if value:
        import pyperclip
        pyperclip.copy(value)
        click.echo(f"Value for '{key}' copied to clipboard.")
    else:
        click.echo(f"Error: No value found for '{key}'.")

@cli.command()
@vault_unlocked_required
def list():
    """List all keys stored in the ark"""
    items = list_vault_items()
    if items:
        click.echo("Stored items:")
        for item in items:
            click.echo(f"- {item}")
    else:
        click.echo("The ark is empty.")

@cli.command()
@vault_unlocked_required
@click.argument('key')
@click.option('--force', is_flag=True, help="Force deletion without confirmation")
def delete(key, force):
    """Delete a key-value pair from the ark"""
    if not force:
        if not click.confirm(f"Are you sure you want to delete '{key}'?"):
            click.echo("Deletion cancelled.")
            return
    
    if delete_vault_item(key):
        click.echo(f"Deleted '{key}' from the ark.")
    else:
        click.echo(f"Error: Failed to delete '{key}' from the ark.")

@cli.command()
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def change_password(password):
    """Change the ark password"""
    if not is_vault_initialized():
        click.echo("Error: Ark is not initialized. Please run 'init' command first.")
        return

    if not validate_password_strength(password):
        click.echo("Error: New password does not meet the requirements.")
        return

    hashed_password = hash_password(password)
    if store_encrypted_data('password.bin', hashed_password):
        click.echo("Password changed successfully.")
    else:
        click.echo("Error: Failed to change password.")

# ark/src/local_vault/cli.py

import click
import os
import sys
from pathlib import Path
from functools import wraps
from datetime import datetime, timedelta

from .crypto import hash_password, verify_password, generate_encryption_key
from .storage import (
    initialize_vault, 
    store_encrypted_data, 
    retrieve_encrypted_data, 
    retrieve_user_password,
    list_vault_items,
    delete_vault_item,
    is_vault_initialized,
    get_vault_path,
    vault_state
)

from .utils import validate_password_strength, secure_delete_directory

def vault_unlocked_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not vault_state.is_unlocked():
            click.echo("Error: Ark is locked. Please unlock the ark first.")
            return
        return f(*args, **kwargs)
    return decorated_function

@click.group()
def cli():
    """Local Ark CLI - Secure storage for sensitive information"""
    pass

@cli.command()
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def init(password):
    """Initialize the ark"""
    if is_vault_initialized():
        click.echo("Error: Ark is already initialized.")
        return

    if not validate_password_strength(password):
        click.echo("Error: Password does not meet the requirements.")
        click.echo("Password must be at least 12 characters long and contain:")
        click.echo("- At least one uppercase letter")
        click.echo("- At least one lowercase letter")
        click.echo("- At least one number")
        click.echo("- At least one special character")
        return
    
    hashed_password = hash_password(password)
    encryption_key = generate_encryption_key()
    
    if initialize_vault(hashed_password, encryption_key):
        click.echo("Ark initialized successfully.")
        click.echo(f"Ark location: {get_vault_path()}")
    else:
        click.echo("Error: Failed to initialize ark.")

@cli.command()
def lock():
    """Lock the ark"""
    vault_state.lock()
    click.echo("Ark locked.")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
def unlock(password):
    """Unlock the ark"""
    if not is_vault_initialized():
        click.echo("Error: Ark is not initialized. Please run 'init' command first.")
        return

    stored_password = retrieve_user_password()
    if verify_password(stored_password, password):
        vault_state.unlock()
        click.echo("Ark unlocked successfully.")
    else:
        click.echo("Error: Incorrect password.")


@cli.command()
@vault_unlocked_required
@click.argument('key')
@click.argument('value')
def add(key, value):
    """Add a key-value pair to the ark"""
    if store_encrypted_data(key, value):
        click.echo(f"Added '{key}' to the ark.")
    else:
        click.echo(f"Error: Failed to add '{key}' to the ark.")

@cli.command()
@vault_unlocked_required
@click.argument('key')
def get(key):
    """Retrieve a value from the ark and copy to clipboard"""
    value = retrieve_encrypted_data(key)
    if value:
        import pyperclip
        pyperclip.copy(value)
        click.echo(f"Value for '{key}' copied to clipboard.")
    else:
        click.echo(f"Error: No value found for '{key}'.")

@cli.command()
@vault_unlocked_required
def list():
    """List all keys stored in the ark"""
    items = list_vault_items()
    if items:
        click.echo("Stored items:")
        for item in items:
            click.echo(f"- {item}")
    else:
        click.echo("The ark is empty.")

@cli.command()
@vault_unlocked_required
@click.argument('key')
@click.option('--force', is_flag=True, help="Force deletion without confirmation")
def delete(key, force):
    """Delete a key-value pair from the ark"""
    if not force:
        if not click.confirm(f"Are you sure you want to delete '{key}'?"):
            click.echo("Deletion cancelled.")
            return
    
    if delete_vault_item(key):
        click.echo(f"Deleted '{key}' from the ark.")
    else:
        click.echo(f"Error: Failed to delete '{key}' from the ark.")

@cli.command()
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def change_password(password):
    """Change the ark password"""
    if not is_vault_initialized():
        click.echo("Error: Ark is not initialized. Please run 'init' command first.")
        return

    if not validate_password_strength(password):
        click.echo("Error: New password does not meet the requirements.")
        return

    hashed_password = hash_password(password)
    if store_encrypted_data('password.bin', hashed_password):
        click.echo("Password changed successfully.")
    else:
        click.echo("Error: Failed to change password.")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
@click.option('--force', is_flag=True, help="Force deletion without confirmation")
def destroy(password, force):
    """Destroy the ark and all its contents"""
    if not is_vault_initialized():
        click.echo("Error: Ark is not initialized.")
        return

    # Verify the password
    stored_password = retrieve_user_password()
    if not verify_password(stored_password, password):
        click.echo("Error: Incorrect password. Ark destruction cancelled.")
        return

    if not force:
        if not click.confirm("Are you sure you want to destroy the ark? This action cannot be undone."):
            click.echo("Ark destruction cancelled.")
            return

    vault_path = get_vault_path()
    try:
        secure_delete_directory(vault_path)
        click.echo("Ark destroyed successfully.")
    except Exception as e:
        click.echo(f"Error: Failed to destroy ark. {str(e)}")

if __name__ == '__main__':
    cli()
