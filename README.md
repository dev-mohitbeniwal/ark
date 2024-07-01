# Local Ark

Local Ark is a secure, command-line based password and sensitive information manager designed for developers and security-conscious users. It provides a robust, encrypted storage solution for your sensitive data, right on your local machine.

## Features

- **Strong Encryption**: Uses AES-GCM for authenticated encryption, providing both confidentiality and integrity.
- **Secure Key Management**: Implements key encryption key (KEK) for added security.
- **Password-Based Key Derivation**: Utilizes PBKDF2 with a high iteration count for deriving keys from passwords.
- **Ark Locking**: Automatically locks the ark after a period of inactivity.
- **Secure File Operations**: Implements secure deletion and permission management for ark files.
- **Backup and Restore**: Allows users to create and restore backups of their ark.
- **Key Rotation**: Supports rotating encryption keys for enhanced security.
- **Clipboard Integration**: Copies retrieved passwords to clipboard for convenience.

## Security Measures

- Implements strict access controls on ark files and directories.
- Uses constant-time comparison for password verification to prevent timing attacks.
- Securely overwrites memory to prevent sensitive data leakage.
- Disables core dumps to prevent unintended exposure of sensitive information.
- Implements integrity checks to detect tampering with ark files.
- Provides protection against concurrent access attempts.

## Installation

```bash
pip install ark
```

## Usage

## Initialize the Ark

```bash
ark init
```

###Add a new entry

```bash
ark add <key> <value>
```

### Retrieve a value

```bash
ark get <key>
```

### List all entries

```bash
ark list
```

### Delete an entry

```bash
ark delete <key>
```

### Change master password

```bash
ark change-password
```

### Create a backup

```bash
ark backup <backup_path>
```

### Restore from a backup

```bash
ark restore <backup_path>
```

### Destroy the ark

```bash
ark destroy
```

## Development

To set up the development environment:

### Clone the repository:

```bash
git clone https://github.com/yourusername/ark.git
cd ark
```

### Create a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

### Install dependencies:

```bash
pip install -r requirements.txt
```

### Run tests:

```bash
pytest
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### License

This project is licensed under the MIT License - see the LICENSE file for details.

### Disclaimer

While Local Ark implements various security measures, no system is 100% secure. Use at your own risk and always follow best practices for password management and system security.
