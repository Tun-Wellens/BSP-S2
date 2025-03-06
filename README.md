# AES Encryption/Decryption Tool

## Overview
This project implements AES (Advanced Encryption Standard) encryption and decryption using different modes of operation:
- **CBC (Cipher Block Chaining)**
- **CM (Counter Mode)**
- **GCM (Galois Counter Mode)** (with authentication support)

It provides a **Command Line Interface (CLI)** for encrypting and decrypting files using a password-derived key.

## Features
- Supports AES encryption and decryption.
- Three modes of operation: **CBC, CM, and GCM**.
- Secure key generation from a password using **SHA-256**.
- Automatic padding for incomplete blocks.
- GCM mode includes authentication via a TAG.

## File Structure
- `main.py` - CLI interface for encryption and decryption.
- `key.py` - Implements AES key expansion.
- `encryption.py` - Implements AES encryption functions.
- `decryption.py` - Implements AES decryption functions.
- `cbc.py` - Implements CBC mode.
- `cm.py` - Implements CM (Counter Mode).
- `gcm.py` - Implements GCM (Authenticated Encryption).

## How to Use
### 1. Running the CLI
Run the program using:
```sh
python main.py
```
You will be prompted to enter a password. This password is hashed to generate a secure 128-bit encryption key.

### 2. Available Options
Once the program starts, select one of the following options:
1. Encrypt using **CBC mode**
2. Decrypt using **CBC mode**
3. Encrypt using **CM mode**
4. Decrypt using **CM mode**
5. Encrypt using **GCM mode**
6. Decrypt using **GCM mode**
7. Exit

### 3. Encrypting a File
After selecting an encryption mode, you will be asked to provide:
- The **file path** of the file to encrypt.
- The **output path** where the encrypted file should be saved.

Example for **CBC encryption**:
```sh
Enter the path of the file you want to encrypt: input.txt
Enter the path of the output file: encrypted.bin
```

### 4. Decrypting a File
When selecting a decryption mode, provide:
- The **file path** of the encrypted file.
- The **output path** for the decrypted file.

Example for **GCM decryption**:
```sh
Enter the path of the file you want to decrypt: encrypted.bin
Enter the path of the output file: decrypted.txt
```
