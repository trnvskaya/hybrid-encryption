# File Encryption/Decryption Tool

A C++ implementation of hybrid encryption using OpenSSL for secure file encryption and decryption with public/private key pairs.

## Overview
This tool implements hybrid encryption by combining symmetric and asymmetric cryptography. It uses RSA public key encryption to secure a randomly generated symmetric key, which is then used to encrypt the actual file data with a specified symmetric cipher.

## Key Features
- **Hybrid Encryption**: Combines RSA public key encryption with symmetric ciphers for optimal security and performance
- **Multiple Cipher Support**: Supports various symmetric ciphers (AES-128-CBC, AES-256-CBC, etc.)
- **Secure Key Management**: Encrypts symmetric keys using RSA public keys
- **Memory Efficient**: Processes files in chunks to handle large files without excessive memory usage
- **Error Handling**: Comprehensive error checking for file operations, key validation, and cryptographic operations

## Functions

### `seal()`
Encrypts a file using hybrid encryption:
- Generates a random symmetric key and IV
- Encrypts the file data with the symmetric cipher
- Encrypts the symmetric key with the RSA public key
- Stores cipher info, encrypted key, IV, and encrypted data in output file

### `open()`
Decrypts a previously sealed file:
- Reads cipher information and encrypted symmetric key from file
- Decrypts the symmetric key using the RSA private key
- Decrypts the file data using the recovered symmetric key
- Outputs the original plaintext

## File Format
The encrypted file contains:
- Cipher NID (identifies the symmetric cipher used)
- Encrypted key length
- Encrypted symmetric key
- Initialization Vector (IV) if required by cipher
- Encrypted file data

## Usage
```cpp
// Encrypt a file
int result = seal("input.txt", "encrypted.bin", "public_key.pem", "aes-128-cbc");

// Decrypt a file
int result = open("encrypted.bin", "decrypted.txt", "private_key.pem");
```

## Dependencies
- OpenSSL library (EVP, PEM, RAND modules)
- RSA key pair in PEM format

## Error Handling
- File I/O errors
- Invalid key formats
- Unsupported cipher algorithms
- Memory allocation failures
- Cryptographic operation failures

The tool ensures secure file encryption suitable for protecting sensitive data with strong cryptographic guarantees.
