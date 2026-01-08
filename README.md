# Hybrid Secure File Transfer System

## Table of Contents
1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Tech Stack](#tech-stack)
4. [Architecture](#architecture)
5. [Installation](#installation)
6. [Setup](#setup)
7. [Usage](#usage)
8. [API Reference](#api-reference)
9. [Testing](#testing)
10. [Security Notes](#security-notes)
11. [Contributing](#contributing)
12. [License](#license)
13. [Authors](#authors)
14. [Acknowledgments](#acknowledgments)

    
## Overview

A secure file transfer application that combines symmetric (AES) and asymmetric (RSA) cryptography to ensure confidentiality, integrity, and secure key exchange over network sockets.

---
## Key Features

- **Confidential File Access**: Only the intended receiver can decrypt the transmitted file using their RSA-2048 private key.

- **Hybrid Encryption**: Uses AES-256 for fast file encryption and RSA-2048 to securely encrypt and exchange the AES key.

- **Integrity Verification**: Computes a SHA-256 hash of the original file to ensure contents cannot be modified without detection.

- **Secure Key Protection**: Protects the AES key by encrypting it with the receiver’s RSA public key before transmission.

- **Network Transfer**: Transmits all encrypted components (encrypted AES key, IV, ciphertext, and hash) over a TCP socket.

- **Receiver-Side Reconstruction**: Reconstructs and decrypts the file on the receiver’s side using the decrypted AES key and IV.

- **File Validation**: Verifies that the received file is identical to the original by comparing SHA-256 hashes.

- **Key Management**: Automated RSA key pair generation for secure sender–receiver communication.

- **Testing Suite**: Comprehensive tests for cryptographic operations and end-to-end roundtrip verification.
---

## Tech Stack
- Language: Python 3.9.x
- Cryptography: AES-256 (CBC), RSA-2048, SHA-256
- Networking: TCP sockets (Python `socket`)
- GUI: Tkinter
- Key Management: PEM key files (public/private)
- Testing: Python test scripts (crypto + end-to-end transfer)
---

## Architecture

The system implements a hybrid cryptosystem:

1. **Sender Side**:
   - Generates AES key and IV for file encryption
   - Encrypts the file using AES
   - Computes SHA-256 hash of original file
   - Encrypts AES key with receiver's RSA public key
   - Sends encrypted key, IV, hash, and ciphertext over socket

2. **Receiver Side**:
   - Receives encrypted data packets
   - Decrypts AES key using RSA private key
   - Decrypts file using AES key and IV
   - Verifies integrity by comparing hashes
---
## Installation

### Prerequisites and Usage Notes
- Python 3.9.x
- pip for package management
- Split terminals for sender and receiver
- Virtual environment (optional but recommended to use)
- Write sender side message in file "example_sample.txt" if not using GUI
- Stored message in "decrypted_example_sample.txt" will be changed automatically after successful transfer and decryption.
 

### Dependencies
```bash
pip install pycryptodome
```

## Setup
1. **Clone the repository and navigate inside the folder**:
   ```bash
   cd Hybrid-Secure-File-Transfer-System
   ```

2. **Navigate to the Project directory**:
   ```bash
   cd Project
   ```

3. **Generate RSA keys (Receiver only)**:
   ```bash
   python keygen.py
   ```
   This creates `receiver_private.pem` (keep secret) and `receiver_public.pem` (share with sender).

4. **Run tests to verify setup**:
   ```bash
   python tests/test_crypto_roundtrip.py
   ```

## Usage

### Command Line Interface

#### Sender
1. cd Hybrid Secure File Transfer System 

Example:
```bash
python socket_sender.py --ip 127.0.0.1 --port 5001 --pubkey receiver_public.pem --file tests/samples/example_sample.txt
```

#### Receiver
```bash
python socket_receiver.py --port <port> --privkey <receiver_private.pem>
```

Example:
```bash
python socket_receiver.py --port 5001 --privkey receiver_private.pem
```

### Graphical User Interface

1. Start the receiver:
   ```bash
   python socket_receiver.py --port 5001 --privkey receiver_private.pem
   ```

2. Launch the GUI:
   ```bash
   python gui.py
   ```

3. In the GUI:
   - Browse and select a file
   - Enter receiver IP and port (defaults provided)
   - Specify receiver's public key path
   - Click Send

### Demo

Run the example usage script to see a local roundtrip demonstration:
```bash
python example_usage.py
```

## API Reference

The `crypto_utils.py` module provides the following functions:

- `generate_rsa_keypair()` → `(private_pem_bytes, public_pem_bytes)`
- `save_pem(private_pem, public_pem, priv_path, pub_path)`
- `load_public_key(pem_path)` → `RSAPublicKey`
- `load_private_key(pem_path)` → `RSAPrivateKey`
- `encrypt_file_bytes(plaintext_bytes)` → `(ciphertext, aes_key, iv)`
- `decrypt_file_bytes(ciphertext, aes_key, iv)` → `plaintext_bytes`
- `rsa_encrypt_key(aes_key, public_pem)` → `encrypted_key`
- `rsa_decrypt_key(encrypted_key, private_pem)` → `aes_key`
- `sha256_hash(data_bytes)` → `hex_string`

## Testing

Run the test suite:
```bash
python tests/test_crypto_roundtrip.py
```

Additional disk-based tests:
- Sender test: `python sender_disk_test.py`
- Receiver test: `python receiver_disk_test.py`

## Security Notes

- Keep RSA private keys secure and never share them
- The system uses AES-GCM mode for authenticated encryption
- SHA-256 ensures integrity but not authenticity (no digital signatures implemented)
- For production use, consider additional security measures like certificate validation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details

## Authors

- Muhammad Abdullah and team members

## Acknowledgments

- Built as part of an Information Security project
- Uses PyCryptodome for cryptographic operations