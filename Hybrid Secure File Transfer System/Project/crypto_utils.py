# crypto_utils.py
"""
Crypto utilities for Hybrid Secure File Transfer System.

Provides:
- AES-256-CBC encrypt/decrypt for arbitrary byte buffers
- RSA-OAEP encrypt/decrypt for AES key exchange
- SHA-256 hashing helper
- RSA keypair generation and simple PEM load/save helpers

Dependencies:
    pip install pycryptodome
"""

from typing import Tuple
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

# Constants
AES_KEY_SIZE = 32   # 256 bits
IV_SIZE = 16        # AES block size (128 bits)
RSA_KEY_SIZE = 2048

# -------------------------
# Key generation / loading
# -------------------------
def generate_rsa_keypair(key_size: int = RSA_KEY_SIZE) -> Tuple[bytes, bytes]:
    """
    Generate an RSA key pair.

    Args:
        key_size: RSA key size in bits (default 2048).

    Returns:
        (private_pem_bytes, public_pem_bytes)
    """
    key = RSA.generate(key_size)
    private_pem = key.export_key(format='PEM')
    public_pem = key.publickey().export_key(format='PEM')
    return private_pem, public_pem


def save_pem(private_pem: bytes, public_pem: bytes, priv_path: str, pub_path: str) -> None:
    """
    Save PEM bytes to disk.

    Args:
        private_pem: bytes of private key PEM
        public_pem: bytes of public key PEM
        priv_path: file path to write private PEM
        pub_path: file path to write public PEM
    """
    with open(priv_path, 'wb') as f:
        f.write(private_pem)
    with open(pub_path, 'wb') as f:
        f.write(public_pem)


def load_public_key(pem_path: str) -> bytes:
    """
    Load and return public key PEM bytes from file.

    Args:
        pem_path: path to public PEM file.

    Returns:
        bytes of PEM file.
    """
    if not os.path.exists(pem_path):
        raise FileNotFoundError(f"Public key file not found: {pem_path}")
    with open(pem_path, 'rb') as f:
        return f.read()


def load_private_key(pem_path: str) -> bytes:
    """
    Load and return private key PEM bytes from file.

    Args:
        pem_path: path to private PEM file.

    Returns:
        bytes of PEM file.
    """
    if not os.path.exists(pem_path):
        raise FileNotFoundError(f"Private key file not found: {pem_path}")
    with open(pem_path, 'rb') as f:
        return f.read()

# -------------------------
# AES helpers
# -------------------------
def generate_aes_key() -> bytes:
    """
    Return a cryptographically secure random AES key (32 bytes / 256 bits).
    """
    return get_random_bytes(AES_KEY_SIZE)


def encrypt_file_bytes(plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext bytes using AES-256-CBC.

    Args:
        plaintext: raw bytes to encrypt

    Returns:
        (ciphertext_bytes, aes_key_bytes, iv_bytes)
    """
    aes_key = generate_aes_key()
    iv = get_random_bytes(IV_SIZE)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext, aes_key, iv


def decrypt_file_bytes(ciphertext: bytes, aes_key: bytes, iv: bytes) -> bytes:
    """
    Decrypt AES-CBC ciphertext bytes.

    Args:
        ciphertext: bytes encrypted via encrypt_file_bytes
        aes_key: AES key bytes returned by encrypt_file_bytes
        iv: initialization vector bytes returned by encrypt_file_bytes

    Returns:
        plaintext bytes

    Raises:
        ValueError on padding error or invalid key/iv.
    """
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# -------------------------
# RSA helpers (encrypt AES key)
# -------------------------
def rsa_encrypt_key(aes_key: bytes, receiver_public_pem: bytes) -> bytes:
    """
    Encrypt an AES key with receiver's RSA public key (OAEP).

    Args:
        aes_key: raw AES key bytes (32 bytes)
        receiver_public_pem: PEM bytes for receiver public key

    Returns:
        encrypted AES key bytes
    """
    rsa_key = RSA.import_key(receiver_public_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    return rsa_cipher.encrypt(aes_key)


def rsa_decrypt_key(encrypted_aes_key: bytes, receiver_private_pem: bytes) -> bytes:
    """
    Decrypt an encrypted AES key using RSA private PEM.

    Args:
        encrypted_aes_key: encrypted AES key bytes
        receiver_private_pem: PEM bytes containing private key

    Returns:
        original AES key bytes
    """
    rsa_key = RSA.import_key(receiver_private_pem)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    return rsa_cipher.decrypt(encrypted_aes_key)

# -------------------------
# Hash helpers
# -------------------------
def sha256_hash(data: bytes) -> str:
    """
    Compute SHA-256 hash of data and return hexadecimal string.

    Args:
        data: bytes to hash

    Returns:
        hex string of SHA-256 digest
    """
    return hashlib.sha256(data).hexdigest()


# -------------------------
# Convenience disk helpers
# -------------------------
def encrypt_file_on_disk(input_path: str) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Convenience: read file from disk, encrypt it and compute hash.

    Args:
        input_path: path to file to encrypt

    Returns:
        (ciphertext, aes_key, iv, file_hash_bytes)
    """
    with open(input_path, 'rb') as f:
        data = f.read()
    ciphertext, aes_key, iv = encrypt_file_bytes(data)
    file_hash = sha256_hash(data).encode('utf-8')
    return ciphertext, aes_key, iv, file_hash


def decrypt_file_to_disk(output_path: str, ciphertext: bytes, aes_key: bytes, iv: bytes) -> None:
    """
    Decrypt ciphertext and write plaintext to a file.

    Args:
        output_path: path where decrypted data will be written
        ciphertext: encrypted bytes
        aes_key: AES key bytes
        iv: IV bytes
    """
    plaintext = decrypt_file_bytes(ciphertext, aes_key, iv)
    with open(output_path, 'wb') as f:
        f.write(plaintext)
