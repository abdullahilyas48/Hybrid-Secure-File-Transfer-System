# tests/test_crypto_roundtrip.py
import os
import sys
sys.path.append(os.path.abspath('..'))  # so import crypto_utils works from tests folder

from crypto_utils import (
    generate_rsa_keypair, encrypt_file_bytes, rsa_encrypt_key,
    rsa_decrypt_key, decrypt_file_bytes, sha256_hash
)

def test_roundtrip_small():
    priv, pub = generate_rsa_keypair()
    plaintext = b"Hello, this is a small test!"
    ciphertext, aes_key, iv = encrypt_file_bytes(plaintext)
    enc_key = rsa_encrypt_key(aes_key, pub)
    dec_aes = rsa_decrypt_key(enc_key, priv)
    assert dec_aes == aes_key, "RSA key roundtrip failed"
    out = decrypt_file_bytes(ciphertext, dec_aes, iv)
    assert out == plaintext, "AES decrypt didn't match original"
    print("test_roundtrip_small OK")

def test_tamper_detection():
    priv, pub = generate_rsa_keypair()
    plaintext = b"Testing tamper detection."
    ciphertext, aes_key, iv = encrypt_file_bytes(plaintext)
    enc_key = rsa_encrypt_key(aes_key, pub)
    dec_aes = rsa_decrypt_key(enc_key, priv)

    # tamper a byte in ciphertext (e.g., flip a bit)
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01  # flip a single bit
    tampered = bytes(tampered)

    try:
        decrypted = decrypt_file_bytes(tampered, dec_aes, iv)
    except ValueError:
        print("test_tamper_detection OK (decryption failed as expected)")
        return

    # If decryption did not raise, compare hashes
    orig_hash = sha256_hash(plaintext)
    dec_hash = sha256_hash(decrypted)
    if dec_hash != orig_hash:
        print("test_tamper_detection OK (hash mismatch detected)")
    else:
        print("Tamper test FAILED: decrypted data matches original hash (unexpected)")


if __name__ == "__main__":
    test_roundtrip_small()
    test_tamper_detection()
