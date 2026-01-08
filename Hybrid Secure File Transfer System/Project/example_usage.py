# example_usage.py
"""
Small example showing how sender and receiver call crypto_utils.
This is for developer reference — not networked.
"""

from crypto_utils import (
    generate_rsa_keypair, save_pem, load_public_key, load_private_key,
    encrypt_file_bytes, decrypt_file_bytes, rsa_encrypt_key, rsa_decrypt_key,
    sha256_hash
)
import os

def demo_roundtrip():
    # 1) Generate keys (receiver) - one-time
    priv_pem, pub_pem = generate_rsa_keypair()
    save_pem(priv_pem, pub_pem, "example_receiver_private.pem", "example_receiver_public.pem")
    print("Generated example receiver PEM files.")

    # 2) Sender side: read a small sample file or create one
    sample_path = "tests/samples/example_sample.txt"
    os.makedirs(os.path.dirname(sample_path), exist_ok=True)
    with open(sample_path, "wb") as f:
        f.write(b"Example data for demo.")

    plaintext = open(sample_path, "rb").read()
    print("Plaintext length:", len(plaintext))

    # 3) Sender encrypts file with AES
    ciphertext, aes_key, iv = encrypt_file_bytes(plaintext)
    print("Ciphertext length:", len(ciphertext))

    # 4) Sender computes hash and encrypts AES key with receiver public key
    file_hash = sha256_hash(plaintext)
    encrypted_aes_key = rsa_encrypt_key(aes_key, pub_pem)
    print("Encrypted AES key length:", len(encrypted_aes_key))

    # 5) Receiver decrypts AES key and then the file
    decrypted_aes_key = rsa_decrypt_key(encrypted_aes_key, priv_pem)
    recovered_plaintext = decrypt_file_bytes(ciphertext, decrypted_aes_key, iv)

    # 6) Verify integrity
    recovered_hash = sha256_hash(recovered_plaintext)
    print("Original hash :", file_hash)
    print("Recovered hash:", recovered_hash)
    assert recovered_hash == file_hash
    print("Roundtrip OK — plaintext recovered and hash matches.")

if __name__ == "__main__":
    demo_roundtrip()
