"""
Disk-only test for sender side of the Hybrid Secure File Transfer System.
Uses crypto_utils.py EXACT function names.

This script:
1. Reads tests/samples/example_sample.txt
2. Encrypts it with AES-256-CBC
3. Encrypts AES key using receiver_public.pem
4. Computes SHA-256 hash (hex)
5. Saves ciphertext, encrypted key, iv, hash to disk
"""

import os
from crypto_utils import (
    encrypt_file_bytes,
    rsa_encrypt_key,
    sha256_hash,
    load_public_key
)

# ----------- CONFIG -----------
PLAINTEXT_PATH = "tests/samples/example_sample.txt"
PUBLIC_KEY_PATH = "receiver_public.pem"

# Changed output filenames to match receiver_disk_test.py expectations
OUT_CIPHERTEXT = "received_decrypted_cipher.bin"
OUT_ENC_KEY = "received_decrypted_enc_key.bin"
OUT_IV = "received_decrypted_iv.bin"
OUT_HASH = "received_decrypted_hash.txt"
# ------------------------------

# Step 1: Read plaintext file
if not os.path.exists(PLAINTEXT_PATH):
    raise FileNotFoundError(f"Sample file not found: {PLAINTEXT_PATH}")

with open(PLAINTEXT_PATH, "rb") as f:
    plaintext = f.read()

print("[1] Loaded sample file")

# Step 2: AES encrypt (from crypto_utils.py)
ciphertext, aes_key, iv = encrypt_file_bytes(plaintext)
print("[2] AES encryption successful")

# Step 3: RSA encrypt AES key
public_pem = load_public_key(PUBLIC_KEY_PATH)
encrypted_aes_key = rsa_encrypt_key(aes_key, public_pem)
print("[3] AES key RSA-encrypted")

# Step 4: SHA-256 hash (hex string)
file_hash_hex = sha256_hash(plaintext)
print("[4] SHA-256 hash computed:", file_hash_hex)

# Step 5: Write outputs (matching receiver filenames)
with open(OUT_CIPHERTEXT, "wb") as f:
    f.write(ciphertext)

with open(OUT_ENC_KEY, "wb") as f:
    f.write(encrypted_aes_key)

with open(OUT_IV, "wb") as f:
    f.write(iv)

with open(OUT_HASH, "w") as f:
    f.write(file_hash_hex)

print("\n--- SUCCESS ---")
print("Generated files:")
print(f"  {OUT_CIPHERTEXT}")
print(f"  {OUT_ENC_KEY}")
print(f"  {OUT_IV}")
print(f"  {OUT_HASH}")
