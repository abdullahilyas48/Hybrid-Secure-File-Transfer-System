# receiver_disk_test.py

from crypto_utils import decrypt_file_bytes, rsa_decrypt_key, load_private_key, sha256_hash

PRIVATE_PEM = "receiver_private.pem"
ENC_KEY_FILE = "received_decrypted_enc_key.bin"
IV_FILE = "received_decrypted_iv.bin"
HASH_FILE = "received_decrypted_hash.txt"
CIPHERTEXT_FILE = "received_decrypted_cipher.bin"
OUTPUT_FILE = "decrypted_example_sample.txt"

# Load encrypted AES key
with open(ENC_KEY_FILE, "rb") as f:
    encrypted_key = f.read()

# Load IV
with open(IV_FILE, "rb") as f:
    iv = f.read()

# Load original hash
with open(HASH_FILE, "rb") as f:
    original_hash = f.read().decode().strip()  # decode bytes to string

# Load ciphertext
with open(CIPHERTEXT_FILE, "rb") as f:
    ciphertext = f.read()

# Load private key
private_key = load_private_key(PRIVATE_PEM)

# Decrypt AES key
aes_key = rsa_decrypt_key(encrypted_key, private_key)

# Decrypt ciphertext
plaintext = decrypt_file_bytes(ciphertext, aes_key, iv)

# Verify hash
recovered_hash = sha256_hash(plaintext)
if recovered_hash == original_hash:
    print("SHA-256 hash verified: OK")
else:
    print("Hash mismatch! Integrity check failed.")

# Write decrypted file
with open(OUTPUT_FILE, "wb") as f:
    f.write(plaintext)

print(f"Decrypted file saved: {OUTPUT_FILE}")
