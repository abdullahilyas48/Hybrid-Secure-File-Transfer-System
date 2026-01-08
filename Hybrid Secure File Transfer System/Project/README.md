# Hybrid Secure File Transfer — Cryptography Module (Member 1)

## Setup
1. Install dependencies:
pip install pycryptodome


2. Generate RSA keys (receiver only):
python keygen.py
This creates:
- receiver_private.pem  (KEEP SECRET)
- receiver_public.pem   (GIVE TO SENDER)


3. Run crypto tests:
python tests/test_crypto_roundtrip.py


4. Run demo example:
python example_usage.py

5. Sender terminal (Member 2)
python socket_sender.py --ip 127.0.0.1 --port 5001 --pubkey receiver_public.pem --file tests/samples/example_sample.txt

6. Receiver terminal
python socket_receiver.py --port 5001 --privkey receiver_private.pem

7. python receiver_disk_test.py (Member 3)

## Public API (functions you can import)
- encrypt_file_bytes(plaintext_bytes) → (ciphertext, aes_key, iv)
- decrypt_file_bytes(ciphertext, aes_key, iv) → plaintext
- rsa_encrypt_key(aes_key, public_pem) → encrypted AES key
- rsa_decrypt_key(encrypted_key, private_pem) → original AES key
- sha256_hash(data_bytes) → hex hash string

## Packet order (network layer must follow this)
When sending over socket, send data in EXACT order:
1. Encrypted AES key  
2. IV  
3. Original SHA-256 hash (UTF-8 encoded)  
4. Ciphertext  






## Commands in order:
1. python3 sender_disk_test.py (terminal 1)

2. python3 socket_receiver.py --port 5001 --privkey receiver_private.pem (terminal 2)

3. python3 gui.py (terminal 1)

4. In GUI, browse example_sample.txt & select it.

5. python3 receiver_disk_test.py (terminal 2)