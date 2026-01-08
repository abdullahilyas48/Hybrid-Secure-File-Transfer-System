# socket_sender.py
import argparse
import socket
from net_utils import send_blob
from crypto_utils import (
    encrypt_file_bytes, rsa_encrypt_key,
    sha256_hash
)


def main(ip, port, pubkey_path, file_path):
    print("Reading public key...")
    with open(pubkey_path, "rb") as f:
        public_pem = f.read()

    print("Reading file to encrypt...")
    with open(file_path, "rb") as f:
        plaintext = f.read()

    print("Encrypting with AES-256...")
    ciphertext, aes_key, iv = encrypt_file_bytes(plaintext)

    print("Encrypting AES key with receiver RSA public key...")
    enc_key = rsa_encrypt_key(aes_key, public_pem)

    print("Computing SHA-256 hash of original file...")
    file_hash_hex = sha256_hash(plaintext)
    file_hash_bytes = file_hash_hex.encode("utf-8")

    print("Connecting to receiver:", ip, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    print("Connected.")

    print("Sending encrypted AES key...")
    send_blob(sock, enc_key)

    print("Sending IV...")
    send_blob(sock, iv)

    print("Sending hash...")
    send_blob(sock, file_hash_bytes)

    print("Sending ciphertext...")
    send_blob(sock, ciphertext)

    sock.close()
    print("Data sent successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--pubkey", required=True)
    parser.add_argument("--file", required=True)

    args = parser.parse_args()
    main(args.ip, args.port, args.pubkey, args.file)
