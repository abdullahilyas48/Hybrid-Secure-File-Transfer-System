# socket_receiver.py
import argparse
import socket
from net_utils import recv_blob


def main(listen_ip, port, privkey_path, out_basename="received_decrypted"):
    print("Starting server on", listen_ip, port)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((listen_ip, port))
    server.listen(1)

    print("Waiting for incoming connection...")
    conn, addr = server.accept()
    print("Connection from:", addr)

    print("Receiving encrypted AES key...")
    enc_key = recv_blob(conn)

    print("Receiving IV...")
    iv = recv_blob(conn)

    print("Receiving SHA-256 hash...")
    file_hash_bytes = recv_blob(conn)

    print("Receiving ciphertext...")
    ciphertext = recv_blob(conn)

    conn.close()
    server.close()

    # Save raw data for decryption stage
    print("Writing output files...")

    with open(out_basename + "_enc_key.bin", "wb") as f:
        f.write(enc_key)

    with open(out_basename + "_iv.bin", "wb") as f:
        f.write(iv)

    with open(out_basename + "_hash.txt", "wb") as f:
        f.write(file_hash_bytes)

    with open(out_basename + "_cipher.bin", "wb") as f:
        f.write(ciphertext)

    print("All blobs saved. Ready for decryption by Member 3.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default="0.0.0.0")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--privkey", required=True)
    parser.add_argument("--out", default="received_decrypted")

    args = parser.parse_args()
    main(args.ip, args.port, args.privkey, args.out)
