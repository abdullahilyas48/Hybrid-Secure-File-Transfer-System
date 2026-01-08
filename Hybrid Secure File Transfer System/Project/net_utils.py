# net_utils.py
import struct
import socket

def send_blob(sock: socket.socket, data: bytes):
    length = len(data)
    sock.sendall(struct.pack(">I", length))
    sock.sendall(data)


def recv_n(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("Socket closed unexpectedly during recv_n")
        buf += chunk
    return buf


def recv_blob(sock: socket.socket) -> bytes:
    header = recv_n(sock, 4)      # 4-byte big-endian length
    (length,) = struct.unpack(">I", header)
    return recv_n(sock, length)
