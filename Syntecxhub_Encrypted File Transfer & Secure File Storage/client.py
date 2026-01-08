import socket
import ssl
import os
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4443
CHUNK_SIZE = 1024 * 1024

def send_file(file_path):
    key = get_random_bytes(32)
    iv = get_random_bytes(16)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=SERVER_HOST) as conn:
            filename = os.path.basename(file_path)

            conn.sendall(key)
            conn.sendall(iv)

            conn.sendall(struct.pack(">I", len(filename)))
            conn.sendall(filename.encode())

            cipher = AES.new(key, AES.MODE_CBC, iv)

            with open(file_path, "rb") as f:
                while chunk := f.read(CHUNK_SIZE):
                    pad = 16 - len(chunk) % 16
                    chunk += bytes([pad]) * pad

                    encrypted = cipher.encrypt(chunk)
                    hmac = HMAC.new(key, encrypted, SHA256).digest()

                    conn.sendall(struct.pack(">I", len(encrypted)))
                    conn.sendall(encrypted)
                    conn.sendall(hmac)

            conn.sendall(struct.pack(">I", 0))
            print("[+] File sent securely")

if __name__ == "__main__":
    path = input("Enter file path: ")
    send_file(path)
