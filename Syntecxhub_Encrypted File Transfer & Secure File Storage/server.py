import socket
import ssl
import os
import struct
from Crypto.Hash import HMAC, SHA256

HOST = "0.0.0.0"
PORT = 4443
STORAGE_DIR = "storage"

os.makedirs(STORAGE_DIR, exist_ok=True)

def recv_all(conn, size):
    data = b""
    try:
        while len(data) < size:
            packet = conn.recv(size - len(data))
            if not packet:
                return None
            data += packet
        return data
    except:
        return None

def handle_client(conn):
    try:
        print("[+] Client connected")

        key = recv_all(conn, 32)
        iv = recv_all(conn, 16)

        if not key or not iv:
            print("[!] Connection closed early")
            return

        filename_len_data = recv_all(conn, 4)
        if not filename_len_data:
            return

        filename_len = struct.unpack(">I", filename_len_data)[0]
        filename = recv_all(conn, filename_len).decode()

        path = os.path.join(STORAGE_DIR, filename + ".enc")

        with open(path, "wb") as f:
            while True:
                size_data = recv_all(conn, 4)
                if not size_data:
                    break

                size = struct.unpack(">I", size_data)[0]
                if size == 0:
                    break

                encrypted_chunk = recv_all(conn, size)
                if not encrypted_chunk:
                    break

                received_hmac = recv_all(conn, 32)
                if not received_hmac:
                    break

                h = HMAC.new(key, encrypted_chunk, SHA256)
                h.verify(received_hmac)

                f.write(encrypted_chunk)

        print("[+] File stored securely")

    except Exception as e:
        print("[!] Error:", e)

    finally:
        conn.close()

def main():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("server.crt", "server.key")

    sock = socket.socket()
    sock.bind((HOST, PORT))
    sock.listen(5)

    print("[+] Secure server listening on port 4443")

    while True:
        client, addr = sock.accept()
        conn = context.wrap_socket(client, server_side=True)
        handle_client(conn)

if __name__ == "__main__":
    main()
