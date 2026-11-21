"""Milestone 3 server.
1. Signed ephemeral Diffie-Hellman handshake (proves the server's identity, gives a fresh AES key).
2. For every message: AES-256-GCM decrypt (integrity), then verify the sender's RSA signature."""
import json
import socket
import sys

from aes_gcm import gcm_decrypt
from pki import (dh_derive_session_key, dh_generate_keypair, load_json, receive_frame,
                 rsa_sign, rsa_verify, send_frame)

HOST, PORT = "127.0.0.1", 5050

SERVER_PRIVATE_KEY = load_json("server_key.json")     # {"n", "d"}  never leaves the server
SERVER_CERTIFICATE = load_json("server_cert.json")    # public key signed by the CA
TRUSTSTORE = load_json("truststore.json")             # client id -> public key {"n", "e"}


def do_handshake(connection):
    """Returns the 32-byte AES session key shared with the client."""
    # Client sends its ephemeral DH public value.
    client_dh_public = json.loads(receive_frame(connection))["dh"]

    # Server creates its own NEW ephemeral DH pair for this session only.
    server_dh_private, server_dh_public = dh_generate_keypair()

    # Sign both DH values with the server's RSA private key. An attacker who swaps either
    # value cannot produce a valid signature, so a man-in-the-middle is detected.
    signed_bytes = f"{client_dh_public},{server_dh_public}".encode()
    signature = rsa_sign(signed_bytes, SERVER_PRIVATE_KEY["n"], SERVER_PRIVATE_KEY["d"])
    send_frame(connection, json.dumps({"certificate": SERVER_CERTIFICATE,
                                       "dh": server_dh_public,
                                       "signature": signature}).encode())

    # The private DH value is never stored -> past sessions stay safe later (forward secrecy).
    return dh_derive_session_key(server_dh_private, client_dh_public)


def handle_client(connection):
    session_key = do_handshake(connection)
    print("[server] handshake done, session key derived")

    next_sequence_number = 0          # blocks replayed or reordered messages
    while True:
        try:
            frame = receive_frame(connection)
        except ConnectionError:
            return                    # client disconnected
        print(f"[server] received ciphertext ({len(frame)} bytes): {frame.hex().upper()}")

        # Frame layout: 8-byte sequence number | AES-GCM ciphertext | 16-byte tag
        sequence_bytes = frame[:8]
        nonce = bytes(4) + sequence_bytes             # 12 bytes, unique because the number grows

        # Step 1: AES-GCM decrypt. Fails if ciphertext OR sequence number was modified.
        try:
            transaction = json.loads(gcm_decrypt(session_key, nonce, frame[8:],
                                                 associated_data=sequence_bytes))
        except ValueError as error:
            print(f"[server] REJECTED: {error}")
            continue

        if int.from_bytes(sequence_bytes, "big") != next_sequence_number:
            print("[server] REJECTED: replayed or out-of-order message")
            continue

        # Step 2: who signed it? Look the sender up in the truststore and verify the signature.
        sender_public_key = TRUSTSTORE.get(transaction["id"])
        signed_bytes = sequence_bytes + transaction["message"].encode()
        if sender_public_key is None or not rsa_verify(signed_bytes, transaction["signature"],
                                                       sender_public_key["n"],
                                                       sender_public_key["e"]):
            print(f"[server] REJECTED: unknown signatory or bad signature ('{transaction['id']}')")
            continue

        next_sequence_number += 1
        print(f"[server] verified signatory   : {transaction['id']}")
        print(f"[server] decrypted transaction: {transaction['message']}")


def main():
    run_once = "--once" in sys.argv       # handy for demos/tests: stop after one client
    with socket.socket() as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[server] listening on {HOST}:{PORT}")
        while True:
            connection, address = server_socket.accept()
            print(f"[server] connection from {address[0]}:{address[1]}")
            try:
                handle_client(connection)
            except (ValueError, KeyError, ConnectionError) as error:
                print(f"[server] protocol error: {error}")
            connection.close()
            print("[server] connection closed")
            if run_once:
                break


if __name__ == "__main__":
    main()
