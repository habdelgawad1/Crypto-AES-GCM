"""Milestone 3 server.
1. Signed ephemeral Diffie-Hellman handshake (proves the server's identity, gives a fresh AES key).
2. For every message: AES-256-GCM decrypt (integrity), then verify the sender's RSA signature."""
import json
import socket
import sys

from aes_gcm import gcm_decrypt
from pki import (dh_derive_session_key, dh_generate_keypair, handshake_transcript, key_fingerprint,
                 load_json, receive_frame, rsa_sign, rsa_verify, send_frame)

HOST, PORT = "127.0.0.1", 5050

SERVER_PRIVATE_KEY = load_json("server_key.json")     # {"n", "d"}  never leaves the server
SERVER_CERTIFICATE = load_json("server_cert.json")    # public key signed by the CA
TRUSTSTORE = load_json("truststore.json")             # client id -> public key {"n", "e"}

NONCE_SIZE, TAG_SIZE = 12, 16


def do_handshake(connection):
    """Returns the 32-byte AES session key shared with the client."""
    # Client sends its ephemeral DH public value.
    client_dh_public = json.loads(receive_frame(connection))["dh"]

    # Server creates its own NEW ephemeral DH pair for this session only.
    server_dh_private, server_dh_public = dh_generate_keypair()

    # Sign the whole handshake (both DH values + protocol parameters) with the server's RSA key.
    # An attacker who swaps any value cannot produce a valid signature -> MITM is detected.
    transcript = handshake_transcript(SERVER_CERTIFICATE["name"], client_dh_public, server_dh_public)
    signature = rsa_sign(transcript, SERVER_PRIVATE_KEY["n"], SERVER_PRIVATE_KEY["d"])
    send_frame(connection, json.dumps({"certificate": SERVER_CERTIFICATE,
                                       "dh": server_dh_public,
                                       "signature": signature}).encode())

    session_key = dh_derive_session_key(server_dh_private, client_dh_public, transcript)
    del server_dh_private          # discard the ephemeral secret -> forward secrecy
    return session_key


def handle_client(connection):
    session_key = None
    try:
        session_key = do_handshake(connection)
        print(f"[server] handshake done, session key fingerprint {key_fingerprint(session_key)}")
        next_sequence_number = 0          # blocks replayed or reordered messages
        while True:
            try:
                frame = receive_frame(connection)
            except ConnectionError:
                return                    # client disconnected
            print(f"[server] received ciphertext ({len(frame)} bytes): {frame.hex().upper()}")

            # Frame layout: 12-byte nonce | AES-GCM ciphertext | 16-byte tag.
            # The nonce is the message counter, so it never repeats under one key.
            if len(frame) < NONCE_SIZE + TAG_SIZE:
                print("[server] REJECTED: frame too short")
                continue
            nonce = frame[:NONCE_SIZE]

            # Step 1: AES-GCM decrypt. Fails if ciphertext, tag OR nonce was modified.
            try:
                transaction = json.loads(gcm_decrypt(session_key, nonce, frame[NONCE_SIZE:],
                                                     associated_data=nonce))
            except ValueError as error:
                print(f"[server] REJECTED: {error}")
                continue

            if int.from_bytes(nonce, "big") != next_sequence_number:
                print("[server] REJECTED: replayed or out-of-order message")
                continue

            # Step 2: who signed it? Look the sender up in the truststore and verify the signature.
            sender_public_key = TRUSTSTORE.get(transaction["id"])
            signed_bytes = nonce + transaction["message"].encode()
            if sender_public_key is None or not rsa_verify(signed_bytes, transaction["signature"],
                                                           sender_public_key["n"],
                                                           sender_public_key["e"]):
                print(f"[server] REJECTED: unknown signatory or bad signature "
                      f"('{transaction['id']}')")
                continue

            next_sequence_number += 1
            print(f"[server] verified signatory   : {transaction['id']}")
            print(f"[server] decrypted transaction: {transaction['message']}")
    finally:
        session_key = None                # drop the session key when the session ends


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
