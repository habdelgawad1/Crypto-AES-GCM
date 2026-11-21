"""Milestone 3 client.
1. Verifies the server via PKI (CA-signed certificate + signed DH value), then derives the AES key.
2. Signs every transaction with its own RSA private key and sends it encrypted with AES-256-GCM."""
import json
import socket

from aes_gcm import gcm_encrypt
from pki import (dh_derive_session_key, dh_generate_keypair, load_json, receive_frame,
                 rsa_sign, rsa_verify, send_frame, verify_certificate)

HOST, PORT = "127.0.0.1", 5050

CA_ROOT = load_json("ca_root.json")                 # pre-trusted CA public key
CLIENT_PRIVATE_KEY = load_json("client_key.json")   # {"id", "n", "d"}  never leaves the client


def do_handshake(connection):
    """Returns the 32-byte AES session key, or exits if the server cannot be authenticated."""
    # New ephemeral DH pair for this session only.
    client_dh_private, client_dh_public = dh_generate_keypair()
    send_frame(connection, json.dumps({"dh": client_dh_public}).encode())

    reply = json.loads(receive_frame(connection))
    certificate, server_dh_public = reply["certificate"], reply["dh"]

    # Check 1: is the server's certificate signed by the CA we trust?
    if not verify_certificate(certificate, CA_ROOT):
        raise SystemExit("server certificate NOT signed by trusted CA")

    # Check 2: did that certified server sign THIS exact DH exchange? (stops a man-in-the-middle)
    signed_bytes = f"{client_dh_public},{server_dh_public}".encode()
    if not rsa_verify(signed_bytes, reply["signature"], certificate["n"], certificate["e"]):
        raise SystemExit("server DH signature INVALID (possible MITM)")

    print(f"[client] server '{certificate['name']}' authenticated")
    # Only derive the key after both checks passed.
    return dh_derive_session_key(client_dh_private, server_dh_public)


def main():
    with socket.create_connection((HOST, PORT)) as connection:
        session_key = do_handshake(connection)
        print("[client] enter a message, or press Ctrl+C/Ctrl+D to exit")

        sequence_number = 0               # increases with every message (stops replays)
        try:
            while True:
                message = input("[client] message> ")
                if not message:
                    continue

                sequence_bytes = sequence_number.to_bytes(8, "big")

                # Sign (sequence number + message) with OUR private key: proves who sent it.
                signature = rsa_sign(sequence_bytes + message.encode(),
                                     CLIENT_PRIVATE_KEY["n"], CLIENT_PRIVATE_KEY["d"])
                transaction = json.dumps({"id": CLIENT_PRIVATE_KEY["id"],
                                          "message": message,
                                          "signature": signature}).encode()

                # Encrypt with AES-256-GCM. The nonce is built from the sequence number so it never
                # repeats; the sequence number is also authenticated (associated data).
                nonce = bytes(4) + sequence_bytes
                frame = sequence_bytes + gcm_encrypt(session_key, nonce, transaction,
                                                     associated_data=sequence_bytes)
                print(f"[client] plaintext  : {message}")
                print(f"[client] ciphertext : {frame.hex().upper()} ({len(frame)} bytes)")
                send_frame(connection, frame)
                sequence_number += 1
        except (EOFError, KeyboardInterrupt):
            print("\n[client] disconnected")


if __name__ == "__main__":
    main()
