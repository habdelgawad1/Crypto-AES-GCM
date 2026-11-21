"""Milestone 3 client.
1. Verifies the server via PKI (CA-signed certificate + signed handshake), then derives the AES key.
2. Signs every transaction with its own RSA private key and sends it encrypted with AES-256-GCM."""
import json
import socket

from aes_gcm import gcm_encrypt
from pki import (check_certificate, dh_derive_session_key, dh_generate_keypair,
                 handshake_transcript, key_fingerprint, load_json, receive_frame, rsa_sign,
                 rsa_verify, send_frame)

HOST, PORT = "127.0.0.1", 5050
EXPECTED_SERVER_NAME = "leg-bank-server"            # who we think we are talking to

CA_ROOT = load_json("ca_root.json")                 # pre-trusted CA root certificate
CLIENT_PRIVATE_KEY = load_json("client_key.json")   # {"id", "n", "d"}  never leaves the client


def do_handshake(connection):
    """Returns the 32-byte AES session key. Raises (and the session is never accepted) if the
    server cannot be authenticated."""
    # The trusted root must itself be a valid, self-signed CA certificate.
    check_certificate(CA_ROOT, CA_ROOT, expected_usage="ca")

    # New ephemeral DH pair for this session only.
    client_dh_private, client_dh_public = dh_generate_keypair()
    send_frame(connection, json.dumps({"dh": client_dh_public}).encode())

    reply = json.loads(receive_frame(connection))
    certificate, server_dh_public = reply["certificate"], reply["dh"]

    # Check 1: certificate signed by our CA, still valid, meant for servers, and for the right name?
    check_certificate(certificate, CA_ROOT, "server-auth", EXPECTED_SERVER_NAME)

    # Check 2: did that certified server sign THIS exact handshake? (stops a man-in-the-middle)
    transcript = handshake_transcript(certificate["name"], client_dh_public, server_dh_public)
    if not rsa_verify(transcript, reply["signature"], certificate["n"], certificate["e"]):
        raise ValueError("server handshake signature INVALID (possible MITM)")

    print(f"[client] server '{certificate['name']}' authenticated")
    # Only derive the key after both checks passed.
    session_key = dh_derive_session_key(client_dh_private, server_dh_public, transcript)
    del client_dh_private          # discard the ephemeral secret -> forward secrecy
    print(f"[client] session key fingerprint {key_fingerprint(session_key)}")
    return session_key


def main():
    with socket.create_connection((HOST, PORT)) as connection:
        try:
            session_key = do_handshake(connection)
        except (ValueError, KeyError, ConnectionError) as error:
            raise SystemExit(f"[client] handshake failed, connection refused: {error}")
        print("[client] enter a message, or press Ctrl+C/Ctrl+D to exit")

        sequence_number = 0               # increases with every message
        try:
            while True:
                message = input("[client] message> ")
                if not message:
                    continue

                # 12-byte nonce = message counter: unique for every message under this key.
                nonce = sequence_number.to_bytes(12, "big")

                # Sign (nonce + message) with OUR private key: proves who sent it.
                signature = rsa_sign(nonce + message.encode(),
                                     CLIENT_PRIVATE_KEY["n"], CLIENT_PRIVATE_KEY["d"])
                transaction = json.dumps({"id": CLIENT_PRIVATE_KEY["id"],
                                          "message": message,
                                          "signature": signature}).encode()

                # Encrypt with AES-256-GCM; the nonce is sent in front and is also authenticated.
                frame = nonce + gcm_encrypt(session_key, nonce, transaction, associated_data=nonce)
                print(f"[client] plaintext  : {message}")
                print(f"[client] ciphertext : {frame.hex().upper()} ({len(frame)} bytes)")
                send_frame(connection, frame)
                sequence_number += 1
        except (EOFError, KeyboardInterrupt):
            print("\n[client] disconnected")
        except ConnectionError:
            print("\n[client] server closed the connection")
        finally:
            session_key = None            # drop the session key when the session ends


if __name__ == "__main__":
    main()
