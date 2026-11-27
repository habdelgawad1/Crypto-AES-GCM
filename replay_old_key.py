"""Demo for the auditor: a frame recorded under an OLD session key is useless after key rotation.
Run with the server running:   python replay_old_key.py"""
import socket
import time

from client import HOST, PORT, build_data_frame, do_handshake
from pki import key_fingerprint, send_frame

with socket.create_connection((HOST, PORT)) as connection:
    old_key = do_handshake(connection)                          # session key #1
    recorded_frame = build_data_frame(old_key, 0, "SEND1500")   # a frame an attacker recorded
    send_frame(connection, recorded_frame)                      # accepted: key #1 is still valid

    new_key = do_handshake(connection, rekey=True)              # key rotation -> session key #2
    print(f"[attacker] key rotated: {key_fingerprint(old_key)} -> {key_fingerprint(new_key)}")
    print("[attacker] replaying the frame recorded under the OLD key ...")
    send_frame(connection, recorded_frame)
    time.sleep(1)                                               # let the server print its verdict
