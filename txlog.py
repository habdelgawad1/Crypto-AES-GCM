"""Tamper-evident transaction log: a hash chain plus a signature from the server.

Each log line is one JSON entry: time, client, message, prev_hash, signature
  prev_hash = SHA-256 of the previous log LINE, so every entry is chained to the whole history.
  signature = the server's RSA signature over the entry. Someone who edits the file can recompute
              hashes, but cannot re-sign without the server's private key.
Editing, deleting, inserting or re-ordering entries breaks the chain or a signature.
Limitation: cutting entries off the END of the log leaves a valid chain (keep copies elsewhere).

Auditor check (public data only, no private key):   python txlog.py [log_file]"""
import json
import sys
import time

from pki import check_certificate, load_json, rsa_sign, rsa_verify, sha256

LOG_FILE = "transactions.log"
GENESIS_HASH = "0" * 64                    # prev_hash of the very first entry


def read_lines(path):
    try:
        with open(path) as file:
            return file.read().splitlines()
    except FileNotFoundError:
        return []


def signed_bytes(entry):
    """What the server signs: every field of the entry except the signature itself."""
    return json.dumps({k: v for k, v in entry.items() if k != "signature"}, sort_keys=True).encode()


def append_entry(path, client, message, server_n, server_d):
    """Add one transaction to the log. Returns (entry number, hash of the new line)."""
    lines = read_lines(path)
    entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
             "client": client,
             "message": message,
             "prev_hash": sha256(lines[-1].encode()).hex() if lines else GENESIS_HASH}
    entry["signature"] = rsa_sign(signed_bytes(entry), server_n, server_d)
    line = json.dumps(entry)
    with open(path, "a") as file:
        file.write(line + "\n")
    return len(lines) + 1, sha256(line.encode()).hex()


def verify_log(path, server_n, server_e):
    """Returns (good entries, problem). problem is None if the log is intact, otherwise text
    describing the first bad entry."""
    previous_hash = GENESIS_HASH
    lines = read_lines(path)
    for number, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
            chain_ok = entry["prev_hash"] == previous_hash
            signature_ok = rsa_verify(signed_bytes(entry), entry["signature"], server_n, server_e)
        except (ValueError, KeyError, TypeError):
            return number - 1, f"entry {number}: line is damaged or unreadable"
        if not chain_ok:
            return number - 1, f"entry {number}: hash chain broken (entry deleted, inserted or re-ordered)"
        if not signature_ok:
            return number - 1, f"entry {number}: server signature invalid (entry modified or forged)"
        previous_hash = sha256(line.encode()).hex()
    return len(lines), None


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else LOG_FILE
    print(f"Checked at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  file: {path}")
    # The verification key must really be the server's: its certificate has to chain to the CA.
    certificate = load_json("server_cert.json")
    try:
        check_certificate(certificate, load_json("ca_root.json"), "server-auth")
    except ValueError as error:
        raise SystemExit(f"Cannot verify: server certificate rejected ({error})")
    count, problem = verify_log(path, certificate["n"], certificate["e"])
    if problem:
        print(f"ALERT: TRANSACTION LOG TAMPERING DETECTED at {problem}")
        print(f"       {count} earlier entries verified OK. Report as an incident (NIS2 Article 23).")
        sys.exit(1)
    print(f"Log integrity OK: {count} entries, hash chain and server signatures verified")
