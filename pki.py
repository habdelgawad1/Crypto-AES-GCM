"""Shared helpers: RSA signatures, certificates, Diffie-Hellman + HKDF, JSON files, socket framing.
Only Python's standard hashlib (SHA-256), hmac, secrets (random numbers) and time are used."""
import hashlib
import hmac
import json
import secrets
import struct
import time

# Diffie-Hellman group: the 2048-bit safe prime from RFC 3526 (group 14), generator 2.
DH_PRIME = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05"
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb"
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b"
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718"
    "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff", 16)
DH_GENERATOR = 2


def sha256(data):
    return hashlib.sha256(data).digest()


# ------------------------------------------------------------------ HKDF (RFC 5869)
def hkdf_sha256(secret, salt, info):
    """Turn a raw secret into a 32-byte key. (Expand step needs only one block for 32 bytes.)"""
    pseudo_random_key = hmac.new(salt, secret, hashlib.sha256).digest()              # extract
    return hmac.new(pseudo_random_key, info + b"\x01", hashlib.sha256).digest()       # expand


# ------------------------------------------------------------------ RSA
def is_prime(number, rounds=32):
    """Miller-Rabin primality test."""
    if number % 2 == 0:
        return number == 2
    odd_part, power_of_two = number - 1, 0
    while odd_part % 2 == 0:
        odd_part, power_of_two = odd_part // 2, power_of_two + 1
    for _ in range(rounds):
        x = pow(2 + secrets.randbelow(number - 3), odd_part, number)
        if x in (1, number - 1):
            continue
        for _ in range(power_of_two - 1):
            x = x * x % number
            if x == number - 1:
                break
        else:
            return False            # this witness proves the number is composite
    return True


def generate_prime(bits):
    while True:
        # force the top two bits (so p*q has full length) and the lowest bit (so it is odd)
        candidate = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if is_prime(candidate):
            return candidate


def generate_rsa_keypair(bits=2048, public_exponent=65537):
    """Returns (n, e, d): public key = (n, e), private key = (n, d)."""
    while True:
        p, q = generate_prime(bits // 2), generate_prime(bits // 2)
        phi = (p - 1) * (q - 1)
        if p != q and phi % public_exponent != 0:
            return p * q, public_exponent, pow(public_exponent, -1, phi)


# Fixed prefix that says "this is a SHA-256 hash" (part of the PKCS#1 v1.5 standard).
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def pkcs1_encode(message, n):
    """PKCS#1 v1.5 signature padding: 00 01 FF..FF 00 || DigestInfo || SHA-256(message)."""
    key_length = (n.bit_length() + 7) // 8
    digest_info = SHA256_DIGEST_INFO + sha256(message)
    padding = b"\xff" * (key_length - len(digest_info) - 3)
    return int.from_bytes(b"\x00\x01" + padding + b"\x00" + digest_info, "big")


def rsa_sign(message, n, private_exponent):
    """signature = padded_hash^d mod n   (only the private key owner can compute this)."""
    return pow(pkcs1_encode(message, n), private_exponent, n)


def rsa_verify(message, signature, n, public_exponent):
    """Valid if signature^e mod n gives back the padded hash   (anyone can check this)."""
    return 0 <= signature < n and pow(signature, public_exponent, n) == pkcs1_encode(message, n)


# ------------------------------------------------------------------ certificates
# A certificate = name + public key + usage + validity period, signed by an issuer (the CA).
def certificate_bytes(certificate):
    """The exact bytes the issuer signs (every field except the signature itself)."""
    fields = {key: value for key, value in certificate.items() if key != "signature"}
    return json.dumps(fields, sort_keys=True).encode()


def create_certificate(name, n, e, usage, issuer_name, issuer_n, issuer_private_exponent,
                       valid_days=365):
    now = int(time.time())
    certificate = {"name": name, "n": n, "e": e, "usage": usage, "issuer": issuer_name,
                   "not_before": now, "not_after": now + valid_days * 86400}
    certificate["signature"] = rsa_sign(certificate_bytes(certificate), issuer_n,
                                        issuer_private_exponent)
    return certificate


def check_certificate(certificate, issuer, expected_usage, expected_name=None):
    """Raises ValueError (with the reason) unless the certificate is genuine and fit for use."""
    if certificate["issuer"] != issuer["name"] or not rsa_verify(
            certificate_bytes(certificate), certificate["signature"], issuer["n"], issuer["e"]):
        raise ValueError("certificate NOT signed by the trusted CA")
    if not certificate["not_before"] <= time.time() <= certificate["not_after"]:
        raise ValueError("certificate expired or not yet valid")
    if certificate["usage"] != expected_usage:
        raise ValueError(f"certificate is not meant for '{expected_usage}'")
    if expected_name is not None and certificate["name"] != expected_name:
        raise ValueError(f"certificate name '{certificate['name']}' is not '{expected_name}'")


# ------------------------------------------------------------------ Diffie-Hellman
def handshake_transcript(server_name, client_dh_public, server_dh_public):
    """Everything agreed in the handshake. The server signs it; both sides feed it into the key."""
    return json.dumps({"protocol": "LEG-BANK-M3", "dh_group": "RFC3526-group14",
                       "cipher": "AES-256-GCM", "server": server_name,
                       "client_dh": client_dh_public, "server_dh": server_dh_public},
                      sort_keys=True).encode()


def dh_generate_keypair():
    """New random private value x and public value g^x mod p (call once per session)."""
    private_value = secrets.randbelow(DH_PRIME - 3) + 2
    return private_value, pow(DH_GENERATOR, private_value, DH_PRIME)


def dh_derive_session_key(my_private_value, peer_public_value, transcript):
    """shared secret = peer_public^my_private mod p, then HKDF -> 32-byte AES-256 key."""
    if not 2 <= peer_public_value <= DH_PRIME - 2:      # reject trivial/invalid public values
        raise ValueError("invalid DH public value")
    shared_secret = pow(peer_public_value, my_private_value, DH_PRIME)
    return hkdf_sha256(shared_secret.to_bytes(256, "big"), salt=sha256(transcript),
                       info=b"AES-256-GCM session key")


def key_fingerprint(session_key):
    """Short value to print on both sides to show they derived the same key (without leaking it)."""
    return sha256(b"fingerprint" + session_key).hex()[:16].upper()


# ------------------------------------------------------------------ session policy
MAX_MESSAGES_PER_KEY = 3    # rotate the session key after this many messages (use more in production)
TYPE_REKEY = b"R"           # a frame starting with "R" begins a new DH handshake (key rotation).
                            # Data frames start with their nonce, whose first byte is always 0x00.


# ------------------------------------------------------------------ files
def load_json(path):
    with open(path) as file:
        return json.load(file)


def save_json(path, data):
    with open(path, "w") as file:
        json.dump(data, file)


# ------------------------------------------------------------------ socket framing
# TCP is a byte stream, so every message is sent as: 4-byte length + data.
MAX_FRAME_SIZE = 65536


def send_frame(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def receive_exactly(sock, size):
    """recv() may return fewer bytes than asked, so loop until we have all of them."""
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("peer closed connection")
        data += part
    return data


def receive_frame(sock):
    size = struct.unpack(">I", receive_exactly(sock, 4))[0]
    if size > MAX_FRAME_SIZE:
        raise ValueError("frame too large")
    return receive_exactly(sock, size)
