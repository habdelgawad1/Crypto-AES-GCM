"""Shared helpers: RSA signatures, certificates, Diffie-Hellman, JSON files, and socket framing.
Only Python's standard hashlib (SHA-256) and secrets (random numbers) are used."""
import hashlib
import json
import secrets
import struct

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


def rsa_sign(message, n, private_exponent):
    """signature = hash(message)^d mod n   (only the private key owner can compute this)."""
    return pow(int.from_bytes(sha256(message), "big"), private_exponent, n)


def rsa_verify(message, signature, n, public_exponent):
    """Valid if signature^e mod n gives back hash(message)   (anyone can check this)."""
    return pow(signature, public_exponent, n) == int.from_bytes(sha256(message), "big")


# ------------------------------------------------------------------ certificates
def certificate_bytes(certificate):
    """The exact bytes the CA signs: owner name + public key."""
    return f"{certificate['name']},{certificate['n']},{certificate['e']}".encode()


def create_certificate(owner_name, owner_n, owner_e, ca_n, ca_private_exponent):
    """The CA signs (name, public key) -> binds the key to the name."""
    certificate = {"name": owner_name, "n": owner_n, "e": owner_e}
    certificate["signature"] = rsa_sign(certificate_bytes(certificate), ca_n, ca_private_exponent)
    return certificate


def verify_certificate(certificate, ca_root):
    """True only if this certificate was signed by the CA whose public key is `ca_root`."""
    return rsa_verify(certificate_bytes(certificate), certificate["signature"],
                      ca_root["n"], ca_root["e"])


# ------------------------------------------------------------------ Diffie-Hellman
def dh_generate_keypair():
    """New random private value x and public value g^x mod p (call once per session)."""
    private_value = secrets.randbelow(DH_PRIME - 3) + 2
    return private_value, pow(DH_GENERATOR, private_value, DH_PRIME)


def dh_derive_session_key(my_private_value, peer_public_value):
    """shared secret = peer_public^my_private mod p, hashed into a 32-byte AES-256 key."""
    if not 2 <= peer_public_value <= DH_PRIME - 2:      # reject trivial/invalid public values
        raise ValueError("invalid DH public value")
    shared_secret = pow(peer_public_value, my_private_value, DH_PRIME)
    return sha256(str(shared_secret).encode())


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
