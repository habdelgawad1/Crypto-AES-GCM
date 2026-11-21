"""AES-256-GCM written from scratch (no crypto libraries).

AES-256  = the block cipher: turns one 16-byte block into another using a 32-byte key.
CTR mode = uses AES as a keystream generator, so messages of any length can be encrypted.
GCM      = CTR mode + an authentication tag, so any change to the message is detected.

Public functions:
    gcm_encrypt(key, nonce, plaintext, associated_data) -> ciphertext + 16-byte tag
    gcm_decrypt(key, nonce, ciphertext_and_tag, associated_data) -> plaintext (or ValueError)
"""

# AES substitution box (S-box): replaces every byte with a fixed, non-linear value.
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


ROUNDS = 14   # AES-256 uses 14 rounds


# ------------------------------------------------------------------ AES-256 block cipher
def multiply_by_2(byte):
    """Multiply a byte by 2 in the AES finite field GF(2^8)."""
    byte <<= 1
    if byte & 0x100:            # overflowed 8 bits -> reduce with the AES polynomial
        byte ^= 0x11B
    return byte


def make_round_keys(key):
    """Expand the 32-byte key into 15 round keys (16 bytes each)."""
    words = [list(key[4 * i:4 * i + 4]) for i in range(8)]     # first 8 words = the key itself
    round_constant = 1
    for i in range(8, 60):
        word = words[i - 1][:]
        if i % 8 == 0:
            word = word[1:] + word[:1]                         # rotate left by one byte
            word = [SBOX[b] for b in word]                     # substitute each byte
            word[0] ^= round_constant
            round_constant = multiply_by_2(round_constant)
        elif i % 8 == 4:
            word = [SBOX[b] for b in word]                     # extra substitution used by AES-256
        words.append([a ^ b for a, b in zip(words[i - 8], word)])
    # group 4 words (16 bytes) per round key
    return [sum(words[4 * r:4 * r + 4], []) for r in range(ROUNDS + 1)]


def sub_bytes(state):
    return [SBOX[b] for b in state]


def shift_rows(state):
    """State is 4x4 stored column by column; row r is rotated left by r positions."""
    return [state[row + 4 * ((col + row) % 4)] for col in range(4) for row in range(4)]


def mix_columns(state):
    """Mix the 4 bytes of every column so each output byte depends on the whole column."""
    mixed = []
    for col in range(4):
        a = state[4 * col:4 * col + 4]
        total = a[0] ^ a[1] ^ a[2] ^ a[3]
        mixed += [a[i] ^ total ^ multiply_by_2(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
    return mixed


def add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


def aes_encrypt_block(block, round_keys):
    """Encrypt exactly one 16-byte block."""
    state = add_round_key(list(block), round_keys[0])
    for round_number in range(1, ROUNDS + 1):
        state = shift_rows(sub_bytes(state))
        if round_number < ROUNDS:                  # the last round has no MixColumns
            state = mix_columns(state)
        state = add_round_key(state, round_keys[round_number])
    return bytes(state)


# ------------------------------------------------------------------ GCM mode
def xor_bytes(first, second):
    return bytes(a ^ b for a, b in zip(first, second))


def gf128_multiply(x, y):
    """Multiply two 128-bit numbers in GF(2^128) using GCM's bit order."""
    result = 0
    for bit in range(127, -1, -1):
        if (x >> bit) & 1:
            result ^= y
        if y & 1:                                   # shifting out a 1 -> reduce with GCM polynomial
            y = (y >> 1) ^ (0xE1 << 120)
        else:
            y >>= 1
    return result


def ctr_crypt(round_keys, nonce, data):
    """Encrypt/decrypt with CTR mode (same operation both ways): XOR data with AES keystream."""
    output = b""
    for offset in range(0, len(data), 16):
        # counter block = 12-byte nonce + 4-byte counter (counter value 1 is reserved for the tag)
        counter_block = nonce + (2 + offset // 16).to_bytes(4, "big")
        keystream = aes_encrypt_block(counter_block, round_keys)
        output += xor_bytes(data[offset:offset + 16], keystream)
    return output


def compute_tag(round_keys, nonce, associated_data, ciphertext):
    """Authentication tag over the associated data AND the ciphertext (GHASH + masking)."""
    hash_key = int.from_bytes(aes_encrypt_block(bytes(16), round_keys), "big")

    def pad_to_16(data):
        return data + bytes(-len(data) % 16)

    # GHASH input = padded associated data + padded ciphertext + both lengths (in bits)
    ghash_input = (pad_to_16(associated_data) + pad_to_16(ciphertext)
                   + (len(associated_data) * 8).to_bytes(8, "big")
                   + (len(ciphertext) * 8).to_bytes(8, "big"))
    ghash = 0
    for offset in range(0, len(ghash_input), 16):
        block = int.from_bytes(ghash_input[offset:offset + 16], "big")
        ghash = gf128_multiply(ghash ^ block, hash_key)

    # mask the hash with AES(nonce || counter=1) so the tag reveals nothing about hash_key
    mask = aes_encrypt_block(nonce + (1).to_bytes(4, "big"), round_keys)
    return xor_bytes(ghash.to_bytes(16, "big"), mask)


def gcm_encrypt(key, nonce, plaintext, associated_data=b""):
    """key: 32 bytes. nonce: 12 bytes, NEVER reused with the same key.
    associated_data is authenticated but not encrypted. Returns ciphertext + 16-byte tag."""
    round_keys = make_round_keys(key)
    ciphertext = ctr_crypt(round_keys, nonce, plaintext)
    return ciphertext + compute_tag(round_keys, nonce, associated_data, ciphertext)


def gcm_decrypt(key, nonce, ciphertext_and_tag, associated_data=b""):
    """Verify the tag FIRST; only if it matches is the plaintext returned."""
    if len(ciphertext_and_tag) < 16:
        raise ValueError("message too short")
    ciphertext, received_tag = ciphertext_and_tag[:-16], ciphertext_and_tag[-16:]
    round_keys = make_round_keys(key)
    expected_tag = compute_tag(round_keys, nonce, associated_data, ciphertext)
    difference = 0
    for a, b in zip(received_tag, expected_tag):    # compare every byte (no early exit)
        difference |= a ^ b
    if difference:
        raise ValueError("authentication tag mismatch (message was tampered with)")
    return ctr_crypt(round_keys, nonce, ciphertext)


if __name__ == "__main__":
    # Official NIST AES-256-GCM test vectors (test cases 13 and 14)
    zero_key, zero_nonce = bytes(32), bytes(12)
    assert gcm_encrypt(zero_key, zero_nonce, b"").hex() == "530f8afbc74536b9a963b4f1c4cb738b"
    assert gcm_encrypt(zero_key, zero_nonce, bytes(16)).hex() == (
        "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
    sealed = gcm_encrypt(zero_key, zero_nonce, b"hello", b"header")
    assert gcm_decrypt(zero_key, zero_nonce, sealed, b"header") == b"hello"
    print("AES-256-GCM self-test passed")
