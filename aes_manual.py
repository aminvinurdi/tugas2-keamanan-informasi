"""AES-128 built from scratch (FIPS-197). No crypto packages.

AES state is stored column-major: state[row + 4*column].
This code is educational, not hardened against timing/side-channel attacks.
"""


def gf_mul(a: int, b: int) -> int:
    """Multiplication in GF(2^8) modulo x^8+x^4+x^3+x+1."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def gf_pow(a: int, n: int) -> int:
    result = 1
    while n:
        if n & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        n >>= 1
    return result


def rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def make_sboxes():
    sbox = [0] * 256
    inverse = [0] * 256
    for i in range(256):
        inv = gf_pow(i, 254) if i != 0 else 0
        y = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
        sbox[i] = y
        inverse[y] = i
    return sbox, inverse


SBOX, INV_SBOX = make_sboxes()


def expand_key(key: bytes) -> list[list[int]]:
    """AES-128 key schedule: 16-byte key -> 11 round keys of 16 bytes."""
    if len(key) != 16:
        raise ValueError('AES-128 requires a 16-byte key')
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        temp = words[i - 1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]      # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= rcon
            rcon = gf_mul(rcon, 2)
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    return [sum(words[4 * rnd:4 * rnd + 4], []) for rnd in range(11)]


def add_round_key(state, round_key):
    return [a ^ b for a, b in zip(state, round_key)]


def sub_bytes(state, inverse=False):
    table = INV_SBOX if inverse else SBOX
    return [table[b] for b in state]


def shift_rows(state, inverse=False):
    shifted = state[:]
    for row in range(4):
        for col in range(4):
            source_col = (col - row) % 4 if inverse else (col + row) % 4
            shifted[row + 4 * col] = state[row + 4 * source_col]
    return shifted


def mix_columns(state, inverse=False):
    result = state[:]
    matrix = ([14, 11, 13, 9], [9, 14, 11, 13], [13, 9, 14, 11], [11, 13, 9, 14]) if inverse else (
        [2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2])
    for col in range(4):
        values = state[4 * col:4 * col + 4]
        for row in range(4):
            result[4 * col + row] = (
                gf_mul(matrix[row][0], values[0]) ^ gf_mul(matrix[row][1], values[1]) ^
                gf_mul(matrix[row][2], values[2]) ^ gf_mul(matrix[row][3], values[3])
            )
    return result


class AES128:
    def __init__(self, key: bytes):
        self.round_keys = expand_key(key)

    def encrypt_block(self, plaintext: bytes) -> bytes:
        if len(plaintext) != 16:
            raise ValueError('AES block must be exactly 16 bytes')
        state = add_round_key(list(plaintext), self.round_keys[0])
        for rnd in range(1, 10):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.round_keys[rnd])
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, self.round_keys[10])
        return bytes(state)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != 16:
            raise ValueError('AES block must be exactly 16 bytes')
        state = add_round_key(list(ciphertext), self.round_keys[10])
        for rnd in range(9, 0, -1):
            state = shift_rows(state, inverse=True)
            state = sub_bytes(state, inverse=True)
            state = add_round_key(state, self.round_keys[rnd])
            state = mix_columns(state, inverse=True)
        state = shift_rows(state, inverse=True)
        state = sub_bytes(state, inverse=True)
        state = add_round_key(state, self.round_keys[0])
        return bytes(state)
