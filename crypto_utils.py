"""ASCII keys, PKCS#7 padding and AES-128-CBC implemented without crypto libs."""
import json
import secrets
import string

from aes_manual import AES128

ASCII_ALPHABET = string.ascii_letters + string.digits


def check_key(key: str) -> str:
    if not isinstance(key, str) or len(key) != 16 or not key.isascii():
        raise ValueError('Key harus 16 karakter ASCII (AES-128), misalnya AliceSecretKey01')
    return key


def random_ascii(count: int = 16) -> str:
    return ''.join(secrets.choice(ASCII_ALPHABET) for _ in range(count))


def encrypt_ascii(plaintext: str, key: str) -> str:
    """Return uppercase hex encoding of IV (16 bytes) || CBC ciphertext."""
    check_key(key)
    if not isinstance(plaintext, str) or not plaintext.isascii():
        raise ValueError('Plaintext harus format ASCII (tanpa emoji/non-ASCII).')
    data = plaintext.encode('ascii')
    padlen = 16 - (len(data) % 16)
    data += bytes([padlen]) * padlen
    iv = secrets.token_bytes(16)
    previous = iv
    aes = AES128(key.encode('ascii'))
    chunks = []
    for offset in range(0, len(data), 16):
        block = data[offset:offset + 16]
        xored = bytes(a ^ b for a, b in zip(block, previous))
        previous = aes.encrypt_block(xored)
        chunks.append(previous)
    return (iv + b''.join(chunks)).hex().upper()


def decrypt_ascii(encoded_hex: str, key: str) -> str:
    check_key(key)
    try:
        raw = bytes.fromhex(encoded_hex)
    except (TypeError, ValueError):
        raise ValueError('Ciphertext bukan data HEX yang valid') from None
    if len(raw) < 32 or (len(raw) - 16) % 16:
        raise ValueError('Ciphertext CBC tidak memiliki panjang valid')
    iv, ciphertext = raw[:16], raw[16:]
    aes = AES128(key.encode('ascii'))
    previous = iv
    chunks = []
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset:offset + 16]
        decoded = aes.decrypt_block(block)
        chunks.append(bytes(a ^ b for a, b in zip(decoded, previous)))
        previous = block
    result = b''.join(chunks)
    padlen = result[-1]
    if not 1 <= padlen <= 16 or result[-padlen:] != bytes([padlen]) * padlen:
        raise ValueError('Padding invalid (kemungkinan kunci salah atau data berubah)')
    try:
        return result[:-padlen].decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('Hasil dekripsi bukan ASCII (kunci atau data salah)') from None


def encrypt_json(value: dict, key: str) -> str:
    return encrypt_ascii(json.dumps(value, separators=(',', ':'), ensure_ascii=True), key)


def decrypt_json(encoded_hex: str, key: str) -> dict:
    obj = json.loads(decrypt_ascii(encoded_hex, key))
    if not isinstance(obj, dict):
        raise ValueError('Payload tidak berbentuk JSON object')
    return obj
