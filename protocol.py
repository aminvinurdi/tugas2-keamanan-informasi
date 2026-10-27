"""One JSON object per TCP line. Payloads use ASCII and cipher HEX strings."""
import json

MAX_LINE = 1024 * 1024


def send_json(sock, payload: dict):
    blob = json.dumps(payload, ensure_ascii=True, separators=(',', ':')).encode('ascii') + b'\n'
    if len(blob) > MAX_LINE:
        raise ValueError('Pesan terlalu panjang')
    sock.sendall(blob)


def recv_json(reader) -> dict:
    line = reader.readline(MAX_LINE + 1)
    if not line:
        raise ConnectionError('Koneksi telah ditutup')
    if len(line) > MAX_LINE or not line.endswith(b'\n'):
        raise ValueError('Pesan jaringan terlalu panjang atau tidak lengkap')
    obj = json.loads(line.decode('ascii'))
    if not isinstance(obj, dict):
        raise ValueError('Pesan jaringan bukan JSON object')
    return obj


def print_cipher(label: str, ciphertext_hex: str):
    print(f'[{label}] HEX: {ciphertext_hex}', flush=True)
