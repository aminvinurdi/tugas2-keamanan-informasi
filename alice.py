"""Alice: KDC requester and two-way AES chat participant."""
import argparse
import getpass
import secrets
import socket
import threading

from crypto_utils import check_key, decrypt_ascii, decrypt_json, encrypt_ascii, random_ascii
from protocol import print_cipher, recv_json, send_json


def request_key_from_kdc(host, port, alice_master_key):
    nonce = random_ascii(16)
    with socket.create_connection((host, port), timeout=10) as sock:
        sock.settimeout(20)
        reader = sock.makefile('rb')
        send_json(sock, {'type': 'KEY_REQUEST', 'alice': 'Alice', 'bob': 'Bob', 'nonce': nonce})
        print('[Alice step 1] Request key ke KDC untuk Bob')
        result = recv_json(reader)
    if result.get('type') == 'ERROR':
        raise ValueError('KDC error: ' + str(result.get('message')))
    if result.get('type') != 'KDC_REPLY':
        raise ValueError('Balasan KDC tidak dikenali')
    print_cipher('Alice step 2 menerima pesan KDC', result['blob'])
    data = decrypt_json(result['blob'], alice_master_key)
    if data.get('nonce') != nonce or data.get('bob') != 'Bob':
        raise ValueError('Nonce/identitas pada balasan KDC tidak cocok')
    session_key = check_key(data['session'])
    print('[Alice] Key K_AB sudah didekripsi dan nonce Alice cocok.')
    return session_key, data['ticket']


def establish(args, master_key):
    session_key, ticket = request_key_from_kdc(args.kdc_host, args.kdc_port, master_key)
    sock = socket.create_connection((args.bob_host, args.bob_port), timeout=10)
    sock.settimeout(20)
    try:
        reader = sock.makefile('rb')
        send_json(sock, {'type': 'TICKET', 'ticket': ticket})
        print_cipher('Alice step 3 -> Bob, ticket', ticket)
        challenge_msg = recv_json(reader)
        if challenge_msg.get('type') != 'CHALLENGE':
            raise ValueError('Bob tidak mengirim challenge')
        print_cipher('Alice step 4 <- Bob, challenge', challenge_msg['payload'])
        challenge = decrypt_ascii(challenge_msg['payload'], session_key)
        if not challenge.isdecimal():
            raise ValueError('Nonce Bob tidak valid')
        answer = encrypt_ascii(str(int(challenge) - 1), session_key)
        send_json(sock, {'type': 'CHALLENGE_REPLY', 'payload': answer})
        print_cipher('Alice step 5 -> Bob, nonce-1', answer)
        ready = recv_json(reader)
        if ready.get('type') != 'READY' or decrypt_ascii(ready['payload'], session_key) != 'READY':
            raise ValueError('Bob gagal melakukan autentikasi')
        sock.settimeout(None)
        print('[Alice] 5 langkah selesai. Chat AES dua arah AKTIF!')
        return sock, reader, session_key
    except Exception:
        sock.close()
        raise


def read_messages(reader, session_key, stop):
    try:
        while not stop.is_set():
            msg = recv_json(reader)
            if msg.get('type') != 'DATA':
                print('[Alice] Pesan jaringan tidak dikenali')
                continue
            print_cipher('Alice menerima dari Bob', msg['payload'])
            plaintext = decrypt_ascii(msg['payload'], session_key)
            print(f'\nBob: {plaintext}\nAlice> ', end='', flush=True)
    except (OSError, ValueError, ConnectionError, KeyError) as exc:
        if not stop.is_set():
            print(f'\n[Alice] Koneksi terputus: {exc}\nAlice> ', end='', flush=True)


def main():
    parser = argparse.ArgumentParser(description='Alice AES-KDC Chat')
    parser.add_argument('--kdc-host', required=True, help='IP mesin KDC')
    parser.add_argument('--kdc-port', type=int, default=5000)
    parser.add_argument('--bob-host', required=True, help='IP mesin Bob')
    parser.add_argument('--bob-port', type=int, default=5001)
    parser.add_argument('--master-key', help='Hanya untuk uji otomatis; tidak aman di command history')
    args = parser.parse_args()
    master_key = check_key(args.master_key or getpass.getpass('Master key Alice (16 ASCII): '))
    print('Perintah chat: ketik pesan ASCII | /rekey | /status | /quit')
    while True:
        try:
            sock, reader, session_key = establish(args, master_key)
        except (OSError, ValueError, KeyError) as exc:
            print('[Alice] Gagal membuat sesi:', exc)
            retry = input('Ketik r untuk coba lagi atau q untuk keluar: ').strip().lower()
            if retry != 'r':
                return
            continue
        stop = threading.Event()
        receiver = threading.Thread(target=read_messages, args=(reader, session_key, stop), daemon=True)
        receiver.start()
        action = 'quit'
        try:
            while True:
                value = input('Alice> ').strip()
                if not value:
                    continue
                if value == '/quit':
                    break
                if value == '/status':
                    print('[Alice] Tersambung ke Bob. AES-128-CBC, session key ASCII 16 karakter.')
                    continue
                if value == '/rekey':
                    action = 'rekey'
                    print('[Alice] Menghubungi KDC untuk session key baru ...')
                    break
                try:
                    encrypted = encrypt_ascii(value, session_key)
                    print_cipher('Alice -> Bob', encrypted)
                    send_json(sock, {'type': 'DATA', 'payload': encrypted})
                except (OSError, ValueError) as exc:
                    print('[Alice ERROR]', exc)
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            stop.set()
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
            reader.close()
            receiver.join(timeout=2)
        if action != 'rekey':
            return


if __name__ == '__main__':
    main()
