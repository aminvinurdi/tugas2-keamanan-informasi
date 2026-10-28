"""Bob: accepts encrypted tickets, authenticates Alice, and chats both ways."""
import argparse
import getpass
import secrets
import socket
import threading

from crypto_utils import check_key, decrypt_ascii, decrypt_json, encrypt_ascii
from protocol import print_cipher, recv_json, send_json


class BobApp:
    def __init__(self, master_key):
        self.master_key = check_key(master_key)
        self.lock = threading.Lock()
        self.socket = None
        self.session_key = None
        self.server = None
        self.stop = threading.Event()

    def handle_client(self, sock, address):
        with sock:
            try:
                sock.settimeout(20)
                reader = sock.makefile('rb')
                first = recv_json(reader)
                if first.get('type') != 'TICKET':
                    raise ValueError('Tahap 3 membutuhkan ticket KDC')
                print_cipher('Bob step 3 <- Alice, ticket', first['ticket'])
                ticket = decrypt_json(first['ticket'], self.master_key)
                if ticket.get('alice') != 'Alice':
                    raise ValueError('Ticket ditolak: ID_A tidak valid')
                session_key = check_key(ticket['session'])
                nonce = str(secrets.randbelow(900000000000) + 100000000000)
                challenge = encrypt_ascii(nonce, session_key)
                print_cipher('Bob step 4 -> Alice, challenge', challenge)
                send_json(sock, {'type': 'CHALLENGE', 'payload': challenge})
                reply = recv_json(reader)
                if reply.get('type') != 'CHALLENGE_REPLY':
                    raise ValueError('Tahap 5 challenge response tidak diterima')
                print_cipher('Bob step 5 <- Alice, nonce-1', reply['payload'])
                if decrypt_ascii(reply['payload'], session_key) != str(int(nonce) - 1):
                    raise ValueError('Autentikasi Alice gagal: nonce tidak cocok')
                ready = encrypt_ascii('READY', session_key)
                send_json(sock, {'type': 'READY', 'payload': ready})
                sock.settimeout(None)
                with self.lock:
                    if self.socket is not None:
                        try:
                            self.socket.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    self.socket = sock
                    self.session_key = session_key
                print('[Bob] 5 langkah selesai. Chat AES dua arah AKTIF!')
                while not self.stop.is_set():
                    msg = recv_json(reader)
                    if msg.get('type') != 'DATA':
                        print('[Bob] Tipe paket tidak dikenal')
                        continue
                    print_cipher('Bob menerima dari Alice', msg['payload'])
                    plaintext = decrypt_ascii(msg['payload'], session_key)
                    print(f'\nAlice: {plaintext}\nBob> ', end='', flush=True)
            except (OSError, ValueError, ConnectionError, KeyError, TypeError) as exc:
                print(f'\n[Bob] Sesi {address[0]} selesai / error: {exc}', flush=True)
            finally:
                with self.lock:
                    if self.socket is sock:
                        self.socket = None
                        self.session_key = None

    def accept_loop(self):
        while not self.stop.is_set():
            try:
                sock, addr = self.server.accept()
            except OSError:
                break
            print(f'[Bob] Ada koneksi dari {addr[0]}:{addr[1]}', flush=True)
            threading.Thread(target=self.handle_client, args=(sock, addr), daemon=True).start()

    def run(self, host, port):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(5)
        print(f'[Bob] Mendengarkan di {host}:{port}')
        print('Ketik pesan ASCII untuk Alice. Perintah: /status | /quit')
        threading.Thread(target=self.accept_loop, daemon=True).start()
        try:
            while True:
                value = input('Bob> ').strip()
                if value == '/quit':
                    break
                if value == '/status':
                    with self.lock:
                        print('[Bob] Sesi:', 'aktif' if self.socket else 'menunggu Alice')
                    continue
                if not value:
                    continue
                try:
                    with self.lock:
                        if not self.socket or not self.session_key:
                            print('[Bob] Belum terhubung. Jalankan Alice dahulu.')
                            continue
                        ciphertext = encrypt_ascii(value, self.session_key)
                        print_cipher('Bob -> Alice', ciphertext)
                        send_json(self.socket, {'type': 'DATA', 'payload': ciphertext})
                except (OSError, ValueError) as exc:
                    print('[Bob ERROR]', exc)
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            self.stop.set()
            self.server.close()
            with self.lock:
                if self.socket:
                    try:
                        self.socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass


def main():
    parser = argparse.ArgumentParser(description='Bob AES-KDC Chat')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5001)
    parser.add_argument('--master-key', help='Hanya untuk uji otomatis; tidak aman di command history')
    args = parser.parse_args()
    key = args.master_key or getpass.getpass('Master key Bob (16 ASCII): ')
    BobApp(key).run(args.host, args.port)


if __name__ == '__main__':
    main()
