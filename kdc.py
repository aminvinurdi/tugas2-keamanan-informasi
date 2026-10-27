"""KDC server for the 5-message symmetric Needham-Schroeder scenario.

Step 1 Alice -> KDC: A, B, nonce_A
Step 2 KDC -> Alice: AES_KA(nonce_A, B, session_key, AES_KB(A, session_key))
Step 3 Alice -> Bob: ticket AES_KB(A, session_key)
Step 4 Bob -> Alice: AES_session(nonce_B)
Step 5 Alice -> Bob: AES_session(nonce_B - 1)
"""
import argparse
import getpass
import socketserver
import threading
import time
from crypto_utils import check_key, encrypt_json, random_ascii
from protocol import recv_json, send_json, print_cipher


class KDCState:
    def __init__(self, alice_key, bob_key, session_key=None):
        self.lock = threading.Lock()
        self.keys = {'Alice': check_key(alice_key), 'Bob': check_key(bob_key)}
        self.next_key = check_key(session_key) if session_key else None

    def issue(self, request):
        if request.get('type') != 'KEY_REQUEST' or request.get('alice') != 'Alice' or request.get('bob') != 'Bob':
            raise ValueError('Request KDC tidak valid')
        nonce = request.get('nonce')
        if not isinstance(nonce, str) or len(nonce) < 8 or not nonce.isascii():
            raise ValueError('Nonce Alice tidak valid')
        with self.lock:
            alice_master, bob_master = self.keys['Alice'], self.keys['Bob']
            session_key = self.next_key or random_ascii()
            self.next_key = None
        expiry = int(time.time()) + 900
        ticket = encrypt_json({'alice': 'Alice', 'session': session_key, 'expires': expiry}, bob_master)
        encrypted_reply = encrypt_json({'nonce': nonce, 'bob': 'Bob', 'session': session_key, 'ticket': ticket}, alice_master)
        return encrypted_reply, ticket


class KDCHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            reader = self.request.makefile('rb')
            req = recv_json(reader)
            print(f"[KDC step 1] Request dari {self.client_address[0]}: Alice meminta key untuk Bob", flush=True)
            blob, ticket = self.server.kdc_state.issue(req)
            print_cipher('KDC step 2 -> Alice (encrypted under K_A)', blob)
            print_cipher('Ticket for Bob (encrypted under K_B)', ticket)
            send_json(self.request, {'type': 'KDC_REPLY', 'blob': blob})
        except Exception as exc:
            print(f'[KDC ERROR] {exc}', flush=True)
            try:
                send_json(self.request, {'type': 'ERROR', 'message': str(exc)})
            except OSError:
                pass


class ThreadedKDC(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description='Manual Key Distribution Center')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--alice-key', help='ASCII 16 karakter (argumen ini muncul di riwayat shell)')
    parser.add_argument('--bob-key', help='ASCII 16 karakter (argumen ini muncul di riwayat shell)')
    args = parser.parse_args()
    key_a = args.alice_key or getpass.getpass('Masukkan master key Alice (16 ASCII): ')
    key_b = args.bob_key or getpass.getpass('Masukkan master key Bob (16 ASCII): ')
    state = KDCState(key_a, key_b)
    with ThreadedKDC((args.host, args.port), KDCHandler) as server:
        server.kdc_state = state
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f'[KDC] Server aktif di {args.host}:{args.port}')
        print('Perintah: session <16ASCII> (tentukan session key untuk handshake berikutnya), status, quit')
        try:
            while True:
                command = input('KDC> ').strip()
                if command.lower() == 'quit':
                    break
                if command.lower() == 'status':
                    print('[KDC] Aktif. Next key:', 'custom' if state.next_key else 'acak otomatis')
                elif command.startswith('session '):
                    try:
                        new_key = check_key(command[len('session '):])
                        with state.lock:
                            state.next_key = new_key
                        print('[KDC] Session key berikutnya sudah diperbarui tanpa restart.')
                    except ValueError as exc:
                        print('[ERROR]', exc)
                elif command:
                    print('Perintah: session <16ASCII> | status | quit')
        except (KeyboardInterrupt, EOFError):
            pass
        finally:
            server.shutdown()


if __name__ == '__main__':
    main()
