"""KDC server for the 5-message symmetric Needham-Schroeder scenario.

Diagram slide 13, PPT Keamanan Informasi Week 7:
Step 1 A -> KDC: ID_A || ID_B || N1
Step 2 KDC -> A: E(K_a, [K_s || ID_A || ID_B || N1]) || E(K_b, [K_s || ID_A])
Step 3 A -> B: E(K_b, [K_s || ID_A])
Step 4 B -> A: E(K_s, N2)
Step 5 A -> B: E(K_s, f(N2)); in this demo f(N2) = N2 - 1
Additional confirmation READY happens AFTER step 5, not part of slide's 5 steps.

The || notation is represented as named JSON fields for clarity. Encryption itself
uses hand-written AES-128-CBC and random IVs for demonstration.
"""
import argparse
import getpass
import socketserver
import threading
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
        # Slide 13 (2): two SEPARATE ciphertexts (not a ticket embedded in E(K_a)).
        ticket = encrypt_json({'session': session_key, 'alice': 'Alice'}, bob_master)
        encrypted_reply = encrypt_json({
            'session': session_key, 'alice': 'Alice', 'bob': 'Bob', 'nonce': nonce
        }, alice_master)
        return encrypted_reply, ticket


class KDCHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        try:
            reader = self.request.makefile('rb')
            req = recv_json(reader)
            print(f"[KDC step 1] Request dari {self.client_address[0]}: Alice meminta key untuk Bob", flush=True)
            blob, ticket = self.server.kdc_state.issue(req)
            print_cipher('KDC step 2a E(K_a, [K_s, ID_A, ID_B, N1])', blob)
            print_cipher('KDC step 2b E(K_b, [K_s, ID_A])', ticket)
            send_json(self.request, {'type': 'KDC_REPLY', 'for_alice': blob, 'ticket_for_bob': ticket})
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
