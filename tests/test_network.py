"""Local TCP integration test: real sockets, KDC, Alice, Bob, handshake and chat."""
import sys
import socket
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from alice import establish
from bob import BobApp
from kdc import KDCState, KDCHandler, ThreadedKDC
from crypto_utils import decrypt_ascii, decrypt_json, encrypt_ascii
from protocol import recv_json, send_json


class TestEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kdc_state = KDCState('AliceSecretKey01', 'BobSecretKey0001')
        cls.kdc = ThreadedKDC(('127.0.0.1', 0), KDCHandler)
        cls.kdc.kdc_state = cls.kdc_state
        cls.kdc_thread = threading.Thread(target=cls.kdc.serve_forever, daemon=True)
        cls.kdc_thread.start()
        cls.bob = BobApp('BobSecretKey0001')
        cls.bob.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.bob.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.bob.server.bind(('127.0.0.1', 0))
        cls.bob.server.listen(5)
        cls.bob_thread = threading.Thread(target=cls.bob.accept_loop, daemon=True)
        cls.bob_thread.start()
        cls.args = SimpleNamespace(kdc_host='127.0.0.1', kdc_port=cls.kdc.server_address[1],
                                   bob_host='127.0.0.1', bob_port=cls.bob.server.getsockname()[1])

    @classmethod
    def tearDownClass(cls):
        cls.bob.stop.set()
        cls.bob.server.close()
        cls.kdc.shutdown()
        cls.kdc.server_close()

    def test_kdc_step2_matches_ppt_two_separate_ciphertexts(self):
        n1 = 'ABCDEF1234567890'
        for_alice, ticket_for_bob = self.kdc_state.issue({
            'type': 'KEY_REQUEST', 'alice': 'Alice', 'bob': 'Bob', 'nonce': n1
        })
        body = decrypt_json(for_alice, 'AliceSecretKey01')
        ticket = decrypt_json(ticket_for_bob, 'BobSecretKey0001')
        self.assertEqual(set(body), {'session', 'alice', 'bob', 'nonce'})
        self.assertEqual(set(ticket), {'session', 'alice'})
        self.assertEqual(body['alice'], 'Alice')
        self.assertEqual(body['bob'], 'Bob')
        self.assertEqual(body['nonce'], n1)
        self.assertEqual(ticket, {'session': body['session'], 'alice': 'Alice'})

    def test_five_steps_and_two_way_chat_and_rekey(self):
        alice_sock, alice_reader, key_one = establish(self.args, 'AliceSecretKey01')
        self.assertEqual(self.bob.session_key, key_one)
        enc = encrypt_ascii('Halo Bob, pesan dari Alice', key_one)
        send_json(alice_sock, {'type': 'DATA', 'payload': enc})
        reply = encrypt_ascii('Halo Alice, balasan Bob', self.bob.session_key)
        with self.bob.lock:
            send_json(self.bob.socket, {'type': 'DATA', 'payload': reply})
        received = recv_json(alice_reader)
        self.assertEqual(decrypt_ascii(received['payload'], key_one), 'Halo Alice, balasan Bob')
        alice_sock.shutdown(socket.SHUT_RDWR)
        alice_sock.close()
        alice_reader.close()

        changed_key = 'NewSessionKey123'
        self.kdc_state.next_key = changed_key
        alice_sock, alice_reader, key_two = establish(self.args, 'AliceSecretKey01')
        self.assertEqual(key_two, changed_key)
        self.assertNotEqual(key_one, key_two)
        self.assertEqual(self.bob.session_key, changed_key)
        alice_sock.shutdown(socket.SHUT_RDWR)
        alice_sock.close()
        alice_reader.close()


if __name__ == '__main__':
    unittest.main()
