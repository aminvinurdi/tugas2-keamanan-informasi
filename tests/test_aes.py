import unittest
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aes_manual import AES128, SBOX, INV_SBOX, gf_mul
from crypto_utils import encrypt_ascii, decrypt_ascii, encrypt_json, decrypt_json


class TestAES128(unittest.TestCase):
    def test_nist_fips_197_vector(self):
        key = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        plaintext = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
        expected = bytes.fromhex('69C4E0D86A7B0430D8CDB78070B4C55A')
        cipher = AES128(key)
        self.assertEqual(cipher.encrypt_block(plaintext), expected)
        self.assertEqual(cipher.decrypt_block(expected), plaintext)

    def test_sbox_inversion(self):
        self.assertEqual(SBOX[0], 0x63)
        self.assertEqual(SBOX[0x53], 0xED)
        for n in range(256):
            self.assertEqual(INV_SBOX[SBOX[n]], n)

    def test_gf_multiplication(self):
        self.assertEqual(gf_mul(0x57, 0x13), 0xFE)

    def test_cbc_ascii_roundtrips(self):
        key = 'AliceSecretKey01'
        for msg in ['', 'A', '0123456789ABCDEF', 'Hello Bob!', 'x' * 150]:
            encrypted = encrypt_ascii(msg, key)
            self.assertTrue(all(c in '0123456789ABCDEF' for c in encrypted))
            self.assertEqual(decrypt_ascii(encrypted, key), msg)
            self.assertNotEqual(encrypted, encrypt_ascii(msg, key))  # random IV

    def test_ascii_only(self):
        with self.assertRaises(ValueError):
            encrypt_ascii('Halo Bob 😊', 'AliceSecretKey01')

    def test_json(self):
        value = {'alice': 'Alice', 'session': 'ABCDEF1234567890'}
        encoded = encrypt_json(value, 'AliceSecretKey01')
        self.assertEqual(decrypt_json(encoded, 'AliceSecretKey01'), value)


if __name__ == '__main__':
    unittest.main()
