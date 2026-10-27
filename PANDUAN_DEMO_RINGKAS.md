# Panduan cepat demo KI

## Sebelum demo

1. Catat **IP Alice**, **IP KDC**, dan **IP Bob**. Harus 3 IP berbeda.
2. Jalankan `python -m unittest discover -s tests -v` dari VS Code; pastikan semuanya `OK`.
3. Buka Wireshark pada interface VMnet1, display filter `tcp.port == 5000 || tcp.port == 5001`.
4. Buka tiga terminal: Ubuntu KDC, Ubuntu Bob, Windows Alice.

## Yang dilakukan saat demo

1. **KDC**: `python3 kdc.py` → input `AliceSecretKey01` lalu `BobSecretKey0001`.
2. **Bob**: `python3 bob.py` → input `BobSecretKey0001`.
3. **Alice**: `python alice.py --kdc-host IP_KDC --bob-host IP_BOB` → input `AliceSecretKey01`.
4. Lihat pesan `5 langkah selesai`, lalu Alice mengetik `Halo Bob!`.
5. Bob membalas `Halo Alice!`, lihat keduanya menerima balasan plaintext hasil dekripsi.
6. Buka Wireshark. Filter `tcp.port == 5000 || tcp.port == 5001`, Follow TCP Stream untuk ciphertext.
7. **KDC**: `session ABCD1234EFGH5678` → **Alice**: `/rekey`; buktikan kedua pihak tetap berkomunikasi.

