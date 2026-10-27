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

## Jawaban singkat saat ditanya dosen

- **Kenapa perlu KDC?** Agar Alice dan Bob memperoleh session key bersama tanpa mengirim session key itu secara terang-terangan antar mereka.
- **Apa beda master key dan session key?** Master key `K_A`, `K_B` ialah rahasia jangka lebih panjang antara masing-masing entitas dan KDC; session key `K_AB` dipakai Alice-Bob untuk satu sesi chat.
- **Kenapa AES?** Algoritma enkripsi simetris blok 128 bit. AES-128 memakai key 128 bit dan 10 round.
- **Apa yang manual?** Key expansion, S-Box, ShiftRows, MixColumns, AddRoundKey dan inversnya; CBC dan PKCS#7 juga dikodekan sendiri.
- **Kenapa hex?** Ciphertext ialah bytes, Hex adalah representasi text dari bytes terenkripsi untuk transport/demo. Hex sendiri bukan enkripsi.
- **Apa fungsi nonce?** Membantu memastikan pesan balasan terkait permintaan/challenge yang masih berlaku.
- **Kenapa Wireshark?** Membuktikan transmisi TCP pada IP berbeda dan melihat bahwa payload chat terenkripsi.
- **Gimana mengubah key?** Atur kunci sesi berikutnya di terminal KDC melalui `session <16 ASCII>`; ketik `/rekey` di Alice untuk memulai ulang protokol tanpa restart.

**CATATAN:** Lima langkah wajib disamakan dengan PPT dosen. Contoh ini menerapkan versi Needham–Schroeder symmetric key. Jangan mengklaim kesesuaian dengan PPT bila belum dicek.
