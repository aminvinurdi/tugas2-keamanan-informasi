# Peta PPT dosen -> source code (untuk persiapan demo)

Dasar: **PPT Keamanan Informasi Week 7.pdf, halaman 7, slide bernomor 13, Key Distribution Scenario**. Slide mendefinisikan 5 pertukaran pesan. Implementasi ini memakai AES-128 manual sebagai operasi `E()` dan memakai JSON-per-baris sebagai pembungkus pesan TCP. Pembungkus JSON **bukan** AES dan bukan bagian dari notasi slide.

## Notasi dan variabel

| Notasi PPT | Arti di program | Source |
|---|---|---|
| `ID_A` | string `Alice` | `alice.py` |
| `ID_B` | string `Bob` | `alice.py`, `kdc.py` |
| `K_a` | master key ASCII 16 karakter Alice-KDC | `alice.py`, `kdc.py` |
| `K_b` | master key ASCII 16 karakter Bob-KDC | `bob.py`, `kdc.py` |
| `K_s` | session key AES yang diterbitkan KDC untuk satu sesi | `kdc.py` |
| `N1` | nonce acak ASCII dari Alice | `alice.py` |
| `N2` | nonce angka acak ASCII dari Bob | `bob.py` |
| `E(K,X)` | enkripsi AES-128-CBC manual; output IV+ct dalam HEX | `aes_manual.py`, `crypto_utils.py` |
| `f(N2)` | `N2 - 1` | `alice.py`, `bob.py` |

## Lima langkah yang harus bisa dijelaskan

1. **Alice -> KDC:** `ID_A || ID_B || N1`.
   - `alice.request_key_from_kdc()`: membuat `nonce` dan mengirim `KEY_REQUEST`.
   - `kdc.KDCState.issue()`: memvalidasi identitas dan nonce.
2. **KDC -> Alice:** `E(K_a, [K_s || ID_A || ID_B || N1]) || E(K_b, [K_s || ID_A])`.
   - `kdc.KDCState.issue()`: menghasilkan **dua ciphertext terpisah** (`encrypted_reply` dan `ticket`).
   - `kdc.KDCHandler.handle()`: mengirim kedua ciphertext sebagai `for_alice` dan `ticket_for_bob`.
   - `alice.request_key_from_kdc()`: membuka **hanya** bagian `for_alice` dengan `K_a`, memvalidasi `N1`, `ID_A`, `ID_B`, lalu menyimpan tiket tanpa mengetahui isi terenkripsi di bawah `K_b`.
3. **Alice -> Bob:** `E(K_b, [K_s || ID_A])`.
   - `alice.establish()`: mengirim tiket apa adanya.
   - `bob.BobApp.handle_client()`: membuka tiket menggunakan `K_b`, memperoleh `K_s` dan `ID_A`.
4. **Bob -> Alice:** `E(K_s, N2)`.
   - `bob.BobApp.handle_client()`: membuat nonce angka acak, mengenkripsinya dengan `K_s`, mengirim `CHALLENGE`.
   - `alice.establish()`: menerima lalu mendekripsinya dengan `K_s`.
5. **Alice -> Bob:** `E(K_s, f(N2))`.
   - `alice.establish()`: mengenkripsi `int(N2)-1` dengan `K_s`, mengirim `CHALLENGE_REPLY`.
   - `bob.BobApp.handle_client()`: mendekripsi lalu membandingkan dengan `N2-1` miliknya.

**Sesudah langkah 5:** Bob mengirim `READY` terenkripsi sebagai tanda siap (fitur tambahan, bukan bagian dari lima langkah PPT). Selanjutnya Alice dan Bob saling berkirim paket `DATA` terenkripsi dua arah memakai session key.

## AES manual yang perlu dipahami

- `aes_manual.py`: `expand_key`, `sub_bytes`, `shift_rows`, `mix_columns`, `add_round_key` dan kebalikannya saat dekripsi. AES-128 menggunakan 16-byte key, state 4x4 byte, 10 ronde.
- `crypto_utils.py`: mode CBC manual (XOR dengan ciphertext sebelumnya), IV acak, padding PKCS#7, convert bytes -> ciphertext HEX. Representasi HEX bukan algoritma enkripsi.
- `protocol.py`: satu JSON object per baris jaringan; `KEY_REQUEST`, `KDC_REPLY`, `TICKET`, `CHALLENGE`, `CHALLENGE_REPLY`, `READY`, `DATA`.

## Pengujian

```bash
python -m unittest discover -s tests -v
```

Uji lokal memakai loopback `127.0.0.1` dan **belum membuktikan** syarat tiga IP. Untuk memenuhi tugas, jalankan Alice di Windows host, KDC di VM Ubuntu #1, Bob di VM Ubuntu #2; masing-masing mempunyai IP berbeda dan bisa saling terhubung. Rekam transmisi di Wireshark adapter VMnet1 atau di interface VM terkait.

## Keamanan dan kejujuran klaim

- Protokol dari slide adalah protokol pembelajaran; ticket tanpa batas waktu atau perlindungan replay yang lengkap memiliki keterbatasan jika key lama dibocorkan.
- Implementasi CBC tanpa MAC/integrity protection tidak cukup aman untuk produksi. Jangan digunakan untuk pesan rahasia sungguhan.
- Master key untuk demo tidak boleh dikirim melalui jaringan; dimasukkan di terminal masing-masing pihak dan pada KDC sebelum menjalankan program. Tidak ada cara otomatis aman untuk memprovisi master key yang ditetapkan dalam diagram.
- Perubahan session key tanpa restart: perintah `session <tepat 16 ASCII>` pada terminal KDC untuk handshake selanjutnya, lalu `/rekey` pada Alice. Master key berbeda dari session key; pergantian master key tidak didukung saat proses berjalan.
