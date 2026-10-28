# Tugas KI — AES-128 Manual + KDC + Chat Alice–Bob

**Status:** Versi disesuaikan dengan diagram *Key Distribution Scenario* pada **slide 13 / halaman 7, PPT Keamanan Informasi Week 7.pdf**. Lima pesan dasar mengikuti diagram dosen; format serialization-nya JSON, algoritma E memakai AES-128-CBC manual dengan IV acak. Ada pesan ekstra `READY` sebagai konfirmasi setelah langkah ke-5 (bukan bagian lima langkah PPT). Hasil perlu dijalankan ulang di jaringan VMware sebelum dikumpulkan.

## Gambaran arsitektur

```text
                KDC (Ubuntu VM #1)
                   TCP :5000
                 /         \
                /           \
Alice (Windows Host) <----> Bob (Ubuntu VM #2)
    client                  TCP :5001
                  AES-128-CBC
```

Semua mesin berada pada VMware **Host-only / VMnet1** dengan **3 IP IPv4 berbeda**. Bob adalah TCP server, Alice TCP client; komunikasi chat **dua arah** di koneksi tersebut. KDC menjadi server distribusi key terpisah.

### Lima langkah **persis sesuai struktur PPT slide 13**

Notasi diagram: `ID_A=Alice`, `ID_B=Bob`, `K_a=master Alice`, `K_b=master Bob`, `K_s=session key`, `N1=nonce Alice`, `N2=nonce Bob`, dan `E(K,x)` berarti AES dengan kunci K.

1. **Alice → KDC:** `ID_A || ID_B || N1`. JSON: `KEY_REQUEST {alice, bob, nonce}`.
2. **KDC → Alice:** `E(K_a, [K_s || ID_A || ID_B || N1]) || E(K_b, [K_s || ID_A])`. Dua ciphertext mandiri, dikirim dalam pesan JSON `KDC_REPLY {for_alice, ticket_for_bob}`; ticket tidak disisipkan di ciphertext pertama.
3. **Alice → Bob:** `E(K_b, [K_s || ID_A])`. JSON: `TICKET {ticket}`; Bob mendekripsi menggunakan `K_b`.
4. **Bob → Alice:** `E(K_s, N2)`. JSON: `CHALLENGE {payload}`.
5. **Alice → Bob:** `E(K_s, f(N2))`. Di program, fungsi `f` adalah mengurangi bilangan nonce satu: `f(N2)=N2-1`. JSON: `CHALLENGE_REPLY {payload}`.

**Sesudah langkah 5** Bob mengirim `READY` terenkripsi sebagai acknowledgement tambahan agar Alice tahu verifikasi sukses, kemudian kedua pengguna chat dua arah dengan AES. Paket `READY` **bukan langkah keenam protokol PPT**, hanya fitur implementasi.

> Slide tidak menentukan mode AES, IV, atau format serialisasi; untuk keperluan tugas dipakai AES-128-CBC (manual), IV acak, PKCS#7, JSON framing TCP, plaintext dan key berkarakter ASCII, ciphertext dalam HEX. Penggunaan ini merupakan keputusan desain proyek, bukan klaim bahwa slide memerintahkannya. Format nonce challenge menggunakan angka ASCII.

> **Batasan keamanan:** tiket langkah 3 sengaja hanya memuat K_s dan ID_A agar sesuai diagram PPT. Protokol klasik ini memiliki keterbatasan replay jika tiket lama / session key lama bocor; jangan gunakan aplikasi demonstrasi ini untuk komunikasi produksi. Pemilihan AES-CBC tanpa autentikasi kriptografis juga tidak tahan manipulasi ciphertext.

KDC memakai dua master key terpisah: `K_A` dan `K_B`. KDC membuat session key `K_AB` acak baru pada setiap handshake (atau menerima session key yang ditentukan operator untuk permintaan berikutnya).

## Apa yang manual?

- `aes_manual.py`: operasi GF(2^8), algoritma S-Box/Inverse S-Box, Key Expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey dan operasi invers AES-128 untuk dekripsi.
- `crypto_utils.py`: mode AES-CBC, IV acak, PKCS#7 padding, plaintext dan key ASCII, output ciphertext HEX.
- `kdc.py`: membuat ciphertext `E(K_a,...)` dan tiket `E(K_b,...)` secara terpisah pada langkah 2, membuat session key, mengelola master key. **Tidak menggunakan library AES siap pakai.**
- `protocol.py`: format paket ASCII JSON-per-baris di atas TCP socket Python standar.
- `alice.py`, `bob.py`: handshake dan chat dua arah, masing-masing sender dan receiver.

**Tidak perlu `pip install` apa pun.** Program menggunakan modul Python standard library saja. Gunakan Python 3.10 atau lebih baru.

## Cara tes TERCEPAT di satu komputer (sebelum VM siap)

> Uji lokal ini **belum memenuhi syarat 3 IP**. Untuk mengecek kode saja. Buka 3 terminal berbeda pada folder proyek di VS Code.

Terminal 1, jalankan KDC:

```powershell
python kdc.py
```

Saat ditanya key, isi:

```text
Master key Alice: AliceSecretKey01
Master key Bob:   BobSecretKey0001
```

Terminal 2, jalankan Bob:

```powershell
python bob.py
```

Ketika ditanya master key Bob, isi `BobSecretKey0001`.

Terminal 3, jalankan Alice:

```powershell
python alice.py --kdc-host 127.0.0.1 --bob-host 127.0.0.1
```

Ketika ditanya master key Alice, isi `AliceSecretKey01`.

Coba ketik pesan ASCII dari terminal Alice dan balas dari terminal Bob. Lihat dua terminal menampilkan ciphertext HEX. Jangan memakai emoji/karakter non-ASCII.

## Cara pakai sungguhan dengan 3 IP di VMware (sesuai ketentuan)

**1. Persiapan VMware dan OS**

- Instal VMware Workstation di Windows.
- Download **satu ISO Ubuntu Server** untuk membuat 2 VM.
- Buat VM `KDC-Server`: Ubuntu Server, RAM 2 GB, 2 vCPU, disk 20 GB.
- Buat VM `Bob-Client`: Ubuntu Server, RAM 2 GB, 2 vCPU, disk 20 GB.
- Set **Network Adapter > Host-only** pada kedua VM, dan aktifkan adapter VMnet1 pada Windows host. Aktifkan DHCP Host-only atau berikan ketiga alamat IP statis dalam subnet yang sama, tidak bentrok.
- Saat instalasi Ubuntu, centang opsi **Install OpenSSH server** agar folder proyek bisa dikirim via `scp`.

**2. Cek ketiga IP**

Windows (Alice):

```powershell
ipconfig
```

Cari `VMware Network Adapter VMnet1` dan IPv4. Di terminal Ubuntu (KDC/Bob):

```bash
ip -4 addr
```

**Contoh hipotetis**, BUKAN IP yang harus dipakai (pakai hasil `ipconfig` dan `ip -4 addr` milikmu):

| Entitas | Lokasi | Contoh IP |
|---|---|---|
| Alice | Windows | `192.168.100.1` |
| KDC | VM #1 | `192.168.100.10` |
| Bob | VM #2 | `192.168.100.11` |

Cek dari Windows: `ping 192.168.100.10` dan `ping 192.168.100.11`. Ganti sesuai IP nyata.

**3. Kirim folder kode ke kedua VM**

Dari **PowerShell Windows**, setelah OpenSSH Server sudah berjalan di Ubuntu dan SSH terjangkau:

```powershell
scp -r "C:\path\ke\KI_AES_KDC_Manual" username@IP_KDC:/home/username/
scp -r "C:\path\ke\KI_AES_KDC_Manual" username@IP_BOB:/home/username/
```

`username` adalah username Ubuntu yang dipilih saat instalasi. Sesuaikan path folder dan IP dengan keadaanmu. Jika `scp` gagal karena SSH belum terpasang, pasang `openssh-server` di Ubuntu ketika VM memiliki akses Internet/NAT, kemudian kembalikan jaringan VM ke Host-only.

**4. Jalankan di masing-masing OS, dengan urutan ini:**

Di terminal Ubuntu **KDC**:

```bash
cd ~/KI_AES_KDC_Manual
python3 kdc.py --host 0.0.0.0 --port 5000
```

Masukkan key `AliceSecretKey01` lalu `BobSecretKey0001`.

Di terminal Ubuntu **Bob**:

```bash
cd ~/KI_AES_KDC_Manual
python3 bob.py --host 0.0.0.0 --port 5001
```

Masukkan key `BobSecretKey0001`.

Di **Windows Alice**, buka terminal VS Code dalam folder proyek:

```powershell
python alice.py --kdc-host IP_KDC --bob-host IP_BOB
```

Ganti `IP_KDC` dan `IP_BOB` dengan IP nyata. Masukkan key `AliceSecretKey01`.

Jika muncul `5 langkah selesai. Chat AES dua arah AKTIF!`, coba kirim `Halo Bob` dari Alice dan balas `Halo Alice` dari Bob.

### Mengubah kunci TANPA restart

- Pada terminal **KDC**: ketik `session ABCD1234EFGH5678` (tepat 16 karakter ASCII).
- Pada terminal **Alice**: ketik `/rekey`.
- KDC kemudian menggunakan kunci baru untuk sesi berikutnya. Alice mendapatkan tiket baru, Bob memvalidasi dan memakai session key baru. **Bob dan KDC tidak perlu restart.**
- Ketik `/status` untuk melihat status, `/quit` untuk keluar.

Master key Alice dan Bob dimasukkan saat awal aplikasi, **bukan di-hardcode di kode aplikasi**. Untuk mendemonstrasikan perubahan key saat program berjalan, gunakan **session key** seperti di atas.

## Wireshark untuk demo

1. Instal Wireshark + Npcap di Windows.
2. Pilih interface **VMware Network Adapter VMnet1** (adapter Host-only). Capture pada interface ini sambil melakukan handshake.
3. Pada **display filter** Wireshark, gunakan:

   ```text
   tcp.port == 5000 || tcp.port == 5001
   ```

4. Klik kanan paket yang relevan, pilih **Follow > TCP Stream**. Tunjukkan paket `KEY_REQUEST`, `KDC_REPLY`, `TICKET`, `CHALLENGE`, `CHALLENGE_REPLY`, dan paket chat `DATA`.
5. Tunjukkan `payload` berbentuk HEX bukan pesan `Halo Bob`. **Catatan:** metadata seperti IP, port, dan tipe pesan JSON tetap terlihat; yang disembunyikan AES adalah isi pesan, bukan seluruh traffic.
6. Jika paket tidak muncul, pastikan interface benar, filter tepat, serta tidak terjadi blokir Windows Firewall/Ubuntu UFW. Beberapa lalu lintas antar-VM pada host-only switch virtual mungkin membutuhkan capture pada interface VM/guest untuk terlihat; komunikasi host↔VM biasanya dapat ditangkap dari VMnet1.

## Uji otomatis

Di VS Code PowerShell, atau terminal Linux di folder proyek:

```bash
python -m unittest discover -s tests -v
```

Di Ubuntu gunakan `python3` jika `python` tidak dikenali. Tes mencakup:
- Vektor uji resmi **FIPS-197 AES-128**: `00112233445566778899AABBCCDDEEFF` dengan key `000102030405060708090A0B0C0D0E0F` menghasilkan `69C4E0D86A7B0430D8CDB78070B4C55A`.
- Validasi S-Box dan operasi finite field.
- CBC roundtrip ASCII multi-blok dengan IV acak.
- Simulasi socket TCP nyata KDC ↔ Alice ↔ Bob, balasan dua arah, dan pergantian session key.

## File utama dan pembagian presentasi

| File | Kegunaan yang perlu dijelaskan |
|---|---|
| `aes_manual.py` | AES-128, key schedule, 10 rounds, operasi invers |
| `crypto_utils.py` | CBC, IV, padding, ASCII, HEX |
| `kdc.py` | Key Distribution Center, dua master key, ticket, session key |
| `alice.py` | Pemintaan ke KDC, langkah 1–2–3–4–5, chat, `/rekey` |
| `bob.py` | Validasi ticket, challenge-response, penerima & pengirim chat |
| `protocol.py` | JSON di atas TCP, bukan AES |
| `tests/` | Bukti pengujian unit dan integrasi |

Saran alur demo: cek 3 IP → jalankan KDC → jalankan Bob → Wireshark capture → jalankan Alice → tunjukkan langkah 1–5 → kirim dua arah → tunjukkan ciphertext Hex di Wireshark → ubah session key di KDC dan ketik `/rekey` pada Alice → kirim lagi.

## Batasan dan integritas akademik

- **Sudah dibandingkan dengan diagram PPT dosen slide 13.** Struktur lima pesan dasar sesuai; pilihan CBC/IV/JSON/READY adalah detail implementasi tambahan, bukan tertulis eksplisit di slide.
- AES-CBC dengan IV acak memberikan kerahasiaan tetapi **tidak memberikan autentikasi/integritas ciphertext secara kuat**. Untuk produksi perlu AEAD seperti GCM atau mekanisme autentikasi terpisah; proyek ini menekankan implementasi **manual** sesuai tugas kelas.
- Penggunaan untuk latihan/demo saja, tidak aman untuk sistem produksi karena risiko side-channel/replay dan keterbatasan protokol klasik.
- Jangan asal mengumpulkan proyek tanpa memahami/menguji, menyesuaikan instruksi dosen, dan merekam kontribusi asli anggota di GitHub. `git commit` harus mencerminkan pekerjaan masing-masing anggota, jangan merekayasa authorship.
