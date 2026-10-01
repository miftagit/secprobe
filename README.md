# SecProbe

**CLI scanner berbasis Python untuk mengevaluasi keamanan website berdasarkan OWASP Top 10.**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-2f7d32?style=for-the-badge)
![Use](https://img.shields.io/badge/Use-Authorized%20Testing%20Only-d46a6a?style=for-the-badge)

## Demo

<!-- Ganti dengan GIF/screenshot hasil scan kamu, taruh di folder assets/ -->
![SecProbe demo](assets/demo.gif)

## Overview

SecProbe adalah tools command-line untuk menguji website terhadap kategori OWASP Top 10. Kamu bisa scan semua modul sekaligus atau pilih modul tertentu, lalu simpan hasilnya ke file laporan.

## Features

- Scan berdasarkan modul OWASP Top 10 (contoh: `A02`, `A06`)
- Bisa scan semua modul atau hanya modul yang dipilih
- Output berwarna di terminal (colorama)
- Simpan hasil scan ke file laporan `.txt`

## Responsible Use

Gunakan SecProbe hanya pada website milik sendiri atau yang kamu punya izin tertulis untuk diuji. Scanning tanpa izin bisa melanggar hukum dan kebijakan penggunaan yang berlaku.

Untuk latihan, kamu bisa pakai situs demo yang memang sengaja dibuat rentan: `https://demo.testfire.net`

## Instalasi

1. Install [Python 3.10+](https://www.python.org/downloads/)
2. Clone repo dan install library:

```bash
git clone https://github.com/USERNAME_KAMU/secprobe.git
cd secprobe
pip install -r requirements.txt
```

## Penggunaan

Scan semua modul:

```bash
python secprobe.py --url https://demo.testfire.net
```

Scan modul tertentu:

```bash
python secprobe.py --url https://demo.testfire.net --modul A02 A06
```

Scan dan simpan laporan:

```bash
python secprobe.py --url https://demo.testfire.net --output laporan.txt
```

### Opsi

| Opsi       | Fungsi                                            |
| ---------- | ------------------------------------------------- |
| `--url`    | URL target yang akan di-scan                      |
| `--modul`  | Pilih modul OWASP tertentu (opsional, bisa lebih dari satu) |
| `--output` | Simpan hasil scan ke file (opsional)              |

## Troubleshooting

### `ModuleNotFoundError: No module named 'requests'`
Library belum terinstall. Jalankan:

```bash
pip install -r requirements.txt
```

### `python` tidak dikenali
Coba pakai `python3 secprobe.py ...` atau pastikan Python sudah masuk ke PATH.

## License

Dirilis dengan lisensi MIT. Lihat file [LICENSE](LICENSE).

## Author

Tools by Miftah
