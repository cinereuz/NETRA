import requests

# Daftar URL yang mau ditest
URL_TEST = [
    # # Harusnya AMAN
    # "https://sipadu.politala.ac.id/gate/login",
    # "https://siakad.ugm.ac.id/login",
    # "https://pajak.go.id/login",
    # "https://bpjs-kesehatan.go.id/account",
    # "https://github.com",
    # "https://kompas.com",

    # # Harusnya PHISHING
    # "http://paypal-secure-login.tk",
    # "http://bca-update-akun.xyz",
    # "http://verify-account.ml",
    # "http://192.168.1.1/login",
    # "http://login-bank.go.id/account",

    # # Harusnya JUDI_ONLINE
    # "https://slot-gacor-maxwin.xyz",
    # "http://togel-online-terpercaya.com",
    # "https://sbobet.com",
    # "http://mahjong-ways-scatter.online",

    # # Harusnya DOMAIN_TIDAK_ADA
    # "https://googgle.com",
    # "https://facebok.com",
    # "https://tokopedai.com",
    # "https://namakami123xyz.com",

    # # Harusnya TIDAK_DAPAT_DIAKSES
    # "https://192.0.2.1/test",

    # Test v2
    # Harusnya AMAN
    "https://google.com",
    "https://youtube.com",
    "https://tokopedia.com",
    "https://ui.ac.id",
    "https://ugm.ac.id",
    "https://kemenkeu.go.id",
    "https://www.detik.com/news/berita/polisi-tangkap-bandar-slot-gacor",
    "https://www.kompas.com/tren/read/2024/bahaya-judi-slot-online",
    "https://nasional.tempo.co/read/bahaya-judi-online-slot-gacor",

    # Harusnya Phishing
    "https://pajak.com",
    "https://bpjs.net",
    "https://kemendikbud.com",
    "http://192.168.1.1/login",
    "http://10.0.0.1/secure/banking",
    "http://user@evil-site.com/steal",
    "http://paypal-secure-login.com/verify",
    "http://bca-mobile-update.net/login",
    "http://mandiri-online-banking.xyz/masuk",

    # Harusnya Judi Online
    "http://slotgacor88win.xyz/daftar",
    "http://judionline-terpercaya.net/slot",
    "http://pragmaticplay-slot.com/login",

    # Harusnya Domain Tidak Ada
    "https://palsubanget.ac.id",
    "https://initidakada.go.id",
    "https://domainmati123.sch.id",
    "https://arnold.go.id",
    "https://website-yang-tidak-pernah-ada-sama-sekali-xyz123.com",
    "https://asjdhaksjdhaksjdh.net",

    # Harusnya Tidak Dapat Diakses
    "http://localhost:9999",

    # Sus
    "http://promo-tokopedia.net/flash-sale",
    "http://shopee-id-promo.com/voucher",
]

# Warna terminal untuk output lebih mudah dibaca
WARNA = {
    'aman'               : '\033[92m',  # hijau
    'phishing'           : '\033[91m',  # merah
    'judi_online'        : '\033[93m',  # kuning
    'suspicious'         : '\033[33m',  # oranye
    'domain_tidak_ada'   : '\033[90m',  # abu gelap
    'tidak_dapat_diakses': '\033[94m',  # biru
    'reset'              : '\033[0m',
}

ICON = {
    'aman'               : '🟢',
    'phishing'           : '🔴',
    'judi_online'        : '🟠',
    'suspicious'         : '🟡',
    'domain_tidak_ada'   : '⚫',
    'tidak_dapat_diakses': '🔵',
}

# Jalankan test untuk semua URL
print("\n" + "=" * 70)
print("  NETRA URL TEST")
print("=" * 70)

hasil_semua = []

for url in URL_TEST:
    try:
        response = requests.post(
            "http://localhost:5000/predict",
            json={"url": url},
            timeout=15,  # timeout 15 detik (lebih dari HTTP_TIMEOUT server)
        )
        hasil = response.json()

        kategori  = hasil.get('kategori', 'error')
        warna     = WARNA.get(kategori, '')
        icon      = ICON.get(kategori, '❓')
        reset     = WARNA['reset']

        print(f"\n{icon} URL      : {url}")
        print(f"   Kategori : {warna}{kategori.upper()}{reset}")
        print(f"   Confidence: {hasil.get('confidence', 0)}%")
        print(f"   Berbahaya : {hasil.get('berbahaya', '-')}")
        print(f"   Method    : {hasil.get('method', '-')}")
        print(f"   Reachable : {hasil.get('is_reachable', '-')} | HTTP {hasil.get('http_status', '-')}")
        print(f"   Detail    : {hasil.get('detail', '-')}")

        hasil_semua.append({
            'url'     : url,
            'kategori': kategori,
            'ok'      : True,
        })

    except requests.exceptions.ConnectionError:
        print(f"\n❌ URL: {url}")
        print(f"   ERROR: Tidak bisa connect ke server Flask!")
        print(f"   Pastikan server sudah jalan: python app.py")
        hasil_semua.append({'url': url, 'kategori': 'error', 'ok': False})

    except Exception as e:
        print(f"\n❌ URL: {url}")
        print(f"   ERROR: {str(e)}")
        hasil_semua.append({'url': url, 'kategori': 'error', 'ok': False})

# Ringkasan hasil
print("\n" + "=" * 70)
print("  RINGKASAN")
print("=" * 70)

from collections import Counter
counter = Counter(h['kategori'] for h in hasil_semua)

for kategori, jumlah in sorted(counter.items()):
    icon = ICON.get(kategori, '❓')
    print(f"  {icon} {kategori:<22}: {jumlah} URL")

total_error = sum(1 for h in hasil_semua if not h['ok'])
print(f"\n  Total ditest : {len(URL_TEST)} URL")
if total_error:
    print(f"  ❌ Error     : {total_error} URL (server tidak bisa diakses)")
print("=" * 70 + "\n")