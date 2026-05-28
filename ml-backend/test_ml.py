# test_ml_murni.py
# Tujuan: test model ML secara murni tanpa reachability check
# Langsung inject fitur ke _prediksi_supervised() dan _prediksi_isolation_forest()

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from utils.predictor import predictor
from utils.feature_extractor import extract_features

# ============================================================
# Fungsi helper: test ML langsung tanpa HTTP check
# ============================================================
def test_ml_langsung(label, url):
    """
    Bypass semua layer rule-based dan reachability.
    Langsung ekstrak fitur dari URL, kirim ke ML.
    """
    features = extract_features(url)

    # Panggil supervised ML langsung
    label_angka, confidence, proba = predictor._prediksi_supervised(features)
    kategori = predictor.LABEL_MAP[label_angka]

    # Panggil Isolation Forest langsung
    is_anomali, skor_raw, if_score = predictor._prediksi_isolation_forest(features)

    status = "✅ BENAR" if kategori == label else f"❌ SALAH (harusnya {label})"

    print(f"\n{'='*60}")
    print(f"  URL      : {url}")
    print(f"  Ekspektasi: {label.upper()}")
    print(f"  ML Hasil  : {kategori.upper()} ({confidence:.1f}%)")
    print(f"  Status    : {status}")
    print(f"  Prob      : aman={proba[0]:.2f} phishing={proba[1]:.2f} judi={proba[2]:.2f}")
    print(f"  IF Anomali: {is_anomali} | IF Score: {if_score:.1f}")

print("\n" + "="*60)
print("  TEST ML MURNI — Tanpa Whitelist & Reachability Check")
print("="*60)

# ============================================================
# Kelompok 1: URL judi online (struktur khas judol Indonesia)
# ============================================================
print("\n--- Judol: Pola domain khas ---")

# Ciri khas domain judol: nama slot + angka + TLD murah
test_ml_langsung('judi_online', 'http://slot88gacor.xyz/daftar')
test_ml_langsung('judi_online', 'http://pragmatic-win999.net/login')
test_ml_langsung('judi_online', 'http://maxwin-slot-gacor.com/register')
test_ml_langsung('judi_online', 'http://togel4d-resmi.net/pasang')
test_ml_langsung('judi_online', 'http://poker99indo.xyz/bonus')

print("\n--- Judol: Subdomain panjang ---")
# Subdomain panjang + path daftar/login = ciri khas judol
test_ml_langsung('judi_online', 'http://daftar.slot-gacor-maxwin.com/member/login')
test_ml_langsung('judi_online', 'http://link.alternatif-sbobet88.net/daftar-sekarang')

# ============================================================
# Kelompok 2: Phishing (meniru bank/layanan Indonesia)
# ============================================================
print("\n--- Phishing: Meniru bank Indonesia ---")

test_ml_langsung('phishing', 'http://bca-verifikasi-akun.com/login')
test_ml_langsung('phishing', 'http://mandiri-internet-banking-update.net/masuk')
test_ml_langsung('phishing', 'http://bri-mobile-notifikasi.xyz/konfirmasi')
test_ml_langsung('phishing', 'http://konfirmasi-bni-mobile.com/secure/verify')

print("\n--- Phishing: Meniru layanan pemerintah ---")
test_ml_langsung('phishing', 'http://bpjs-kesehatan-login.com/daftar')
test_ml_langsung('phishing', 'http://nik-ktp-verifikasi-dukcapil.net/cek')

print("\n--- Phishing: Subdomain menipu ---")
test_ml_langsung('phishing', 'http://secure.paypal.com.login-verify.xyz/account')
test_ml_langsung('phishing', 'http://m.tokopedia.com.update-data.net/masuk')

# ============================================================
# Kelompok 3: AMAN — Web berita dengan keyword judol di URL
# Ini test inti: ML harus tahu ini bukan situs judol
# ============================================================
print("\n--- Aman: Web berita keyword judol di URL (false positive test) ---")

test_ml_langsung('aman', 'https://kumparan.com/berita/polisi-tangkap-bandar-judol-slot-gacor')
test_ml_langsung('aman', 'https://tribunnews.com/nasional/2024/bahaya-judi-online-slot')
test_ml_langsung('aman', 'https://cnnindonesia.com/nasional/pemberantasan-judi-online-poker')

print("\n--- Aman: Website legitimate biasa ---")
test_ml_langsung('aman', 'https://tokopedia.com/product/kaos-polos-murah')
test_ml_langsung('aman', 'https://shopee.co.id/product/123456789')
test_ml_langsung('aman', 'https://bca.co.id/id/informasi/kurs')

print("\n")
print("="*60)
print("  Selesai. Cek kolom 'Status' di atas.")
print("  ✅ = ML benar | ❌ = ML salah (perlu retrain atau tuning)")
print("="*60)