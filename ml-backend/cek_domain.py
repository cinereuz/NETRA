# cek_domain.py — update untuk test typosquatting
from utils.predictor import predictor

print("=" * 55)
print("TEST TYPOSQUATTING DETECTION — Layer 1G")
print("=" * 55)

# Harus terdeteksi PHISHING via typosquatting
phishing_urls = [
    'http://googgle.com',       # mirip google
    'http://paypa1.com',        # mirip paypal  
    'http://tokopedla.com',     # mirip tokopedia
    'http://facebok.com',       # mirip facebook
    'http://mandiri-bank.com',  # mirip mandiri
    'http://bcaa.co.id',        # mirip bca
]

print("\n🔴 Harus PHISHING (typosquatting):")
for url in phishing_urls:
    h = predictor.predict(url)
    status = "✅" if h["kategori"] == "phishing" else "❌"
    print(f'  {status} {h["kategori"]:10} {h["confidence"]:5}%  {url}')
    if h["method"] == "rule_based_typosquatting":
        print(f'       └─ {h["detail"]}')

print("\n🟢 Harus AMAN (domain asli):")
aman_urls = [
    'http://google.com',
    'http://tokopedia.com',
    'http://facebook.com',
    'https://mandiri.co.id',
    'https://bca.co.id',
]
for url in aman_urls:
    h = predictor.predict(url)
    status = "✅" if h["kategori"] == "aman" else "❌"
    print(f'  {status} {h["kategori"]:10} {h["confidence"]:5}%  {url}')