import joblib
import os
import re
import numpy as np
from .feature_extractor import extract_features

BASE_DIR   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODELS_DIR = os.path.join(BASE_DIR, 'models')

# LAYER 1: RULE-BASED

WHITELIST = {
    # International
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
    'twitter.com', 'x.com', 'wikipedia.org', 'github.com',
    'tokopedia.com', 'shopee.co.id', 'gojek.com', 'grab.com',
    'bca.co.id', 'mandiri.co.id', 'bni.co.id', 'bri.co.id',

    # Media & berita
    'detik.com', 'kompas.com', 'tribunnews.com', 'liputan6.com',
    'cnnindonesia.com', 'tempo.co', 'okezone.com', 'republika.co.id',
    'antaranews.com', 'kumparan.com', 'tirto.id', 'idntimes.com',

    # Edukasi
    'skilvul.com', 'dicoding.com', 'zenius.net', 'ruangguru.com',
    'coursera.org', 'udemy.com', 'khan academy.org', 'https://sipadu.politala.ac.id/',

    # E-commerce Indonesia
    'bukalapak.com', 'lazada.co.id', 'blibli.com', 'zalora.co.id',
    'jd.id', 'orami.co.id',

    # Fintech & bank Indonesia
    'ovo.id', 'dana.id', 'linkaja.id', 'jenius.com', 'gopay.co.id',
    'cimbniaga.co.id', 'permatabank.com', 'danamon.co.id',

    # Pemerintah Indonesia (.go.id)
    'kominfo.go.id', 'kemdikbud.go.id', 'bssn.go.id',
    'kemenkeu.go.id', 'pajak.go.id', 'bpjs-kesehatan.go.id',
    'polri.go.id', 'kpu.go.id',
}

BLACKLIST = {
    'sbobet.com', 'rgobet.com', '188bet.com',
}

GAMBLING_REGEX = re.compile(
    r'(slot[-_]?gacor|togel|sbobet|casino|poker[-_]?online|'
    r'judi[-_]?online|maxwin|scatter[-_]?hitam|rtp[-_]?live|'
    r'bandar[-_]?bola|agen[-_]?slot|bonus[-_]?new[-_]?member)',
    re.IGNORECASE
)

PHISHING_REGEX = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'@|'
    r'[a-z0-9]{20,}\.(xyz|tk|ml|ga|cf|gq))',
    re.IGNORECASE
)

# THRESHOLD CONFIDENCE
CONFIDENCE_THRESHOLD = 70.0

IF_ANOMALY_BOOST = 15.0


class NetraPredictor:
    LABEL_MAP = {0: 'aman', 1: 'phishing', 2: 'judi_online'}
    COLOR_MAP = {
        'aman':        '#22c55e',
        'phishing':    '#ef4444',
        'judi_online': '#f97316'
    }

    FEATURE_COLUMNS = [
        'url_length', 'has_https', 'dot_count', 'hyphen_count',
        'at_count', 'double_slash', 'digit_count', 'domain_length',
        'path_depth', 'has_query', 'has_suspicious_tld', 'has_ip',
        'has_phishing_keyword', 'has_gambling_keyword', 'has_brand_spoofing',
        'subdomain_length', 'subdomain_count', 'domain_entropy',
        'special_chars', 'path_length'
    ]

    def __init__(self):
        print("Loading NETRA models v2.0...")
        self._load_supervised()
        self._load_unsupervised()

    def _load_supervised(self):
        try:
            self.hybrid_model = joblib.load(
                os.path.join(MODELS_DIR, 'hybrid_model.pkl')
            )
            self.supervised_loaded = True
            print("  ✅ Supervised model (Hybrid RF+LR) loaded!")
        except FileNotFoundError:
            print("  ⚠️  Supervised model tidak ditemukan!")
            self.supervised_loaded = False

    def _load_unsupervised(self):
        try:
            self.iso_forest = joblib.load(
                os.path.join(MODELS_DIR, 'isolation_forest.pkl')
            )
            self.scaler_if  = joblib.load(
                os.path.join(MODELS_DIR, 'scaler_isolation.pkl')
            )
            self.unsupervised_loaded = True
            print("  ✅ Unsupervised model (Isolation Forest) loaded!")
        except FileNotFoundError:
            print("  ⚠️  Isolation Forest tidak ditemukan!")
            self.unsupervised_loaded = False

    # LAYER 1: Cek Rule-Based
    def _cek_whitelist(self, url):
        url_lower = url.lower()
        return any(domain in url_lower for domain in WHITELIST)

    def _cek_blacklist(self, url):
        url_lower = url.lower()
        return any(domain in url_lower for domain in BLACKLIST)

    # LAYER 2: Supervised ML
    def _prediksi_supervised(self, features_dict):
        features_values = [[features_dict[col] for col in self.FEATURE_COLUMNS]]

        label_angka = self.hybrid_model.predict(features_values)[0]
        proba       = self.hybrid_model.predict_proba(features_values)[0]
        confidence  = float(proba[label_angka]) * 100

        return int(label_angka), confidence, proba

    # LAYER 3: Isolation Forest (Unsupervised)
    def _prediksi_isolation_forest(self, features_dict):
        if not self.unsupervised_loaded:
            return False, 0.0, 0.0

        fitur_array = np.array([[features_dict[col] for col in self.FEATURE_COLUMNS]])

        fitur_scaled = self.scaler_if.transform(fitur_array)

        # Prediksi: -1 = anomali, +1 = normal
        prediksi = self.iso_forest.predict(fitur_scaled)[0]

        # Raw anomaly score
        # Semakin negatif = semakin anomali
        skor_raw = self.iso_forest.score_samples(fitur_scaled)[0]

        # Normalisasi skor ke 0-100
        skor_clipped = np.clip(skor_raw, -0.5, 0.1)
        # Map: -0.5 → 100 (sangat anomali), 0.1 → 0 (sangat normal)
        skor_normal  = (0.1 - skor_clipped) / (0.1 - (-0.5)) * 100
        skor_normal  = round(float(skor_normal), 1)

        is_anomali = (prediksi == -1)

        return is_anomali, float(skor_raw), skor_normal

    # FUNGSI UTAMA: PREDICT
    def predict(self, url):

        # Validasi & normalisasi
        if not url or not isinstance(url, str):
            return self._format('aman', 50.0, 'error',
                                'URL tidak valid', False, 0)

        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Layer 1A: Whitelist
        if self._cek_whitelist(url):
            return self._format(
                kategori   = 'aman',
                confidence = 99.0,
                method     = 'rule_based_whitelist',
                detail     = 'Domain terpercaya (whitelist)',
                is_anomali = False,
                if_score   = 0
            )

        # Layer 1B: Blacklist
        if self._cek_blacklist(url):
            return self._format(
                kategori   = 'judi_online',
                confidence = 99.0,
                method     = 'rule_based_blacklist',
                detail     = 'Domain terblokir (blacklist)',
                is_anomali = True,
                if_score   = 100
            )

        # Layer 1C: Regex Judi
        match_judi = GAMBLING_REGEX.search(url)
        if match_judi:
            return self._format(
                kategori   = 'judi_online',
                confidence = 95.0,
                method     = 'rule_based_regex',
                detail     = f'Keyword judi: "{match_judi.group()}"',
                is_anomali = True,
                if_score   = 90
            )

        # Layer 1D: Regex Phishing
        match_phish = PHISHING_REGEX.search(url)
        if match_phish:
            return self._format(
                kategori   = 'phishing',
                confidence = 92.0,
                method     = 'rule_based_regex',
                detail     = 'Pola phishing terdeteksi',
                is_anomali = True,
                if_score   = 88
            )

        # Ekstrak fitur
        features_dict = extract_features(url)

        # Layer 2: Supervised ML
        if not self.supervised_loaded:
            return self._format('aman', 50.0, 'fallback',
                                'Model tidak tersedia', False, 0)

        label_angka, confidence_sv, proba = self._prediksi_supervised(features_dict)
        kategori = self.LABEL_MAP[label_angka]

        # Layer 3: Isolation Forest
        if_aktif   = False
        is_anomali = False
        if_score   = 0.0
        if_detail  = ''

        if confidence_sv < CONFIDENCE_THRESHOLD and self.unsupervised_loaded:
            if_aktif             = True
            is_anomali, skor_raw, if_score = self._prediksi_isolation_forest(features_dict)

            if is_anomali:
                if kategori == 'aman':
                    kategori   = 'phishing'
                    confidence_sv = 50.0 + (if_score * 0.3)
                    if_detail  = f'IF override: URL anomali (score: {if_score:.0f})'
                else:
                    confidence_sv = min(confidence_sv + IF_ANOMALY_BOOST, 98.0)
                    if_detail  = f'IF konfirmasi anomali (score: {if_score:.0f})'
            else:
                if kategori != 'aman':
                    confidence_sv = max(confidence_sv - 10.0, 51.0)
                    if_detail  = f'IF: URL terlihat normal (score: {if_score:.0f})'
                else:
                    if_detail  = f'IF: normal (score: {if_score:.0f})'

        if if_aktif:
            method = 'hybrid_supervised_unsupervised'
        else:
            method = 'ml_supervised_only'

        detail = f'RF+LR Ensemble | Prob: {proba.round(2).tolist()}'
        if if_detail:
            detail += f' | {if_detail}'

        return self._format(
            kategori   = kategori,
            confidence = confidence_sv,
            method     = method,
            detail     = detail,
            is_anomali = is_anomali,
            if_score   = if_score
        )

    # FORMAT RESPONSE
    def _format(self, kategori, confidence, method, detail='',
                is_anomali=False, if_score=0.0):
        return {
            'kategori'        : kategori,
            'confidence'      : round(confidence, 1),
            'berbahaya'       : kategori != 'aman',
            'warna'           : self.COLOR_MAP.get(kategori, '#6b7280'),
            'method'          : method,
            'detail'          : detail,
            'is_anomali'      : is_anomali,
            'anomaly_score'   : round(if_score, 1) # 0-100, semakin tinggi = semakin mencurigakan
        }

predictor = NetraPredictor()