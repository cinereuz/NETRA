import joblib
import os
import re
import json
from pathlib import Path
import numpy as np
from .feature_extractor import extract_features

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / 'models'
CONFIG_PATH = BASE_DIR / 'data' / 'config.json'

# Load Configuration
with open(CONFIG_PATH, 'r') as f:
    config_data = json.load(f)

# LAYER 1: RULE-BASED & REGEX
WHITELIST = set(config_data['DOMAINS']['WHITELIST'])
BLACKLIST = set(config_data['DOMAINS']['BLACKLIST'])
MULTI_LEVEL_TLDS = set(config_data['DOMAINS']['MULTI_LEVEL_TLDS'])

GAMBLING_REGEX = re.compile(config_data['REGEX_PATTERNS']['GAMBLING'], re.IGNORECASE)
PHISHING_REGEX = re.compile(config_data['REGEX_PATTERNS']['PHISHING'], re.IGNORECASE)

# THRESHOLD & KONSTANTA
CONFIDENCE_THRESHOLD = config_data['THRESHOLDS']['CONFIDENCE']
IF_ANOMALY_BOOST = config_data['THRESHOLDS']['IF_ANOMALY_BOOST']
IF_OVERRIDE_THRESHOLD = config_data['THRESHOLDS']['IF_OVERRIDE']

class NetraPredictor:
    LABEL_MAP = {0: 'aman', 1: 'phishing', 2: 'judi_online'}

    COLOR_MAP = {
        'aman':        '#22c55e',
        'phishing':    '#ef4444',
        'judi_online': '#f97316',
        'suspicious':  '#f59e0b',
    }

    FEATURE_COLUMNS = [
        'url_length', 'has_https', 'dot_count', 'hyphen_count',
        'at_count', 'double_slash', 'digit_count', 'domain_length',
        'path_depth', 'has_query', 'has_suspicious_tld', 'has_ip',
        'has_phishing_keyword', 'has_gambling_keyword', 'has_brand_spoofing',
        'subdomain_length', 'subdomain_count', 'domain_entropy',
        'special_chars', 'path_length', 'digit_ratio_url', 'has_port', 'has_redirect', 
        'consonant_ratio', 'query_length', 'query_params', 'has_fragment'
    ]

    def __init__(self):
        print("Loading NETRA models v2.1 (fixed)...")
        self._load_supervised()
        self._load_unsupervised()

    def _load_supervised(self):
        # Load model supervised (Hybrid RF+LR)
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
        # Load model unsupervised (Isolation Forest)
        try:
            self.iso_forest = joblib.load(
                os.path.join(MODELS_DIR, 'isolation_forest.pkl')
            )
            self.scaler_if = joblib.load(
                os.path.join(MODELS_DIR, 'scaler_isolation.pkl')
            )
            self.unsupervised_loaded = True
            print("  ✅ Unsupervised model (Isolation Forest) loaded!")
        except FileNotFoundError:
            print("  ⚠️  Isolation Forest tidak ditemukan!")
            self.unsupervised_loaded = False

    # LAYER 1: Rule-Based
    def _cek_whitelist(self, url):
        url_lower = url.lower()
        return any(domain in url_lower for domain in WHITELIST)

    def _cek_blacklist(self, url):
        url_lower = url.lower()
        return any(domain in url_lower for domain in BLACKLIST)

    def _ekstrak_domain_utama(self, url):
        try:
            from urllib.parse import urlparse
            parsed   = urlparse(url)
            hostname = parsed.netloc.lower().replace('www.', '')
 
            if ':' in hostname:
                hostname = hostname.split(':')[0]
 
            parts = hostname.split('.')
 
            if len(parts) >= 3:
                kemungkinan_tld2 = parts[-2] + '.' + parts[-1]
                if kemungkinan_tld2 in MULTI_LEVEL_TLDS:
                    return parts[-3] + '.' + kemungkinan_tld2
                else:
                    return parts[-2] + '.' + parts[-1]
 
            elif len(parts) == 2:
                return hostname
 
            return hostname
 
        except Exception:
            return ''

    # LAYER 2: Supervised ML
    def _prediksi_supervised(self, features_dict):
        features_values = [[features_dict[col] for col in self.FEATURE_COLUMNS]]

        # predict() → angka label (0, 1, atau 2)
        label_angka = self.hybrid_model.predict(features_values)[0]

        # predict_proba() → array probabilitas
        # Index 0=aman, 1=phishing, 2=judi_online
        proba = self.hybrid_model.predict_proba(features_values)[0]

        # Confidence = probabilitas label yang dipilih × 100
        confidence = float(proba[label_angka]) * 100

        return int(label_angka), confidence, proba

    # LAYER 3: Isolation Forest
    def _prediksi_isolation_forest(self, features_dict):
        if not self.unsupervised_loaded:
            return False, 0.0, 0.0

        fitur_array  = np.array([[features_dict[col] for col in self.FEATURE_COLUMNS]])
        fitur_scaled = self.scaler_if.transform(fitur_array)

        # predict(): -1 = anomali (mencurigakan), +1 = normal
        prediksi = self.iso_forest.predict(fitur_scaled)[0]

        # score_samples(): semakin negatif = semakin anomali
        skor_raw = self.iso_forest.score_samples(fitur_scaled)[0]

        # Normalisasi skor ke rentang 0-100
        # -0.5 → 100 (sangat anomali), 0.1 → 0 (sangat normal)
        skor_clipped = np.clip(skor_raw, -0.5, 0.1)
        skor_normal  = (0.1 - skor_clipped) / (0.1 - (-0.5)) * 100
        skor_normal  = round(float(skor_normal), 1)

        is_anomali = (prediksi == -1)

        return is_anomali, float(skor_raw), skor_normal

    # FUNGSI UTAMA
    def predict(self, url):
        # Validasi input
        if not url or not isinstance(url, str):
            return self._format('aman', 50.0, 'error',
                                'URL tidak valid', False, 0)

        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Layer 1A: Whitelist
        domain_utama = self._ekstrak_domain_utama(url)
        if domain_utama in WHITELIST or self._cek_whitelist(url):
            return self._format(
                kategori   = 'aman',
                confidence = 99.0,
                method     = 'rule_based_whitelist',
                detail     = f'Domain terpercaya: {domain_utama}',
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
                detail     = f'Keyword judi terdeteksi: "{match_judi.group()}"',
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
                detail     = 'Pola phishing kritis terdeteksi (IP/simbol @)',
                is_anomali = True,
                if_score   = 88
            )

        # Layer 2: Supervised ML
        # Ekstrak fitur URL untuk ML
        features_dict = extract_features(url)

        if not self.supervised_loaded:
            return self._format(
                'aman', 50.0, 'fallback',
                'Model tidak tersedia, tidak bisa memverifikasi', False, 0
            )

        label_angka, confidence_sv, proba = self._prediksi_supervised(features_dict)
        kategori = self.LABEL_MAP[label_angka]

        # Layer 3: Isolation Forest
        is_anomali = False
        if_score   = 0.0
        if_aktif   = False
        if_detail  = ''

        if confidence_sv < CONFIDENCE_THRESHOLD and self.unsupervised_loaded:
            if_aktif   = True
            is_anomali, skor_raw, if_score = self._prediksi_isolation_forest(features_dict)

            if is_anomali:
                if kategori == 'aman':
                    if if_score > IF_OVERRIDE_THRESHOLD:
                        kategori      = 'suspicious'
                        confidence_sv = 45.0
                        if_detail     = (f'IF: anomali tinggi (score: {if_score:.0f}), '
                                         f'perlu verifikasi manual')
                    else:
                        if_detail = (f'IF: sedikit anomali (score: {if_score:.0f}), '
                                     f'tidak cukup untuk override → tetap aman')

                else:
                    confidence_sv = min(confidence_sv + IF_ANOMALY_BOOST, 95.0)
                    if_detail     = f'IF konfirmasi: anomali (score: {if_score:.0f})'

            else:
                if kategori != 'aman':
                    confidence_sv = max(confidence_sv - 15.0, 45.0)
                    if_detail     = f'IF: URL terlihat normal (score: {if_score:.0f}), confidence diturunkan'
                else:
                    if_detail = f'IF: normal (score: {if_score:.0f})'

        if if_aktif:
            method = 'hybrid_supervised_unsupervised'
        else:
            method = 'ml_supervised_only'

        # Detail log untuk debugging
        detail = f'RF+LR Ensemble | Prob aman:{proba[0]:.2f} phishing:{proba[1]:.2f} judi:{proba[2]:.2f}'
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

    def _format(self, kategori, confidence, method, detail='',
                is_anomali=False, if_score=0.0):
        berbahaya = kategori in ('phishing', 'judi_online')

        return {
            'kategori'     : kategori,
            'confidence'   : round(confidence, 1),
            'berbahaya'    : berbahaya,
            'warna'        : self.COLOR_MAP.get(kategori, '#6b7280'),
            'method'       : method,
            'detail'       : detail,
            'is_anomali'   : is_anomali,
            'anomaly_score': round(if_score, 1),
        }


predictor = NetraPredictor()