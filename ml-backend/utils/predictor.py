import joblib
import os
import re
import json
import urllib.request
import urllib.error  
import socket
from pathlib import Path
import numpy as np
import sqlite3
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
LEGITIMATE_TLDS  = set(config_data['DOMAINS']['LEGITIMATE_TLDS'])
TRUSTED_DOMAINS = set()

GAMBLING_REGEX = re.compile(config_data['REGEX_PATTERNS']['GAMBLING'], re.IGNORECASE)
PHISHING_REGEX = re.compile(config_data['REGEX_PATTERNS']['PHISHING'], re.IGNORECASE)

# THRESHOLD & KONSTANTA
CONFIDENCE_THRESHOLD = config_data['THRESHOLDS']['CONFIDENCE']
IF_ANOMALY_BOOST = config_data['THRESHOLDS']['IF_ANOMALY_BOOST']
IF_OVERRIDE_THRESHOLD = config_data['THRESHOLDS']['IF_OVERRIDE']

# HTTP Check
# Timeout (berapa lama tunggu server merespons)
HTTP_TIMEOUT = 8
 
# Status code
HTTP_BLOCKED_BUT_ALIVE = {401, 403, 405, 406, 429}
 
# User-Agent
HTTP_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; NETRA-URLChecker/1.0)',
}

# BRAND + TLD MISMATCH
GOV_BRANDS      = set(config_data['BRAND_TLD_RULES']['GOV_BRANDS'])
BUSINESS_BRANDS = set(config_data['BRAND_TLD_RULES']['BUSINESS_BRANDS'])

class NetraPredictor:
    LABEL_MAP = {0: 'aman', 1: 'phishing', 2: 'judi_online'}

    COLOR_MAP = {
        'aman':        '#22c55e',
        'phishing':    '#ef4444',
        'judi_online': '#f97316',
        'suspicious':  '#f59e0b',
        'domain_tidak_ada'    : '#374151',
        'tidak_dapat_diakses': '#6b7280',
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
        print("Loading NETRA models ...")
        self._load_supervised()
        self._load_unsupervised()
        global TRUSTED_DOMAINS
        TRUSTED_DOMAINS = self._load_trusted_domains()

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
        
    def _cek_brand_tld_mismatch(self, url):
        try:
            from urllib.parse import urlparse
            parsed   = urlparse(url)
            hostname = parsed.netloc.lower().replace('www.', '')
            if ':' in hostname:
                hostname = hostname.split(':')[0]
            parts = hostname.split('.')

            if len(parts) >= 3:
                tld2 = parts[-2] + '.' + parts[-1]
                if tld2 in MULTI_LEVEL_TLDS:
                    tld       = tld2
                    domain    = parts[-3].lower()
                    subdomain = '.'.join(parts[:-3]).lower()
                else:
                    tld       = parts[-1].lower()
                    domain    = parts[-2].lower()
                    subdomain = '.'.join(parts[:-2]).lower()
            elif len(parts) == 2:
                tld       = parts[-1].lower()
                domain    = parts[-2].lower()
                subdomain = ''
            else:
                return False, ''

            # Cek brand pemerintah — wajib .go.id
            for brand in GOV_BRANDS:
                if brand in domain or brand in subdomain:
                    if tld != 'go.id':
                        return True, (
                            f'Brand pemerintah \'{brand}\' seharusnya .go.id, '
                            f'bukan .{tld} (Regulasi PANDI)'
                        )

            # Cek brand badan usaha
            for brand in BUSINESS_BRANDS:
                if brand == domain:
                    if tld not in ('co.id'):
                        return True, (
                            f'Brand badan usaha \'{brand}\' seharusnya .co.id, '
                            f'bukan .{tld} (Regulasi PANDI)'
                        )

            return False, ''

        except Exception:
            return False, ''
        
    def _cek_pandi_tld(self, url):
        PANDI_VERIFIED = {'ac.id', 'go.id', 'sch.id', 'mil.id'}

        try:
            domain_utama = self._ekstrak_domain_utama(url)
            for tld in PANDI_VERIFIED:
                if domain_utama.endswith('.' + tld):
                    return True, tld
            return False, ''
        
        except Exception:
            return False, ''

    # LAYER 2: HTTP Reachability Check
    def _cek_reachability(self, url):
        try:
            req = urllib.request.Request(
                url,
                headers=HTTP_HEADERS,
                method='HEAD',
            )
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                # Server merespons sukses
                return {
                    'is_reachable': True,
                    'http_status' : resp.status,
                    'reachability': 'reachable',
                    'reach_detail': f'Server aktif (HTTP {resp.status})',
                    'kategori_reach': None,
                }
 
        except urllib.error.HTTPError as e:
            # Server ADA dan merespons, tapi dengan kode error
            return {
                'is_reachable': True,
                'http_status' : e.code,
                'reachability': 'reachable',
                'reach_detail': f'Server aktif (HTTP {e.code})',
                'kategori_reach': None,
            }
 
        except socket.timeout:
            # Server tidak merespons
            return {
                'is_reachable': False,
                'http_status' : None,
                'reachability': 'timeout',
                'reach_detail': f'Server tidak merespons (timeout {HTTP_TIMEOUT}s)',
                'kategori_reach': 'tidak_dapat_diakses',
            }
 
        except urllib.error.URLError:
            # DNS gagal resolve = domain tidak terdaftar / tidak ada
            return {
                'is_reachable': False,
                'http_status' : None,
                'reachability': 'unreachable',
                'reach_detail': 'Domain tidak terdaftar atau tidak ditemukan',
                'kategori_reach': 'domain_tidak_ada',
            }
 
        except Exception as e:
            return {
                'is_reachable': False,
                'http_status' : None,
                'reachability': 'error',
                'reach_detail': f'Gagal memeriksa: {str(e)[:60]}',
                'kategori_reach': 'tidak_dapat_diakses',
            }

    # LAYER 3: Supervised ML
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

    # LAYER 4: Isolation Forest
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
            return self._format(
                kategori   = 'tidak_dapat_diakses',
                confidence = 0.0,
                method     = 'error',
                detail     = 'URL tidak valid',
                is_anomali = False,
                if_score   = 0,
                reach_info = None,
            )

        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)

        path_bersih = parsed.path if parsed.path != '/' else ''

        url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            path_bersih,
            parsed.params,
            parsed.query,
            parsed.fragment
        ))

        # Layer 1A: Whitelist
        domain_utama = self._ekstrak_domain_utama(url)
        if domain_utama in WHITELIST or self._cek_whitelist(url):
            return self._format(
                kategori   = 'aman',
                confidence = 99.0,
                method     = 'rule_based_whitelist',
                detail     = f'Domain terpercaya: {domain_utama}',
                is_anomali = False,
                if_score   = 0,
                reach_info = None,
            )
        # Trusted Domain (false positive terverifikasi)
        domain_cek = self._ekstrak_domain_utama(url)
        if domain_cek in TRUSTED_DOMAINS:
            return self._format(
                kategori   = 'aman',
                confidence = 85.0,
                method     = 'trusted_domain_verified',
                detail     = f'Domain {domain_cek} diverifikasi aman oleh komunitas pengguna',
                is_anomali = False,
                if_score   = 0,
                reach_info = None,
            )

        # Layer 1B: Blacklist
        if self._cek_blacklist(url):
            return self._format(
                kategori   = 'judi_online',
                confidence = 99.0,
                method     = 'rule_based_blacklist',
                detail     = 'Domain terblokir (blacklist)',
                is_anomali = True,
                if_score   = 100,
                reach_info = None,
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
                if_score   = 90,
                reach_info = None,
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
                if_score   = 88,
                reach_info = None,
            )

        # Layer 1E: Brand + TLD Mismatch
        is_mismatch, mismatch_detail = self._cek_brand_tld_mismatch(url)
        if is_mismatch:
            return self._format(
                kategori   = 'phishing',
                confidence = 95.0,
                method     = 'rule_based_brand_tld',
                detail     = mismatch_detail,
                is_anomali = True,
                if_score   = 85,
                reach_info = None,
            )
        
        # Layer 1F: TLD Resmi PANDI
        is_pandi_safe, pandi_tld = self._cek_pandi_tld(url)
        if is_pandi_safe:
            return self._format(
                kategori   = 'aman',
                confidence = 97.0,
                method     = 'rule_based_pandi_tld',
                detail     = (f'Domain .{pandi_tld} diverifikasi PANDI — '
                              f'tidak bisa didaftarkan sembarang pihak'),
                is_anomali = False,
                if_score   = 0,
                reach_info = None,
            )
        
        # Layer 2: HTTP Reachability Check
        reach_info = self._cek_reachability(url)
 
        if not reach_info['is_reachable']:
            return self._format(
                kategori   = reach_info['kategori_reach'],
                confidence = 0.0,
                method     = 'http_check',
                detail     = reach_info['reach_detail'],
                is_anomali = False,
                if_score   = 0,
                reach_info = reach_info,
            )

        # Layer 3: Supervised ML
        # Ekstrak fitur URL untuk ML
        features_dict = extract_features(url)

        if not self.supervised_loaded:
            return self._format(
                kategori   = 'tidak_dapat_diakses',
                confidence = 50.0,
                method     = 'fallback',
                detail     = 'Model tidak tersedia',
                is_anomali = False,
                if_score   = 0,
                reach_info = reach_info,
            )

        label_angka, confidence_sv, proba = self._prediksi_supervised(features_dict)
        kategori = self.LABEL_MAP[label_angka]

        # Layer 4: Isolation Forest
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
                    if confidence_sv < CONFIDENCE_THRESHOLD:
                            kategori  = 'suspicious'
                            if_detail = (f'IF: URL terlihat normal (score: {if_score:.0f}), '
                                        f'confidence {confidence_sv:.1f}% < threshold '
                                        f'→ turun ke suspicious')
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
            if_score   = if_score,
            reach_info = reach_info,
        )

    def _format(self, kategori, confidence, method, detail='',
                is_anomali=False, if_score=0.0, reach_info=None):
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
            'is_reachable' : reach_info['is_reachable'] if reach_info else None,
            'http_status'  : reach_info['http_status']  if reach_info else None,
            'reachability' : reach_info['reachability'] if reach_info else 'skipped',
            'reach_detail' : reach_info['reach_detail'] if reach_info else '',
        }
    def reload_config(self):
        global BLACKLIST, WHITELIST, TRUSTED_DOMAINS

        try:
            with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
                config_baru = json.load(f)

            BLACKLIST = set(config_baru['DOMAINS']['BLACKLIST'])
            WHITELIST = set(config_baru['DOMAINS']['WHITELIST'])

            TRUSTED_DOMAINS = self._load_trusted_domains()

            print(f"✅ Config reloaded! Blacklist: {len(BLACKLIST)} | "
                  f"Whitelist: {len(WHITELIST)} | "
                  f"Trusted: {len(TRUSTED_DOMAINS)}")

        except Exception as e:
            print(f"❌ Gagal reload config: {e}")


    def _load_trusted_domains(self):
        try:
            db_path = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'netra.db'
            )

            conn = sqlite3.connect(db_path)
            rows = conn.execute(
                'SELECT domain FROM trusted_urls WHERE aktif=1'
            ).fetchall()
            conn.close()

            return set(r[0] for r in rows)

        except Exception:
            return set()


predictor = NetraPredictor()