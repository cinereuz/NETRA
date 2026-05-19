import json
from flask       import Flask, request, jsonify, render_template
from flask_cors  import CORS
import sqlite3
import os
import datetime

from utils.predictor import predictor

app = Flask(__name__)

CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'netra.db')

app.template_folder = os.path.join(os.path.dirname(__file__), 'templates')

# SETUP DATABASE CROWDSOURCING
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    
    # Tabel laporan dari user (crowdsourcing)
    c.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            kategori    TEXT    NOT NULL,  -- 'phishing', 'judi_online', 'aman'
            source      TEXT    DEFAULT 'user',
            timestamp   TEXT    NOT NULL,
            verified    INTEGER DEFAULT 0  -- 0=belum, 1=sudah diverifikasi
        )
    ''')
    
    # Tabel log prediksi (untuk analisis penelitian)
    c.execute('''
        CREATE TABLE IF NOT EXISTS prediction_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT    NOT NULL,
            kategori    TEXT    NOT NULL,
            confidence  REAL    NOT NULL,
            method      TEXT    NOT NULL,
            timestamp   TEXT    NOT NULL
        )
    ''')

    # Tabel trusted URLs (false positive yang dilaporkan user)
    c.execute('''
        CREATE TABLE IF NOT EXISTS trusted_urls (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT    NOT NULL UNIQUE,
            -- UNIQUE: satu domain hanya bisa masuk sekali
            alasan      TEXT    DEFAULT '',
            -- Alasan kenapa domain ini dipercaya
            ditambah_at TEXT    NOT NULL,
            -- Waktu domain ditambahkan
            aktif       INTEGER DEFAULT 1
            -- 1=aktif, 0=dinonaktifkan admin (soft delete)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database siap!")


# ENDPOINTS API
@app.route('/', methods=['GET'])
def home():
    # Endpoint root
    return jsonify({
        'status' : 'running',
        'name'   : 'NETRA API',
        'version': '1.0.0',
        'endpoints': ['/predict', '/report', '/reports', '/stats']
    })


@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    
    # Validasi
    if not data or 'url' not in data:
        return jsonify({'error': 'Field "url" wajib diisi'}), 400
    
    url = data['url'].strip()
    
    if not url:
        return jsonify({'error': 'URL tidak boleh kosong'}), 400
    
    hasil = predictor.predict(url)
    hasil['url'] = url

    if 'is_anomali' in hasil:
        hasil['is_anomali'] = bool(hasil['is_anomali'])

    for key, val in hasil.items():
        if hasattr(val, 'item'):
            hasil[key] = val.item()
    
    try:
        conn = sqlite3.connect(DB_PATH)

        try:
            conn.execute("ALTER TABLE prediction_logs ADD COLUMN is_anomali INTEGER DEFAULT 0")
            conn.execute("ALTER TABLE prediction_logs ADD COLUMN anomaly_score REAL DEFAULT 0")
            conn.commit()
        except:
            pass

        conn.execute(
            'INSERT INTO prediction_logs '
            '(url, kategori, confidence, method, timestamp, is_anomali, anomaly_score) '
            'VALUES (?, ?, ?, ?, ?, ?, ?)',
            (url, hasil['kategori'], hasil['confidence'], hasil['method'],
            datetime.datetime.now().isoformat(),
            int(hasil.get('is_anomali', False)),
            float(hasil.get('anomaly_score', 0)))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: gagal simpan log → {e}")
    
    return jsonify(hasil)


@app.route('/report', methods=['POST'])
def report():
    data = request.get_json()
    
    if not data or 'url' not in data or 'kategori' not in data:
        return jsonify({'error': 'Field "url" dan "kategori" wajib diisi'}), 400
    
    url      = data['url'].strip()
    kategori = data['kategori'].strip()
    
    # Validasi kategori
    if kategori not in ['phishing', 'judi_online', 'aman']:
        return jsonify({'error': 'Kategori harus: phishing / judi_online / aman'}), 400
    
    # Menyimpan laporan ke database
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            'INSERT INTO reports (url, kategori, source, timestamp) VALUES (?, ?, ?, ?)',
            (url, kategori, 'user', datetime.datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        
        return jsonify({
            'status' : 'success',
            'pesan'  : 'Laporan berhasil dikirim! Terima kasih atas kontribusimu.',
            'url'    : url,
            'kategori': kategori
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/reports', methods=['GET'])
def get_reports():
    limit    = request.args.get('limit',    100,  type=int)
    kategori = request.args.get('kategori', None)
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    
    if kategori:
        rows = conn.execute(
            'SELECT * FROM reports WHERE kategori=? ORDER BY id DESC LIMIT ?',
            (kategori, limit)
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT * FROM reports ORDER BY id DESC LIMIT ?',
            (limit,)
        ).fetchall()
    
    conn.close()
    
    return jsonify({
        'total'  : len(rows),
        'reports': [dict(row) for row in rows]
    })


@app.route('/stats', methods=['GET'])
def stats():
    conn = sqlite3.connect(DB_PATH)
    
    logs = conn.execute(
        'SELECT kategori, COUNT(*) as total FROM prediction_logs GROUP BY kategori'
    ).fetchall()
    
    reports_count = conn.execute('SELECT COUNT(*) FROM reports').fetchone()[0]
    
    conn.close()
    
    stats_dict = {row[0]: row[1] for row in logs}
    
    return jsonify({
        'total_prediksi'   : sum(stats_dict.values()),
        'per_kategori'     : stats_dict,
        'total_laporan_user': reports_count
    })

@app.route('/api/check', methods=['POST'])
def api_check():
    return predict()

@app.route('/admin')
def admin_dashboard():
    return render_template('dashboard.html')


@app.route('/admin/api/reports')
def admin_get_reports():
    status = request.args.get('status', 'all')
    limit  = request.args.get('limit', 100, type=int)

    conn             = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    if status == 'all':
        rows = conn.execute(
            'SELECT * FROM reports ORDER BY id DESC LIMIT ?',
            (limit,)
        ).fetchall()
    else:
        verified = 1 if status == '1' else 0
        rows = conn.execute(
            'SELECT * FROM reports WHERE verified=? ORDER BY id DESC LIMIT ?',
            (verified, limit)
        ).fetchall()

    conn.close()
    return jsonify({'total': len(rows), 'reports': [dict(row) for row in rows]})


@app.route('/admin/api/reports/<int:report_id>/verify', methods=['POST'])
def admin_verify_report(report_id):
    data   = request.get_json()
    action = data.get('action')

    if action not in ['verify', 'reject']:
        return jsonify({'error': 'Action harus: verify atau reject'}), 400

    verified = 1 if action == 'verify' else 0

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            'UPDATE reports SET verified=? WHERE id=?',
            (verified, report_id)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'report_id': report_id, 'status': action})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/api/stats/detail')
def admin_stats_detail():
    conn = sqlite3.connect(DB_PATH)

    prediksi = conn.execute(
        'SELECT kategori, COUNT(*) as total FROM prediction_logs GROUP BY kategori'
    ).fetchall()

    laporan = conn.execute(
        'SELECT kategori, COUNT(*) as total FROM reports GROUP BY kategori'
    ).fetchall()

    pending = conn.execute(
        'SELECT COUNT(*) FROM reports WHERE verified=0'
    ).fetchone()[0]

    top_urls = conn.execute(
        '''SELECT url, COUNT(*) as jumlah FROM reports
           GROUP BY url ORDER BY jumlah DESC LIMIT 10'''
    ).fetchall()

    conn.close()
    return jsonify({
        'prediksi_per_kategori': {row[0]: row[1] for row in prediksi},
        'laporan_per_kategori' : {row[0]: row[1] for row in laporan},
        'pending_review'       : pending,
        'top_reported_urls'    : [{'url': row[0], 'jumlah': row[1]} for row in top_urls]
    })

# CROWDSOURCING INTELLIGENCE (Kandidat Blacklist & Trusted)
@app.route('/admin/api/kandidat')
def admin_kandidat():
    THRESHOLD = 3

    conn             = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute('''
        SELECT
            url,
            kategori,
            COUNT(*) as jumlah_verified
        FROM reports
        WHERE verified = 1
        GROUP BY url, kategori
        HAVING COUNT(*) >= ?
        ORDER BY jumlah_verified DESC
    ''', (THRESHOLD,)).fetchall()
    import json as _json

    config_path = os.path.join(os.path.dirname(__file__), 'data', 'config.json')
    with open(config_path, 'r', encoding='utf-8') as f:
        cfg = _json.load(f)

    blacklist_ada = cfg['DOMAINS']['BLACKLIST']

    whitelist_ada = cfg['DOMAINS']['WHITELIST']

    trusted_ada = [r[0] for r in conn.execute(
        'SELECT domain FROM trusted_urls WHERE aktif=1'
    ).fetchall()]

    conn.close()

    kandidat = []
    for r in rows:
        url      = r['url']
        kategori = r['kategori']

        from urllib.parse import urlparse as _urlparse
        domain_kandidat = _urlparse(url).netloc

        sudah_diproses = domain_kandidat in blacklist_ada or \
                        domain_kandidat in whitelist_ada or \
                        domain_kandidat in trusted_ada
        if sudah_diproses:
            continue

        kandidat.append({
            'url'             : url,
            'kategori'        : kategori,
            'jumlah_verified' : r['jumlah_verified'],
            'aksi_rekomendasi': 'blacklist' if kategori in ['phishing', 'judi_online']
                                            else 'trusted'
        })

    return jsonify({
        'total'    : len(kandidat),
        'kandidat' : kandidat,
        'threshold': THRESHOLD
    })


@app.route('/admin/api/blacklist/tambah', methods=['POST'])
def admin_tambah_blacklist():
    data = request.get_json()
    url  = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL wajib diisi'}), 400

    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc

        if not domain:
            return jsonify({'error': 'Tidak bisa ekstrak domain dari URL'}), 400

        config_path = os.path.join(os.path.dirname(__file__), 'data', 'config.json')
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        if domain in config['DOMAINS']['BLACKLIST']:
            return jsonify({
                'message': f'{domain} sudah ada di blacklist',
                'domain' : domain
            }), 200

        config['DOMAINS']['BLACKLIST'].append(domain)

        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        predictor.reload_config()

        return jsonify({
            'success': True,
            'message': f'✅ {domain} berhasil ditambahkan ke blacklist',
            'domain' : domain
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/api/trusted/tambah', methods=['POST'])
def admin_tambah_trusted():
    data   = request.get_json()
    url    = data.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL wajib diisi'}), 400

    try:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.replace('www.', '')

        if not domain:
            return jsonify({'error': 'Tidak bisa ekstrak domain'}), 400

        config_path = os.path.join(os.path.dirname(__file__), 'data', 'config.json')
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)

        if domain in config['DOMAINS']['WHITELIST']:
            return jsonify({
                'message': f'{domain} sudah ada di whitelist',
                'domain' : domain
            }), 200

        config['DOMAINS']['WHITELIST'].append(domain)

        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        predictor.reload_config()

        return jsonify({
            'success': True,
            'message': f'✅ {domain} ditambahkan ke whitelist',
            'domain' : domain
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/admin/api/trusted', methods=['GET'])
def admin_get_trusted():
    conn             = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        'SELECT * FROM trusted_urls WHERE aktif=1 ORDER BY id DESC'
    ).fetchall()

    conn.close()

    return jsonify({
        'total'  : len(rows),
        'trusted': [dict(r) for r in rows]
    })


@app.route('/admin/api/trusted/<int:trusted_id>/nonaktif', methods=['POST'])
def admin_nonaktif_trusted(trusted_id):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            'UPDATE trusted_urls SET aktif=0 WHERE id=?',
            (trusted_id,)
        )
        conn.commit()
        conn.close()

        predictor.reload_config()

        return jsonify({'success': True, 'id': trusted_id})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# MENJALANKAN SERVER
if __name__ == '__main__':
    init_db()
    
    print("\n" + "=" * 40)
    print("  NETRA API Server")
    print("  http://localhost:5000")
    print("=" * 40 + "\n")
    
    app.run(debug=True, port=5000, host='0.0.0.0')