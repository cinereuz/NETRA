from flask       import Flask, request, jsonify
from flask_cors  import CORS
import sqlite3
import os
import datetime

from utils.predictor import predictor

app = Flask(__name__)

CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'netra.db')


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
            hasil.get('anomaly_score', 0))
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

# MENJALANKAN SERVER
if __name__ == '__main__':
    init_db()
    
    print("\n" + "=" * 40)
    print("  NETRA API Server")
    print("  http://localhost:5000")
    print("=" * 40 + "\n")
    
    app.run(debug=True, port=5000, host='0.0.0.0')