import sqlite3
import pandas as pd

conn = sqlite3.connect(r'C:\Dev\project\web\NETRA\ml-backend\data\netra.db')
cursor = conn.cursor()

print('=== TOTAL DATA DI prediction_logs ===')
cursor.execute("SELECT COUNT(*) FROM prediction_logs")
print(f'Total: {cursor.fetchone()[0]} baris')

print()
print('=== SEMUA NILAI UNIK DI KOLOM method ===')
cursor.execute("SELECT method, COUNT(*) as jumlah FROM prediction_logs GROUP BY method ORDER BY jumlah DESC")
rows = cursor.fetchall()
for r in rows:
    print(f'  {r[0]} : {r[1]} URL')

print()
print('=== DISTRIBUSI method PER kategori ===')
cursor.execute("""
    SELECT method, kategori, COUNT(*) as jumlah 
    FROM prediction_logs 
    GROUP BY method, kategori 
    ORDER BY method, jumlah DESC
""")
rows = cursor.fetchall()
for r in rows:
    print(f'  [{r[0]}] {r[1]} : {r[2]} URL')

print()
print('=== RATA-RATA CONFIDENCE PER method ===')
cursor.execute("""
    SELECT method, ROUND(AVG(confidence), 2) as avg_conf, 
           ROUND(MIN(confidence), 2) as min_conf,
           ROUND(MAX(confidence), 2) as max_conf
    FROM prediction_logs 
    GROUP BY method
""")
rows = cursor.fetchall()
for r in rows:
    print(f'  {r[0]} — avg: {r[1]}%, min: {r[2]}%, max: {r[3]}%')

conn.close()
print()
print('Selesai!')