import sqlite3

conn = sqlite3.connect(r'C:\Dev\project\web\NETRA\ml-backend\data\netra.db')
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = cursor.fetchall()

print('=== TABEL YANG ADA ===')
for t in tables:
    print(t[0])

print()

for t in tables:
    print(f'=== KOLOM TABEL: {t[0]} ===')
    cursor.execute(f'PRAGMA table_info({t[0]})')
    cols = cursor.fetchall()
    for c in cols:
        print(f'  {c[1]} ({c[2]})')
    print()

for t in tables:
    print(f'=== CONTOH DATA: {t[0]} ===')
    cursor.execute(f'SELECT * FROM {t[0]} LIMIT 3')
    rows = cursor.fetchall()
    for r in rows:
        print(r)
    print()

conn.close()
print('Selesai!')