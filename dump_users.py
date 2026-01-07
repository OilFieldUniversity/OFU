import sqlite3
import os
import csv
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'database.db')
OUT_CSV = os.path.join(BASE_DIR, 'users_export.csv')

if not os.path.exists(DB_PATH):
    print(f"Database not found at {DB_PATH}")
    sys.exit(1)

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
try:
    cur.execute('SELECT * FROM users')
except sqlite3.OperationalError as e:
    print('SQL error:', e)
    conn.close()
    sys.exit(1)

rows = cur.fetchall()
cols = [d[0] for d in cur.description] if cur.description else []

with open(OUT_CSV, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    if cols:
        writer.writerow(cols)
    writer.writerows(rows)

print(f'Exported {len(rows)} rows to {OUT_CSV}')
conn.close()
