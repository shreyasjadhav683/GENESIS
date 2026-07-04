import sqlite3
import datetime

db_path = "c:/Users/MANGESH JADHAV/Desktop/genesis/genesis/backend/genesis.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

try:
    c.execute("ALTER TABLE user ADD COLUMN last_logout DATETIME;")
    print("Added last_logout column")
except sqlite3.OperationalError as e:
    print(f"last_logout issue: {e}")

conn.commit()
conn.close()
print("Done.")
