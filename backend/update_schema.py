import sqlite3
import datetime

db_path = "c:/Users/MANGESH JADHAV/Desktop/genesis/genesis/backend/genesis.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Try adding created_at
try:
    c.execute("ALTER TABLE user ADD COLUMN created_at DATETIME;")
    # Set default value for existing users
    c.execute(f"UPDATE user SET created_at = '{datetime.datetime.utcnow().isoformat()}'")
    print("Added created_at column")
except sqlite3.OperationalError as e:
    print(f"created_at issue: {e}")

# Try adding last_active
try:
    c.execute("ALTER TABLE user ADD COLUMN last_active DATETIME;")
    print("Added last_active column")
except sqlite3.OperationalError as e:
    print(f"last_active issue: {e}")

conn.commit()
conn.close()
print("Done.")
