import sqlite3
import datetime

db_path = "c:/Users/MANGESH JADHAV/Desktop/genesis/genesis/backend/genesis.db"
conn = sqlite3.connect(db_path)
c = conn.cursor()

# Backdate created_at by 2 hours so everyone appears offline
past_time = (datetime.datetime.utcnow() - datetime.timedelta(hours=2)).isoformat()
c.execute(f"UPDATE user SET created_at = '{past_time}' WHERE last_active IS NULL")

conn.commit()
conn.close()
print("Fixed created_at for older users.")
