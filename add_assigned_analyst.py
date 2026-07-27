import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parent / "shieldsoc.db"

connection = sqlite3.connect(DATABASE_PATH)
cursor = connection.cursor()

columns = cursor.execute(
    "PRAGMA table_info(security_logs)"
).fetchall()

column_names = [column[1] for column in columns]

if "assigned_analyst" not in column_names:
    cursor.execute(
        """
        ALTER TABLE security_logs
        ADD COLUMN assigned_analyst TEXT DEFAULT 'Unassigned'
        """
    )
    connection.commit()
    print("assigned_analyst column added successfully.")
else:
    print("assigned_analyst column already exists.")

connection.close()