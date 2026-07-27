import sqlite3
from datetime import datetime
from pathlib import Path

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database" / "shieldsoc.db"


def create_admin():
    connection = sqlite3.connect(DATABASE_PATH)
    cursor = connection.cursor()

    username = "admin"
    password = "ShieldSOC@123"
    full_name = "SOC Administrator"
    role = "Administrator"

    password_hash = generate_password_hash(password)

    cursor.execute(
        """
        INSERT OR REPLACE INTO users (
            id,
            full_name,
            username,
            password_hash,
            role,
            is_active,
            created_at
        )
        VALUES (
            COALESCE(
                (
                    SELECT id
                    FROM users
                    WHERE username = ?
                ),
                NULL
            ),
            ?,
            ?,
            ?,
            ?,
            1,
            ?
        )
        """,
        (
            username,
            full_name,
            username,
            password_hash,
            role,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )

    connection.commit()
    connection.close()

    print("Admin user created successfully.")
    print("Username: admin")
    print("Password: ShieldSOC@123")


if __name__ == "__main__":
    create_admin()