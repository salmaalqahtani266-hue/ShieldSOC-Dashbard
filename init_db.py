import sqlite3
from pathlib import Path

# مسار المشروع الرئيسي
BASE_DIR = Path(__file__).resolve().parent.parent

# مكان قاعدة البيانات
DB_PATH = BASE_DIR / "database" / "shieldsoc.db"


def create_database():
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    # جدول بيئات العمل
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS environments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT
        )
        """
    )

    # جدول الأجهزة والأنظمة
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_name TEXT NOT NULL,
            asset_type TEXT NOT NULL,
            ip_address TEXT,
            operating_system TEXT,
            environment TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Online'
        )
        """
    )

    # جدول السجلات الأمنية
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            environment TEXT NOT NULL,
            status TEXT NOT NULL
        )
        """
    )

    # جدول التنبيهات الأمنية
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source TEXT NOT NULL,
            source_ip TEXT,
            environment TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'New'
        )
        """
    )

    # جدول الحوادث
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_code TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            environment TEXT NOT NULL,
            status TEXT NOT NULL,
            assigned_to TEXT,
            created_at TEXT NOT NULL
        )
        """
    )

    # جدول عناوين IP المحظورة
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            country TEXT,
            reason TEXT,
            environment TEXT NOT NULL,
            blocked_at TEXT NOT NULL
        )
        """
    )

    # إضافة أنواع البيئات
    environments = [
        (
            "Airport",
            "Airport systems, baggage networks, access control and airport infrastructure"
        ),
        (
            "Banking",
            "Core banking, ATM networks, payment systems and financial infrastructure"
        ),
        (
            "Energy",
            "SCADA, PLC, substations and industrial control systems"
        ),
        (
            "Government",
            "Government networks, identity systems, email gateways and data centers"
        )
    ]

    cursor.executemany(
        """
        INSERT OR IGNORE INTO environments (name, description)
        VALUES (?, ?)
        """,
        environments
    )
    # جدول المستخدمين
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )
    
    connection.commit()
    connection.close()

    print("ShieldSOC database created successfully.")
    print(f"Database location: {DB_PATH}")


if __name__ == "__main__":
    create_database()