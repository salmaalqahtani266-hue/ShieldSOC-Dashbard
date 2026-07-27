import random
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "database" / "shieldsoc.db"

random.seed(42)


ENVIRONMENTS = ["Airport", "Banking", "Energy", "Government"]

SEVERITIES = ["Critical", "High", "Medium", "Low"]

STATUSES = ["New", "Investigating", "Resolved", "Blocked"]

COUNTRIES = [
    "Russia",
    "Germany",
    "United States",
    "China",
    "Singapore",
    "Netherlands",
    "Brazil",
    "India",
]

SUSPICIOUS_IPS = [
    "185.220.101.4",
    "91.214.124.17",
    "103.27.186.12",
    "45.33.32.156",
    "194.26.29.121",
    "89.248.165.16",
    "167.71.13.196",
    "192.241.214.21",
    "104.248.15.18",
    "159.89.174.9",
]

ENVIRONMENT_DATA = {
    "Airport": {
        "assets": [
            ("CHECKIN-SERVER-01", "Server", "Windows Server 2022"),
            ("BAGGAGE-SYSTEM-01", "Baggage System", "Linux"),
            ("AIRPORT-FIREWALL-01", "Firewall", "FortiOS"),
            ("ACCESS-CONTROL-01", "Access Control", "Embedded OS"),
            ("AIRPORT-WIFI-01", "Wireless Controller", "Cisco IOS"),
        ],
        "events": [
            "Unauthorized badge access attempt",
            "Airport Wi-Fi reconnaissance detected",
            "Suspicious login to baggage handling server",
            "Multiple failed check-in system logins",
            "Malware signature detected on airport endpoint",
            "Unusual traffic from passenger network",
        ],
    },
    "Banking": {
        "assets": [
            ("CORE-BANKING-01", "Core Banking Server", "Linux"),
            ("ATM-GATEWAY-01", "ATM Gateway", "Windows Server 2022"),
            ("SWIFT-GATEWAY-01", "Payment Gateway", "Linux"),
            ("BANK-FIREWALL-01", "Firewall", "Palo Alto OS"),
            ("FRAUD-SYSTEM-01", "Fraud Detection", "Linux"),
        ],
        "events": [
            "Suspicious ATM authentication attempt",
            "Unauthorized access to core banking system",
            "Possible SWIFT credential compromise",
            "Multiple failed customer login attempts",
            "Unusual financial transaction pattern",
            "SQL injection attempt against payment portal",
        ],
    },
    "Energy": {
        "assets": [
            ("SCADA-SERVER-01", "SCADA Server", "Windows Server 2019"),
            ("PLC-GATEWAY-01", "PLC Gateway", "Industrial OS"),
            ("SUBSTATION-FW-01", "Industrial Firewall", "FortiOS"),
            ("HMI-STATION-01", "HMI Workstation", "Windows 10"),
            ("ENERGY-DATA-01", "Historian Server", "Linux"),
        ],
        "events": [
            "Unauthorized access attempt to SCADA server",
            "Unexpected PLC configuration change",
            "Suspicious Modbus traffic detected",
            "Industrial firewall policy violation",
            "Malware activity on HMI workstation",
            "Abnormal communication with power substation",
        ],
    },
    "Government": {
        "assets": [
            ("IDENTITY-SERVER-01", "Identity Server", "Windows Server 2022"),
            ("GOV-MAIL-01", "Email Gateway", "Linux"),
            ("GOV-DNS-01", "DNS Server", "Linux"),
            ("DATA-CENTER-FW-01", "Firewall", "Cisco ASA"),
            ("DOCUMENT-SERVER-01", "Document Server", "Windows Server 2019"),
        ],
        "events": [
            "Phishing email detected",
            "Suspicious access to identity server",
            "DNS tunneling activity detected",
            "Unauthorized document download",
            "Privilege escalation attempt",
            "Possible data exfiltration activity",
        ],
    },
}


def random_time(days_back=7):
    now = datetime.now()
    start = now - timedelta(days=days_back)

    random_seconds = random.randint(
        0,
        int((now - start).total_seconds()),
    )

    return (start + timedelta(seconds=random_seconds)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def random_internal_ip():
    return (
        f"10.{random.randint(1, 20)}."
        f"{random.randint(1, 254)}."
        f"{random.randint(1, 254)}"
    )


def create_assets(cursor):
    for environment, data in ENVIRONMENT_DATA.items():
        for index, asset in enumerate(data["assets"], start=10):
            asset_name, asset_type, operating_system = asset

            cursor.execute(
                """
                INSERT INTO assets (
                    asset_name,
                    asset_type,
                    ip_address,
                    operating_system,
                    environment,
                    status
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    asset_name,
                    asset_type,
                    f"10.{ENVIRONMENTS.index(environment) + 1}.0.{index}",
                    operating_system,
                    environment,
                    random.choice(["Online", "Online", "Online", "Warning"]),
                ),
            )


def create_logs(cursor, count=500):
    for _ in range(count):
        environment = random.choice(ENVIRONMENTS)
        environment_info = ENVIRONMENT_DATA[environment]

        asset = random.choice(environment_info["assets"])
        source_name = asset[0]

        event_description = random.choice(environment_info["events"])
        severity = random.choices(
            SEVERITIES,
            weights=[8, 18, 34, 40],
            k=1,
        )[0]

        source_ip = (
            random.choice(SUSPICIOUS_IPS)
            if severity in ["Critical", "High"]
            else random_internal_ip()
        )

        cursor.execute(
            """
            INSERT INTO security_logs (
                event_time,
                source,
                event_type,
                description,
                severity,
                source_ip,
                destination_ip,
                environment,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                random_time(),
                source_name,
                "Security Event",
                event_description,
                severity,
                source_ip,
                random_internal_ip(),
                environment,
                random.choice(STATUSES),
            ),
        )


def create_alerts(cursor, count=50):
    for _ in range(count):
        environment = random.choice(ENVIRONMENTS)
        environment_info = ENVIRONMENT_DATA[environment]

        asset = random.choice(environment_info["assets"])
        title = random.choice(environment_info["events"])

        severity = random.choices(
            SEVERITIES,
            weights=[20, 35, 30, 15],
            k=1,
        )[0]

        cursor.execute(
            """
            INSERT INTO security_alerts (
                alert_title,
                severity,
                source,
                source_ip,
                environment,
                detected_at,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                severity,
                asset[0],
                random.choice(SUSPICIOUS_IPS),
                environment,
                random_time(3),
                random.choice(["New", "Investigating", "Resolved"]),
            ),
        )


def create_incidents(cursor, count=20):
    incident_titles = [
        "Brute-force attack",
        "Possible malware infection",
        "Suspicious data transfer",
        "Unauthorized access attempt",
        "Credential compromise",
        "Network reconnaissance",
        "Privilege escalation",
        "Possible ransomware activity",
    ]

    analysts = [
        "Tier 1 Analyst",
        "Tier 2 Analyst",
        "Incident Response Team",
        "Threat Hunting Team",
    ]

    for number in range(1, count + 1):
        environment = random.choice(ENVIRONMENTS)

        cursor.execute(
            """
            INSERT INTO incidents (
                incident_code,
                title,
                severity,
                environment,
                status,
                assigned_to,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"INC-{1000 + number}",
                random.choice(incident_titles),
                random.choice(["Critical", "High", "Medium"]),
                environment,
                random.choice(
                    ["Open", "Investigating", "Contained", "Resolved"]
                ),
                random.choice(analysts),
                random_time(14),
            ),
        )


def create_blocked_ips(cursor):
    for ip_address in SUSPICIOUS_IPS:
        cursor.execute(
            """
            INSERT INTO blocked_ips (
                ip_address,
                country,
                reason,
                environment,
                blocked_at
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                ip_address,
                random.choice(COUNTRIES),
                random.choice(
                    [
                        "Brute-force attack",
                        "Malware communication",
                        "Network scanning",
                        "Suspicious authentication",
                        "Possible command and control traffic",
                    ]
                ),
                random.choice(ENVIRONMENTS),
                random_time(30),
            ),
        )


def seed_database():
    if not DB_PATH.exists():
        print("Database file was not found.")
        print("Run: python database/init_db.py")
        return

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()

    # حذف البيانات السابقة حتى لا تتكرر عند إعادة التشغيل
    cursor.execute("DELETE FROM assets")
    cursor.execute("DELETE FROM security_logs")
    cursor.execute("DELETE FROM security_alerts")
    cursor.execute("DELETE FROM incidents")
    cursor.execute("DELETE FROM blocked_ips")

    create_assets(cursor)
    create_logs(cursor, 500)
    create_alerts(cursor, 50)
    create_incidents(cursor, 20)
    create_blocked_ips(cursor)

    connection.commit()

    tables = [
        "assets",
        "security_logs",
        "security_alerts",
        "incidents",
        "blocked_ips",
    ]

    print("ShieldSOC sample data created successfully.")
    print("------------------------------------------")

    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        total = cursor.fetchone()[0]
        print(f"{table}: {total} records")

    connection.close()


if __name__ == "__main__":
    seed_database()