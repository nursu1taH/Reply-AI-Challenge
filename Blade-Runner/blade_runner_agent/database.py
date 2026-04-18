from __future__ import annotations

import csv
import json
import sqlite3
from pathlib import Path


def _connect(database_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    return conn


def build_database(dataset_dir: Path, database_path: Path, force_rebuild: bool = False) -> sqlite3.Connection:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    if force_rebuild and database_path.exists():
        database_path.unlink()

    conn = _connect(database_path)
    _create_schema(conn)
    if _has_existing_data(conn):
        return conn

    transactions = _read_transactions(dataset_dir / "transactions.csv")
    users = _read_json(dataset_dir / "users.json")
    sms_messages = _read_json(dataset_dir / "sms.json")
    email_messages = _read_json(dataset_dir / "mails.json")
    locations = _read_json(dataset_dir / "locations.json")

    iban_to_sender = {}
    for transaction in transactions:
        sender_iban = transaction["sender_iban"]
        sender_id = transaction["sender_id"]
        if sender_iban and sender_id:
            iban_to_sender.setdefault(sender_iban, sender_id)

    user_rows = []
    for user in users:
        sender_id = iban_to_sender.get(user["iban"], "")
        user_rows.append(
            (
                sender_id,
                user["first_name"],
                user["last_name"],
                int(user["birth_year"]),
                float(user["salary"]),
                user["job"],
                user["iban"],
                user["residence"]["city"],
                float(user["residence"]["lat"]),
                float(user["residence"]["lng"]),
                user["description"],
            )
        )

    with conn:
        conn.executemany(
            """
            INSERT INTO transactions (
                transaction_id, sender_id, recipient_id, transaction_type, amount, location,
                payment_method, sender_iban, recipient_iban, balance_after, description, timestamp
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["transaction_id"],
                    row["sender_id"],
                    row["recipient_id"],
                    row["transaction_type"],
                    float(row["amount"]),
                    row["location"],
                    row["payment_method"],
                    row["sender_iban"],
                    row["recipient_iban"],
                    float(row["balance_after"]),
                    row["description"],
                    row["timestamp"],
                )
                for row in transactions
            ],
        )
        conn.executemany(
            """
            INSERT INTO users (
                sender_id, first_name, last_name, birth_year, salary, job, iban,
                residence_city, residence_lat, residence_lng, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            user_rows,
        )
        conn.executemany(
            "INSERT INTO sms_messages (raw_text) VALUES (?)",
            [(item["sms"],) for item in sms_messages],
        )
        conn.executemany(
            "INSERT INTO email_messages (raw_text) VALUES (?)",
            [(item["mail"],) for item in email_messages],
        )
        conn.executemany(
            """
            INSERT INTO locations (biotag, timestamp, lat, lng, city)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    item["biotag"],
                    item["timestamp"],
                    float(item["lat"]),
                    float(item["lng"]),
                    item["city"],
                )
                for item in locations
            ],
        )

    return conn


def reset_analysis_tables(conn: sqlite3.Connection) -> None:
    with conn:
        conn.execute("DELETE FROM communication_events")
        conn.execute("DELETE FROM transaction_scores")
        conn.execute("DELETE FROM llm_reviews")


def _create_schema(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                recipient_id TEXT,
                transaction_type TEXT NOT NULL,
                amount REAL NOT NULL,
                location TEXT,
                payment_method TEXT,
                sender_iban TEXT,
                recipient_iban TEXT,
                balance_after REAL NOT NULL,
                description TEXT,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                sender_id TEXT PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                birth_year INTEGER NOT NULL,
                salary REAL NOT NULL,
                job TEXT NOT NULL,
                iban TEXT NOT NULL,
                residence_city TEXT NOT NULL,
                residence_lat REAL NOT NULL,
                residence_lng REAL NOT NULL,
                description TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sms_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_text TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_text TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                biotag TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                lat REAL NOT NULL,
                lng REAL NOT NULL,
                city TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS communication_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                risk_score REAL NOT NULL,
                theme TEXT NOT NULL,
                requested_amounts TEXT NOT NULL,
                summary TEXT NOT NULL,
                raw_excerpt TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS transaction_scores (
                transaction_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                base_score REAL NOT NULL,
                final_score REAL NOT NULL,
                reviewed INTEGER NOT NULL,
                reasons TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS llm_reviews (
                transaction_id TEXT PRIMARY KEY,
                fraud_probability REAL NOT NULL,
                decision TEXT NOT NULL,
                confidence REAL NOT NULL,
                reasons TEXT NOT NULL,
                raw_response TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_transactions_sender_time
                ON transactions(sender_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_locations_biotag_time
                ON locations(biotag, timestamp);
            CREATE INDEX IF NOT EXISTS idx_comm_events_user_time
                ON communication_events(user_id, timestamp);
            """
        )


def _has_existing_data(conn: sqlite3.Connection) -> bool:
    row = conn.execute("SELECT COUNT(*) AS count FROM transactions").fetchone()
    return bool(row and row["count"])


def _read_transactions(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _read_json(path: Path) -> list[dict[str, object]]:
    return json.loads(path.read_text(encoding="utf-8"))
