from __future__ import annotations

import csv
import json
import math
import re
import sqlite3
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from html import unescape
from pathlib import Path


def ascii_fold(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    return normalized.encode("ascii", "ignore").decode("ascii")


def normalize_text(value: str) -> str:
    lowered = ascii_fold(value).lower()
    return re.sub(r"[^a-z0-9]+", " ", lowered).strip()


def canonical_city(value: str) -> str:
    if not value:
        return ""
    base = value.split(" - ", 1)[0].replace("/", " ")
    return normalize_text(base)


def parse_datetime(value: str) -> datetime:
    cleaned = value.strip()
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        parsed = parsedate_to_datetime(cleaned)
    return parsed.replace(tzinfo=None) if parsed.tzinfo else parsed


def safe_float(value: str) -> float:
    if value in (None, ""):
        return 0.0
    return float(value)


def strip_html(raw: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", raw or "")
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def extract_urls(raw: str) -> list[str]:
    return re.findall(r"https?://[^\s\"'<>]+", raw or "")


def extract_domain(url: str) -> str:
    match = re.match(r"https?://([^/\s]+)", url)
    return match.group(1).lower() if match else ""


def extract_first_percentage(text: str) -> float | None:
    patterns = [
        r"(\d{1,3})\s*(?:percent|prozent|%)",
        r"(\d{1,3})\s*percento",
    ]
    lowered = normalize_text(text)
    for pattern in patterns:
        match = re.search(pattern, lowered)
        if match:
            return float(match.group(1)) / 100.0
    return None


def haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    radius = 6371.0
    lat1_r = math.radians(lat1)
    lat2_r = math.radians(lat2)
    d_lat = math.radians(lat2 - lat1)
    d_lng = math.radians(lng2 - lng1)
    a = (
        math.sin(d_lat / 2) ** 2
        + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(d_lng / 2) ** 2
    )
    return 2 * radius * math.asin(math.sqrt(a))


def parse_email_headers(raw: str) -> dict[str, str]:
    fields = {}
    for header in ("From", "To", "Subject", "Date"):
        match = re.search(rf"^{header}:\s*(.+)$", raw, re.MULTILINE)
        fields[header.lower()] = match.group(1).strip() if match else ""
    return fields


def parse_to_name_and_email(raw_to: str) -> tuple[str, str]:
    match = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', raw_to)
    if match:
        return match.group(1).strip(), match.group(2).strip().lower()
    return raw_to.strip(), ""


def parse_from_name_and_email(raw_from: str) -> tuple[str, str]:
    match = re.search(r'"?([^"<]+)"?\s*<([^>]+)>', raw_from)
    if match:
        return match.group(1).strip(), match.group(2).strip().lower()
    return raw_from.strip(), ""


@dataclass(slots=True)
class UserProfile:
    user_id: str
    full_name: str
    first_name: str
    last_name: str
    birth_year: int
    salary: float
    job: str
    iban: str
    city: str
    residence_lat: float
    residence_lng: float
    description: str
    phishing_susceptibility: float | None


@dataclass(slots=True)
class TransactionRecord:
    transaction_id: str
    sender_id: str
    recipient_id: str
    transaction_type: str
    amount: float
    location: str
    payment_method: str
    sender_iban: str
    recipient_iban: str
    balance_after: float
    description: str
    timestamp: datetime
    user_id: str
    direction: str
    counterparty_id: str
    counterparty_iban: str


@dataclass(slots=True)
class MessageRecord:
    source_type: str
    user_id: str
    owner_label: str
    sender_label: str
    sender_address: str
    timestamp: datetime
    subject: str
    body_text: str
    raw: str
    urls: list[str]


@dataclass(slots=True)
class LocationRecord:
    user_id: str
    timestamp: datetime
    lat: float
    lng: float
    city: str


@dataclass(slots=True)
class AudioRecord:
    user_id: str
    full_name: str
    timestamp: datetime
    path: str


@dataclass(slots=True)
class DatasetBundle:
    users: dict[str, UserProfile]
    transactions: list[TransactionRecord]
    messages: list[MessageRecord]
    locations_by_user: dict[str, list[LocationRecord]]
    city_centroids: dict[str, tuple[float, float]]
    audio_events: list[AudioRecord]


class MirrorDatabase:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path

    def build_from_dataset(self, dataset_dir: Path, rebuild: bool = False) -> None:
        if rebuild and self.database_path.exists():
            self.database_path.unlink()

        conn = sqlite3.connect(self.database_path)
        try:
            self._create_schema(conn)
            if self._has_data(conn):
                return

            users_path = dataset_dir / "users.json"
            tx_path = dataset_dir / "transactions.csv"
            locations_path = dataset_dir / "locations.json"
            sms_path = dataset_dir / "sms.json"
            mails_path = dataset_dir / "mails.json"
            audio_dir = dataset_dir / "audio"

            users_payload = json.loads(users_path.read_text(encoding="utf-8"))
            tx_rows = list(csv.DictReader(tx_path.open(encoding="utf-8", newline="")))
            ibans = {entry["iban"]: entry for entry in users_payload}
            iban_to_user_id: dict[str, str] = {}
            for row in tx_rows:
                if row["sender_iban"] in ibans:
                    iban_to_user_id[row["sender_iban"]] = row["sender_id"]
                if row["recipient_iban"] in ibans:
                    iban_to_user_id[row["recipient_iban"]] = row["recipient_id"]

            resolved_users = []
            for entry in users_payload:
                user_id = iban_to_user_id.get(entry["iban"])
                if not user_id:
                    continue
                resolved_users.append(
                    {
                        "user_id": user_id,
                        "full_name": f"{entry['first_name']} {entry['last_name']}",
                        "first_name": entry["first_name"],
                        "last_name": entry["last_name"],
                        "birth_year": int(entry["birth_year"]),
                        "salary": float(entry["salary"]),
                        "job": entry["job"],
                        "iban": entry["iban"],
                        "city": entry["residence"]["city"],
                        "residence_lat": float(entry["residence"]["lat"]),
                        "residence_lng": float(entry["residence"]["lng"]),
                        "description": entry["description"],
                        "phishing_susceptibility": extract_first_percentage(entry["description"]),
                    }
                )

            self._ingest_users(conn, resolved_users)
            user_by_name = {entry["full_name"]: entry for entry in resolved_users}
            user_by_id = {entry["user_id"]: entry for entry in resolved_users}

            self._ingest_transactions(conn, tx_rows, user_by_id)
            self._ingest_locations(
                conn,
                json.loads(locations_path.read_text(encoding="utf-8")),
                user_by_id,
            )
            self._ingest_sms(
                conn,
                json.loads(sms_path.read_text(encoding="utf-8")),
                resolved_users,
            )
            self._ingest_mails(
                conn,
                json.loads(mails_path.read_text(encoding="utf-8")),
                user_by_name,
            )
            self._ingest_audio(conn, audio_dir, user_by_name)
            conn.commit()
        finally:
            conn.close()

    def load_bundle(self) -> DatasetBundle:
        conn = sqlite3.connect(self.database_path)
        conn.row_factory = sqlite3.Row
        try:
            users = {
                row["user_id"]: UserProfile(
                    user_id=row["user_id"],
                    full_name=row["full_name"],
                    first_name=row["first_name"],
                    last_name=row["last_name"],
                    birth_year=int(row["birth_year"]),
                    salary=float(row["salary"]),
                    job=row["job"],
                    iban=row["iban"],
                    city=row["city"],
                    residence_lat=float(row["residence_lat"]),
                    residence_lng=float(row["residence_lng"]),
                    description=row["description"],
                    phishing_susceptibility=(
                        float(row["phishing_susceptibility"])
                        if row["phishing_susceptibility"] is not None
                        else None
                    ),
                )
                for row in conn.execute("SELECT * FROM users")
            }

            transactions = [
                TransactionRecord(
                    transaction_id=row["transaction_id"],
                    sender_id=row["sender_id"],
                    recipient_id=row["recipient_id"] or "",
                    transaction_type=row["transaction_type"],
                    amount=float(row["amount"]),
                    location=row["location"] or "",
                    payment_method=row["payment_method"] or "",
                    sender_iban=row["sender_iban"] or "",
                    recipient_iban=row["recipient_iban"] or "",
                    balance_after=float(row["balance_after"]),
                    description=row["description"] or "",
                    timestamp=parse_datetime(row["timestamp"]),
                    user_id=row["user_id"] or "",
                    direction=row["direction"] or "external",
                    counterparty_id=row["counterparty_id"] or "",
                    counterparty_iban=row["counterparty_iban"] or "",
                )
                for row in conn.execute(
                    "SELECT * FROM transactions ORDER BY timestamp, transaction_id"
                )
            ]

            messages = [
                MessageRecord(
                    source_type=row["source_type"],
                    user_id=row["user_id"],
                    owner_label=row["owner_label"],
                    sender_label=row["sender_label"],
                    sender_address=row["sender_address"] or "",
                    timestamp=parse_datetime(row["timestamp"]),
                    subject=row["subject"] or "",
                    body_text=row["body_text"],
                    raw=row["raw"],
                    urls=json.loads(row["urls_json"]),
                )
                for row in conn.execute(
                    """
                    SELECT source_type, user_id, owner_label, sender_label, sender_address,
                           timestamp, subject, body_text, raw, urls_json
                    FROM messages
                    ORDER BY timestamp, rowid
                    """
                )
            ]

            locations_by_user: dict[str, list[LocationRecord]] = defaultdict(list)
            for row in conn.execute("SELECT * FROM locations ORDER BY timestamp"):
                locations_by_user[row["user_id"]].append(
                    LocationRecord(
                        user_id=row["user_id"],
                        timestamp=parse_datetime(row["timestamp"]),
                        lat=float(row["lat"]),
                        lng=float(row["lng"]),
                        city=row["city"],
                    )
                )

            audio_events = [
                AudioRecord(
                    user_id=row["user_id"],
                    full_name=row["full_name"],
                    timestamp=parse_datetime(row["timestamp"]),
                    path=row["path"],
                )
                for row in conn.execute(
                    "SELECT * FROM audio_events ORDER BY timestamp, path"
                )
            ]

            city_points: dict[str, list[tuple[float, float]]] = defaultdict(list)
            for user in users.values():
                key = canonical_city(user.city)
                if key:
                    city_points[key].append((user.residence_lat, user.residence_lng))
            for points in locations_by_user.values():
                for point in points:
                    key = canonical_city(point.city)
                    if key:
                        city_points[key].append((point.lat, point.lng))

            city_centroids = {
                city: (
                    sum(lat for lat, _ in points) / len(points),
                    sum(lng for _, lng in points) / len(points),
                )
                for city, points in city_points.items()
            }

            return DatasetBundle(
                users=users,
                transactions=transactions,
                messages=messages,
                locations_by_user=dict(locations_by_user),
                city_centroids=city_centroids,
                audio_events=audio_events,
            )
        finally:
            conn.close()

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                full_name TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                birth_year INTEGER NOT NULL,
                salary REAL NOT NULL,
                job TEXT NOT NULL,
                iban TEXT NOT NULL UNIQUE,
                city TEXT NOT NULL,
                residence_lat REAL NOT NULL,
                residence_lng REAL NOT NULL,
                description TEXT NOT NULL,
                phishing_susceptibility REAL
            );

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
                timestamp TEXT NOT NULL,
                user_id TEXT,
                direction TEXT,
                counterparty_id TEXT,
                counterparty_iban TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_transactions_user_time
                ON transactions(user_id, timestamp);
            CREATE INDEX IF NOT EXISTS idx_transactions_counterparty
                ON transactions(counterparty_id, timestamp);

            CREATE TABLE IF NOT EXISTS locations (
                user_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                lat REAL NOT NULL,
                lng REAL NOT NULL,
                city TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_locations_user_time
                ON locations(user_id, timestamp);

            CREATE TABLE IF NOT EXISTS messages (
                source_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                owner_label TEXT NOT NULL,
                sender_label TEXT NOT NULL,
                sender_address TEXT,
                timestamp TEXT NOT NULL,
                subject TEXT,
                body_text TEXT NOT NULL,
                raw TEXT NOT NULL,
                urls_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_messages_user_time
                ON messages(user_id, timestamp);

            CREATE TABLE IF NOT EXISTS audio_events (
                user_id TEXT NOT NULL,
                full_name TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                path TEXT NOT NULL
            );
            """
        )

    def _has_data(self, conn: sqlite3.Connection) -> bool:
        row = conn.execute("SELECT COUNT(*) AS count FROM transactions").fetchone()
        return bool(row and row[0])

    def _ingest_users(
        self, conn: sqlite3.Connection, users: list[dict[str, object]]
    ) -> None:
        conn.executemany(
            """
            INSERT INTO users (
                user_id, full_name, first_name, last_name, birth_year, salary, job,
                iban, city, residence_lat, residence_lng, description,
                phishing_susceptibility
            )
            VALUES (
                :user_id, :full_name, :first_name, :last_name, :birth_year, :salary,
                :job, :iban, :city, :residence_lat, :residence_lng, :description,
                :phishing_susceptibility
            )
            """,
            users,
        )

    def _ingest_transactions(
        self,
        conn: sqlite3.Connection,
        rows: list[dict[str, str]],
        user_by_id: dict[str, dict[str, object]],
    ) -> None:
        inserts = []
        for row in rows:
            user_id = ""
            direction = "external"
            counterparty_id = ""
            counterparty_iban = ""
            if row["sender_id"] in user_by_id:
                user_id = row["sender_id"]
                direction = "outgoing"
                counterparty_id = row["recipient_id"]
                counterparty_iban = row["recipient_iban"]
            elif row["recipient_id"] in user_by_id:
                user_id = row["recipient_id"]
                direction = "incoming"
                counterparty_id = row["sender_id"]
                counterparty_iban = row["sender_iban"]

            inserts.append(
                {
                    "transaction_id": row["transaction_id"],
                    "sender_id": row["sender_id"],
                    "recipient_id": row["recipient_id"] or "",
                    "transaction_type": row["transaction_type"],
                    "amount": safe_float(row["amount"]),
                    "location": row["location"] or "",
                    "payment_method": row["payment_method"] or "",
                    "sender_iban": row["sender_iban"] or "",
                    "recipient_iban": row["recipient_iban"] or "",
                    "balance_after": safe_float(row["balance_after"]),
                    "description": row["description"] or "",
                    "timestamp": row["timestamp"],
                    "user_id": user_id,
                    "direction": direction,
                    "counterparty_id": counterparty_id or "",
                    "counterparty_iban": counterparty_iban or "",
                }
            )

        conn.executemany(
            """
            INSERT INTO transactions (
                transaction_id, sender_id, recipient_id, transaction_type, amount,
                location, payment_method, sender_iban, recipient_iban, balance_after,
                description, timestamp, user_id, direction, counterparty_id,
                counterparty_iban
            )
            VALUES (
                :transaction_id, :sender_id, :recipient_id, :transaction_type, :amount,
                :location, :payment_method, :sender_iban, :recipient_iban, :balance_after,
                :description, :timestamp, :user_id, :direction, :counterparty_id,
                :counterparty_iban
            )
            """,
            inserts,
        )

    def _ingest_locations(
        self,
        conn: sqlite3.Connection,
        rows: list[dict[str, object]],
        user_by_id: dict[str, dict[str, object]],
    ) -> None:
        inserts = [
            {
                "user_id": row["biotag"],
                "timestamp": row["timestamp"],
                "lat": float(row["lat"]),
                "lng": float(row["lng"]),
                "city": row["city"],
            }
            for row in rows
            if row["biotag"] in user_by_id
        ]
        conn.executemany(
            """
            INSERT INTO locations (user_id, timestamp, lat, lng, city)
            VALUES (:user_id, :timestamp, :lat, :lng, :city)
            """,
            inserts,
        )

    def _ingest_sms(
        self,
        conn: sqlite3.Connection,
        rows: list[dict[str, str]],
        users: list[dict[str, object]],
    ) -> None:
        phone_to_messages: dict[str, list[str]] = defaultdict(list)
        for entry in rows:
            raw = entry["sms"]
            phone_match = re.search(r"^To:\s*(.+)$", raw, re.MULTILINE)
            if phone_match:
                phone_to_messages[phone_match.group(1).strip()].append(raw)

        phone_to_user = self._resolve_sms_owners(phone_to_messages, users)
        inserts = []
        for entry in rows:
            raw = entry["sms"]
            phone_match = re.search(r"^To:\s*(.+)$", raw, re.MULTILINE)
            date_match = re.search(r"^Date:\s*(.+)$", raw, re.MULTILINE)
            sender_match = re.search(r"^From:\s*(.+)$", raw, re.MULTILINE)
            body_match = re.search(r"^Message:\s*(.+)$", raw, re.MULTILINE | re.DOTALL)
            if not (phone_match and date_match and body_match):
                continue
            phone = phone_match.group(1).strip()
            resolved = phone_to_user[phone]
            inserts.append(
                {
                    "source_type": "sms",
                    "user_id": resolved["user_id"],
                    "owner_label": phone,
                    "sender_label": sender_match.group(1).strip() if sender_match else "",
                    "sender_address": "",
                    "timestamp": str(
                        datetime.strptime(date_match.group(1).strip(), "%Y-%m-%d %H:%M:%S")
                    ),
                    "subject": "",
                    "body_text": body_match.group(1).strip(),
                    "raw": raw,
                    "urls_json": json.dumps(extract_urls(raw)),
                }
            )

        conn.executemany(
            """
            INSERT INTO messages (
                source_type, user_id, owner_label, sender_label, sender_address,
                timestamp, subject, body_text, raw, urls_json
            )
            VALUES (
                :source_type, :user_id, :owner_label, :sender_label, :sender_address,
                :timestamp, :subject, :body_text, :raw, :urls_json
            )
            """,
            inserts,
        )

    def _resolve_sms_owners(
        self, phone_to_messages: dict[str, list[str]], users: list[dict[str, object]]
    ) -> dict[str, dict[str, str]]:
        user_features = []
        for user in users:
            first = normalize_text(str(user["first_name"]))
            full = normalize_text(str(user["full_name"]))
            city = normalize_text(str(user["city"]))
            job_token = normalize_text(str(user["job"])).split(" ")[0]
            user_features.append(
                {
                    "user_id": str(user["user_id"]),
                    "full_name": str(user["full_name"]),
                    "first": first,
                    "full": full,
                    "city": city,
                    "job": job_token,
                }
            )

        score_map: dict[str, list[tuple[int, str]]] = {}
        for phone, messages in phone_to_messages.items():
            corpus = normalize_text("\n".join(messages))
            scores = []
            for user in user_features:
                first = user["first"]
                full = user["full"]
                city = user["city"]
                job = user["job"]
                score = 0
                if first:
                    score += corpus.count(first) * 18
                    score += corpus.count(f"hi {first}") * 24
                if full:
                    score += corpus.count(full) * 30
                if city:
                    score += corpus.count(city) * 8
                if job:
                    score += corpus.count(job) * 2
                scores.append((score, user["full_name"]))
            scores.sort(reverse=True)
            score_map[phone] = scores

        remaining_users = {user["full_name"] for user in user_features}
        assignments: dict[str, dict[str, str]] = {}
        unresolved = set(score_map)

        while unresolved and remaining_users:
            best_phone = None
            best_choice = None
            best_margin = -1
            for phone in unresolved:
                available = [
                    (score, name)
                    for score, name in score_map[phone]
                    if name in remaining_users
                ]
                if not available:
                    continue
                top_score, top_name = available[0]
                runner_up = available[1][0] if len(available) > 1 else -1
                margin = top_score - runner_up
                if top_score > 0 and (margin > best_margin or best_phone is None):
                    best_phone = phone
                    best_choice = top_name
                    best_margin = margin
            if best_phone is None or best_choice is None:
                break
            user_row = next(item for item in user_features if item["full_name"] == best_choice)
            assignments[best_phone] = {
                "user_id": user_row["user_id"],
                "full_name": user_row["full_name"],
            }
            unresolved.remove(best_phone)
            remaining_users.remove(best_choice)

        for phone in unresolved:
            available = [
                name
                for _, name in score_map[phone]
                if name in remaining_users
            ]
            fallback_name = available[0] if available else score_map[phone][0][1]
            user_row = next(item for item in user_features if item["full_name"] == fallback_name)
            assignments[phone] = {
                "user_id": user_row["user_id"],
                "full_name": user_row["full_name"],
            }
            remaining_users.discard(fallback_name)

        return assignments

    def _ingest_mails(
        self,
        conn: sqlite3.Connection,
        rows: list[dict[str, str]],
        user_by_name: dict[str, dict[str, object]],
    ) -> None:
        inserts = []
        for entry in rows:
            raw = entry["mail"]
            headers = parse_email_headers(raw)
            to_name, to_email = parse_to_name_and_email(headers["to"])
            from_name, from_email = parse_from_name_and_email(headers["from"])
            user = user_by_name.get(to_name)
            if not user:
                continue
            body = raw.split("\n\n", 1)[1] if "\n\n" in raw else raw
            inserts.append(
                {
                    "source_type": "mail",
                    "user_id": str(user["user_id"]),
                    "owner_label": to_name,
                    "sender_label": from_name,
                    "sender_address": from_email or "",
                    "timestamp": str(parse_datetime(headers["date"])),
                    "subject": headers["subject"],
                    "body_text": strip_html(body),
                    "raw": raw,
                    "urls_json": json.dumps(extract_urls(raw)),
                }
            )

        conn.executemany(
            """
            INSERT INTO messages (
                source_type, user_id, owner_label, sender_label, sender_address,
                timestamp, subject, body_text, raw, urls_json
            )
            VALUES (
                :source_type, :user_id, :owner_label, :sender_label, :sender_address,
                :timestamp, :subject, :body_text, :raw, :urls_json
            )
            """,
            inserts,
        )

    def _ingest_audio(
        self,
        conn: sqlite3.Connection,
        audio_dir: Path,
        user_by_name: dict[str, dict[str, object]],
    ) -> None:
        inserts = []
        if not audio_dir.exists():
            return
        for path in sorted(audio_dir.glob("*.mp3")):
            name = path.stem
            match = re.match(r"(\d{8})_(\d{6})-(.+)$", name)
            if not match:
                continue
            date_part, time_part, raw_name = match.groups()
            normalized_name = normalize_text(raw_name.replace("_", " "))
            resolved_user = None
            for full_name, user in user_by_name.items():
                if normalize_text(full_name) == normalized_name:
                    resolved_user = user
                    break
            if not resolved_user:
                continue
            timestamp = datetime.strptime(
                f"{date_part}{time_part}",
                "%Y%m%d%H%M%S",
            )
            inserts.append(
                {
                    "user_id": str(resolved_user["user_id"]),
                    "full_name": str(resolved_user["full_name"]),
                    "timestamp": str(timestamp),
                    "path": str(path),
                }
            )

        conn.executemany(
            """
            INSERT INTO audio_events (user_id, full_name, timestamp, path)
            VALUES (:user_id, :full_name, :timestamp, :path)
            """,
            inserts,
        )
