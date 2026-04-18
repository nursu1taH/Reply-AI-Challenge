from __future__ import annotations

import csv
import io
import json
import zipfile
from datetime import datetime
from pathlib import Path

from .models import DatasetBundle, LocationPing, MessageEvent, Transaction, UserProfile


REQUIRED_FILES = {
    "transactions.csv",
    "users.json",
    "locations.json",
    "sms.json",
    "mails.json",
}


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%a, %d %b %Y %H:%M:%S %z"):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo:
                return parsed.replace(tzinfo=None)
            return parsed
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _extract_message_metadata(raw_text: str, channel: str) -> MessageEvent:
    first_line = ""
    subject = ""
    date_value = None
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not first_line and stripped:
            first_line = stripped
        lowered = stripped.lower()
        if lowered.startswith("subject:"):
            subject = stripped
        elif lowered.startswith("date:"):
            date_value = stripped.split(":", 1)[1].strip()
    return MessageEvent(
        channel=channel,
        raw_text=raw_text,
        timestamp=_parse_datetime(date_value),
        first_line=first_line,
        subject=subject,
    )


def _read_file_map_from_zip(path: Path) -> dict[str, bytes]:
    with zipfile.ZipFile(path) as archive:
        selected: dict[str, bytes] = {}
        for name in archive.namelist():
            basename = Path(name).name
            if basename in REQUIRED_FILES and not basename.startswith("._"):
                selected[basename] = archive.read(name)
        missing = REQUIRED_FILES.difference(selected)
        if missing:
            missing_text = ", ".join(sorted(missing))
            raise FileNotFoundError(f"Dataset zip is missing required files: {missing_text}")
        return selected


def _read_file_map_from_dir(path: Path) -> dict[str, bytes]:
    selected: dict[str, bytes] = {}
    for candidate in path.rglob("*"):
        if candidate.is_file() and candidate.name in REQUIRED_FILES and not candidate.name.startswith("._"):
            selected[candidate.name] = candidate.read_bytes()
    missing = REQUIRED_FILES.difference(selected)
    if missing:
        missing_text = ", ".join(sorted(missing))
        raise FileNotFoundError(f"Dataset folder is missing required files: {missing_text}")
    return selected


def _load_transactions(raw_bytes: bytes) -> list[Transaction]:
    decoded = raw_bytes.decode("utf-8")
    reader = csv.DictReader(io.StringIO(decoded))
    items: list[Transaction] = []
    for row in reader:
        balance_after = row["balance_after"].strip()
        items.append(
            Transaction(
                transaction_id=row["transaction_id"],
                sender_id=row["sender_id"],
                recipient_id=row["recipient_id"].strip(),
                transaction_type=row["transaction_type"].strip(),
                amount=float(row["amount"]),
                location=row["location"].strip(),
                payment_method=row["payment_method"].strip(),
                sender_iban=row["sender_iban"].strip(),
                recipient_iban=row["recipient_iban"].strip(),
                balance_after=float(balance_after) if balance_after else None,
                description=row["description"].strip(),
                timestamp=datetime.fromisoformat(row["timestamp"]),
            )
        )
    items.sort(key=lambda item: item.timestamp)
    return items


def _load_users(raw_bytes: bytes) -> list[UserProfile]:
    decoded = raw_bytes.decode("utf-8")
    payload = json.loads(decoded)
    users: list[UserProfile] = []
    for item in payload:
        users.append(
            UserProfile(
                first_name=item["first_name"].strip(),
                last_name=item["last_name"].strip(),
                birth_year=int(item["birth_year"]),
                salary=float(item["salary"]),
                job=item["job"].strip(),
                iban=item["iban"].strip(),
                residence_city=item["residence"]["city"].strip(),
                residence_lat=float(item["residence"]["lat"]),
                residence_lng=float(item["residence"]["lng"]),
                description=item["description"].strip(),
            )
        )
    return users


def _load_locations(raw_bytes: bytes) -> list[LocationPing]:
    decoded = raw_bytes.decode("utf-8")
    payload = json.loads(decoded)
    locations: list[LocationPing] = []
    for item in payload:
        locations.append(
            LocationPing(
                biotag=item["biotag"].strip(),
                timestamp=datetime.fromisoformat(item["timestamp"]),
                lat=float(item["lat"]),
                lng=float(item["lng"]),
                city=item["city"].strip(),
            )
        )
    locations.sort(key=lambda item: item.timestamp)
    return locations


def _load_messages(raw_bytes: bytes, channel: str) -> list[MessageEvent]:
    decoded = raw_bytes.decode("utf-8")
    payload = json.loads(decoded)
    key = "sms" if channel == "sms" else "mail"
    messages = [_extract_message_metadata(item[key], channel) for item in payload]
    messages.sort(key=lambda item: item.timestamp or datetime.min)
    return messages


def load_dataset(source: str | Path) -> DatasetBundle:
    source_path = Path(source)
    if source_path.suffix.lower() == ".zip":
        file_map = _read_file_map_from_zip(source_path)
    else:
        file_map = _read_file_map_from_dir(source_path)
    return DatasetBundle(
        source_path=str(source_path.resolve()),
        transactions=_load_transactions(file_map["transactions.csv"]),
        users=_load_users(file_map["users.json"]),
        locations=_load_locations(file_map["locations.json"]),
        sms=_load_messages(file_map["sms.json"], "sms"),
        mails=_load_messages(file_map["mails.json"], "mail"),
    )
