from __future__ import annotations

from datetime import datetime
import csv
import json
from pathlib import Path
import re
import unicodedata
from typing import Dict, Iterable, List, Optional

from .domain import (
    AudioEvent,
    CommunicationEvent,
    DatasetContext,
    TargetProfile,
    Transaction,
    UserProfile,
    normalize_text,
)


COMMUNICATION_KEYWORDS = {
    "urgent": 0.35,
    "verify": 0.45,
    "security": 0.35,
    "suspicious": 0.30,
    "account": 0.15,
    "login": 0.25,
    "locked": 0.25,
    "lottery": 0.65,
    "winner": 0.65,
    "prize": 0.60,
    "refund": 0.30,
    "wallet": 0.45,
    "crypto": 0.40,
    "wire": 0.45,
    "customs": 0.50,
    "release fee": 0.55,
    "invoice": 0.25,
}

SUSPICIOUS_DOMAIN_HINTS = (
    "verify",
    "secure",
    "paypa1",
    "amaz0n",
    "coinbase-secure",
    "release2087",
    "claims-2087",
    "northfinancc",
)


def ascii_fold(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(char for char in normalized if not unicodedata.combining(char)).lower()


def safe_float(raw: str) -> float:
    return float(raw) if raw else 0.0


def extract_phishing_susceptibility(description: str) -> float:
    percent_match = re.search(r"(\d{1,3})\s*%", description)
    if percent_match:
        value = max(0.0, min(100.0, float(percent_match.group(1))))
        return value / 100.0
    probability_match = re.search(r"probability[^0-9]*(\d{1,3})", description.lower())
    if probability_match:
        value = max(0.0, min(100.0, float(probability_match.group(1))))
        return value / 100.0
    return 0.45


def description_category(text: str) -> str:
    lowered = normalize_text(text)
    for key in (
        "salary",
        "rent",
        "gym",
        "insurance",
        "loan",
        "phone",
        "mobile",
        "internet",
        "water",
        "gas",
        "electricity",
        "utility",
        "savings",
        "investment",
        "portfolio",
        "advisor",
        "brokerage",
        "donation",
        "consultant",
        "supplier",
        "invoice",
        "service",
        "software",
        "cloud",
        "meal",
        "union",
        "property tax",
        "dental",
        "stock",
        "office",
        "repair",
    ):
        if key in lowered:
            return key
    return "blank"


def score_communication_risk(text: str) -> float:
    lowered = ascii_fold(text)
    score = 0.0
    hint_found = False
    for keyword, delta in COMMUNICATION_KEYWORDS.items():
        if keyword in lowered:
            score += delta
    for hint in SUSPICIOUS_DOMAIN_HINTS:
        if hint in lowered:
            score += 0.35
            hint_found = True
    if score > 0.0 and re.search(r"https?://[^\s]+", text) and not re.search(
        r"https?://(?:www\.)?(amazon|paypal|coinbase|barclays|chase|dhl|fedex|ups)\.",
        lowered,
    ):
        score += 0.20
    if hint_found and "http" in lowered:
        score += 0.15
    return min(score, 1.6)


def build_user_profiles(dataset_path: Path, transactions: List[Transaction]) -> Dict[str, UserProfile]:
    raw_users = json.loads((dataset_path / "users.json").read_text(encoding="utf-8"))
    iban_to_sender: Dict[str, str] = {}
    for tx in transactions:
        if tx.sender_iban and not tx.sender_id.startswith("EMP"):
            iban_to_sender[tx.sender_iban] = tx.sender_id

    profiles: Dict[str, UserProfile] = {}
    for user in raw_users:
        user_id = iban_to_sender.get(user["iban"])
        if not user_id:
            continue
        profiles[user_id] = UserProfile(
            user_id=user_id,
            first_name=user["first_name"],
            last_name=user["last_name"],
            annual_salary=float(user["salary"]),
            home_city=user["residence"]["city"],
            home_lat=float(user["residence"]["lat"]),
            home_lng=float(user["residence"]["lng"]),
            description=user["description"],
            phishing_susceptibility=extract_phishing_susceptibility(user["description"]),
        )
    return profiles


def load_transactions(dataset_path: Path) -> List[Transaction]:
    rows = csv.DictReader((dataset_path / "transactions.csv").open(encoding="utf-8"))
    return [
        Transaction(
            transaction_id=row["transaction_id"],
            sender_id=row["sender_id"],
            recipient_id=row["recipient_id"],
            transaction_type=row["transaction_type"],
            amount=safe_float(row["amount"]),
            location=row["location"],
            payment_method=row["payment_method"],
            sender_iban=row["sender_iban"],
            recipient_iban=row["recipient_iban"],
            balance_after=safe_float(row["balance_after"]),
            description=row["description"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
        )
        for row in rows
    ]


def build_name_index(users: Dict[str, UserProfile]) -> Dict[str, str]:
    index: Dict[str, str] = {}
    for user_id, profile in users.items():
        first_name = ascii_fold(profile.first_name)
        full_name = ascii_fold(f"{profile.first_name} {profile.last_name}")
        index[first_name] = user_id
        index[full_name] = user_id
    return index


def match_user_from_text(name_index: Dict[str, str], text: str) -> Optional[str]:
    lowered = ascii_fold(text)
    for key, user_id in name_index.items():
        if key and key in lowered:
            return user_id
    return None


def parse_sms_events(dataset_path: Path, name_index: Dict[str, str]) -> Dict[str, List[CommunicationEvent]]:
    raw_sms = json.loads((dataset_path / "sms.json").read_text(encoding="utf-8"))
    events: Dict[str, List[CommunicationEvent]] = {}
    for item in raw_sms:
        text = item["sms"]
        user_id = match_user_from_text(name_index, text)
        if not user_id:
            continue
        timestamp_match = re.search(r"Date:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", text)
        if not timestamp_match:
            continue
        risk_score = score_communication_risk(text)
        if risk_score < 0.35:
            continue
        summary = " | ".join(line.strip() for line in text.splitlines()[:3])
        events.setdefault(user_id, []).append(
            CommunicationEvent(
                user_id=user_id,
                timestamp=datetime.strptime(timestamp_match.group(1), "%Y-%m-%d %H:%M:%S"),
                channel="sms",
                risk_score=risk_score,
                summary=summary[:200],
            )
        )
    return events


def parse_mail_events(dataset_path: Path, name_index: Dict[str, str]) -> Dict[str, List[CommunicationEvent]]:
    raw_mails = json.loads((dataset_path / "mails.json").read_text(encoding="utf-8"))
    events: Dict[str, List[CommunicationEvent]] = {}
    months = {
        month: index
        for index, month in enumerate(
            ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
            start=1,
        )
    }
    for item in raw_mails:
        text = item["mail"]
        risk_score = score_communication_risk(text)
        if risk_score < 0.35:
            continue
        to_match = re.search(r'To:\s*"([^"]+)"', text)
        date_match = re.search(
            r"Date:\s*.*?,\s*(\d{2})\s+(\w{3})\s+(\d{4})\s+(\d{2}:\d{2}:\d{2})",
            text,
        )
        if not (to_match and date_match):
            continue
        user_id = match_user_from_text(name_index, to_match.group(1))
        if not user_id:
            continue
        timestamp = datetime(
            int(date_match.group(3)),
            months[date_match.group(2)],
            int(date_match.group(1)),
            *map(int, date_match.group(4).split(":")),
        )
        subject_match = re.search(r"Subject:\s*(.*)", text)
        subject = subject_match.group(1) if subject_match else "mail alert"
        events.setdefault(user_id, []).append(
            CommunicationEvent(
                user_id=user_id,
                timestamp=timestamp,
                channel="mail",
                risk_score=risk_score,
                summary=subject[:200],
            )
        )
    return events


def merge_event_maps(*maps: Dict[str, List[CommunicationEvent]]) -> Dict[str, List[CommunicationEvent]]:
    merged: Dict[str, List[CommunicationEvent]] = {}
    for current_map in maps:
        for user_id, events in current_map.items():
            merged.setdefault(user_id, []).extend(events)
    for event_list in merged.values():
        event_list.sort(key=lambda event: event.timestamp)
    return merged


def parse_audio_events(dataset_path: Path, users: Dict[str, UserProfile]) -> Dict[str, List[AudioEvent]]:
    audio_dir = dataset_path / "audio"
    if not audio_dir.exists():
        return {}
    normalized_name_index = {
        ascii_fold(f"{profile.first_name}_{profile.last_name}"): user_id
        for user_id, profile in users.items()
    }
    events: Dict[str, List[AudioEvent]] = {}
    pattern = re.compile(r"(\d{8})_(\d{6})-(.+)\.mp3$")
    for file_path in audio_dir.glob("*.mp3"):
        match = pattern.match(file_path.name)
        if not match:
            continue
        speaker_key = ascii_fold(match.group(3))
        user_id = None
        for candidate, mapped_user_id in normalized_name_index.items():
            if candidate in speaker_key or speaker_key in candidate:
                user_id = mapped_user_id
                break
        if not user_id:
            continue
        timestamp = datetime.strptime(f"{match.group(1)}{match.group(2)}", "%Y%m%d%H%M%S")
        events.setdefault(user_id, []).append(
            AudioEvent(user_id=user_id, timestamp=timestamp, file_name=file_path.name)
        )
    for event_list in events.values():
        event_list.sort(key=lambda event: event.timestamp)
    return events


def build_target_profiles(transactions: Iterable[Transaction]) -> Dict[str, TargetProfile]:
    profiles: Dict[str, TargetProfile] = {}
    for tx in transactions:
        target = tx.primary_target
        profile = profiles.setdefault(target, TargetProfile())
        profile.register(tx.sender_id, description_category(tx.description or tx.location), tx.transaction_type)
    return profiles


def load_dataset_context(dataset_path: Path) -> DatasetContext:
    transactions = load_transactions(dataset_path)
    users = build_user_profiles(dataset_path, transactions)
    name_index = build_name_index(users)
    communications = merge_event_maps(
        parse_sms_events(dataset_path, name_index),
        parse_mail_events(dataset_path, name_index),
    )
    audio_events = parse_audio_events(dataset_path, users)
    target_profiles = build_target_profiles(transactions)
    return DatasetContext(
        transactions=sorted(transactions, key=lambda tx: tx.timestamp),
        users=users,
        communications=communications,
        audio_events=audio_events,
        target_profiles=target_profiles,
    )
