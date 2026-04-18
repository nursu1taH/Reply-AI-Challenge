from __future__ import annotations

import email
import email.utils
import json
import math
import re
import sqlite3
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from html import unescape
from statistics import median, pstdev
from urllib.parse import urlparse

from .config import AgentConfig, generate_session_id, load_env
from .database import build_database, reset_analysis_tables

PHISH_KEYWORDS = {
    "urgent": 0.12,
    "verify": 0.16,
    "suspicious": 0.12,
    "security": 0.08,
    "password": 0.18,
    "identity": 0.14,
    "customs": 0.20,
    "parcel": 0.12,
    "delivery": 0.10,
    "held": 0.14,
    "lottery": 0.24,
    "winner": 0.22,
    "claim": 0.18,
    "fee": 0.12,
    "pay": 0.10,
    "payment": 0.10,
    "wallet": 0.16,
    "crypto": 0.24,
    "gift card": 0.24,
    "suspension": 0.18,
    "action required": 0.18,
    "sign-in": 0.18,
}

OFFICIAL_DOMAINS = {
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de"),
    "dhl": ("dhl.com", "dhl.co.uk"),
    "paypal": ("paypal.com",),
    "fedex": ("fedex.com",),
    "government": ("gov.uk", "dresden.de"),
}

SHORTENERS = ("bit.ly", "tinyurl.com", "t.co")
URL_PATTERN = re.compile(r"https?://[^\s\"'>]+", re.IGNORECASE)
CURRENCY_PATTERN = re.compile(r"(?:[$€£]\s?\d+(?:\.\d{1,2})?)", re.IGNORECASE)
HTML_TAG_PATTERN = re.compile(r"<[^>]+>")
JSON_BLOCK_PATTERN = re.compile(r"\{.*\}", re.DOTALL)


@dataclass(slots=True)
class UserProfile:
    sender_id: str
    full_name: str
    first_name: str
    city: str
    residence_lat: float
    residence_lng: float
    salary: float
    description: str
    vulnerability_score: float


@dataclass(slots=True)
class CommunicationEvent:
    user_id: str
    channel: str
    timestamp: datetime
    risk_score: float
    theme: str
    requested_amounts: list[float]
    summary: str
    raw_excerpt: str


@dataclass(slots=True)
class LocationEvent:
    timestamp: datetime
    lat: float
    lng: float
    city: str


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

    @property
    def city(self) -> str:
        if not self.location:
            return ""
        return self.location.split(" - ", 1)[0].strip()


@dataclass(slots=True)
class ReviewResult:
    fraud_probability: float
    decision: str
    confidence: float
    reasons: list[str]
    raw_response: str


@dataclass(slots=True)
class ScoredTransaction:
    transaction: TransactionRecord
    base_score: float
    final_score: float
    reasons: list[str]
    reviewed: bool = False
    review: ReviewResult | None = None


@dataclass
class SenderHistory:
    transactions: list[TransactionRecord] = field(default_factory=list)
    recent_window: deque[TransactionRecord] = field(default_factory=deque)
    amounts_by_type: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    hours_by_type: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    recipient_amounts: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    recipient_counts: Counter[str] = field(default_factory=Counter)
    location_counts: Counter[str] = field(default_factory=Counter)
    city_counts: Counter[str] = field(default_factory=Counter)
    description_counts: Counter[str] = field(default_factory=Counter)

    def add(self, transaction: TransactionRecord) -> None:
        self.transactions.append(transaction)
        self.recent_window.append(transaction)
        self.amounts_by_type[transaction.transaction_type].append(transaction.amount)
        self.hours_by_type[transaction.transaction_type].append(transaction.timestamp.hour)
        if transaction.recipient_id:
            self.recipient_counts[transaction.recipient_id] += 1
            self.recipient_amounts[transaction.recipient_id].append(transaction.amount)
        if transaction.location:
            self.location_counts[transaction.location] += 1
            if transaction.city:
                self.city_counts[transaction.city] += 1
        cleaned_desc = normalize_description(transaction.description)
        if cleaned_desc:
            self.description_counts[cleaned_desc] += 1

    def prune_recent(self, now: datetime, window: timedelta) -> None:
        while self.recent_window and now - self.recent_window[0].timestamp > window:
            self.recent_window.popleft()


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.strip())


def parse_mail_datetime(value: str) -> datetime:
    parsed = email.utils.parsedate_to_datetime(value)
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed


def compact_text(text: str, max_length: int) -> str:
    clean = unescape(HTML_TAG_PATTERN.sub(" ", text))
    clean = re.sub(r"\s+", " ", clean).strip()
    if len(clean) <= max_length:
        return clean
    return clean[: max_length - 3].rstrip() + "..."


def extract_header_value(text: str, field_name: str) -> str:
    pattern = re.compile(rf"^{re.escape(field_name)}:\s*(.+)$", re.MULTILINE)
    match = pattern.search(text)
    return match.group(1).strip() if match else ""


def extract_mail_text(raw_mail: str) -> str:
    message = email.message_from_string(raw_mail)
    if message.is_multipart():
        parts = []
        for part in message.walk():
            if part.get_content_type() not in {"text/plain", "text/html"}:
                continue
            payload = part.get_payload(decode=True)
            if payload:
                parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="ignore"))
        if parts:
            return "\n".join(parts)
    payload = message.get_payload(decode=True)
    if payload:
        return payload.decode(message.get_content_charset() or "utf-8", errors="ignore")
    return raw_mail


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    index = (len(values) - 1) * q
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return values[lower]
    fraction = index - lower
    return values[lower] * (1 - fraction) + values[upper] * fraction


def mean_plus_sigma(values: list[float], sigma: float) -> float:
    if not values:
        return 0.0
    mean = sum(values) / len(values)
    deviation = pstdev(values) if len(values) > 1 else 0.0
    return mean + sigma * deviation


def normalize_description(description: str) -> str:
    if not description:
        return ""
    text = description.lower()
    text = re.sub(r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\b", "", text)
    text = re.sub(r"\b\d{4,}\b", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def robust_amount_score(amount: float, reference_values: list[float]) -> float:
    med = median(reference_values)
    deviations = [abs(value - med) for value in reference_values]
    mad = median(deviations) if deviations else 0.0
    if mad < max(1.0, med * 0.08):
        mad = max(1.0, med * 0.12)
    z_score = abs(amount - med) / mad
    return 0.34 * clamp((z_score - 3.0) / 7.0)


def is_rare_hour(hour: int, historical_hours: list[int]) -> bool:
    if len(historical_hours) < 10:
        return hour in {0, 1, 2, 3, 4}
    counts = Counter(historical_hours)
    return counts[hour] / len(historical_hours) < 0.04 or (hour in {0, 1, 2, 3, 4} and counts[hour] == 0)


def matches_requested_amount(transaction_amount: float, requested_amounts: list[float]) -> bool:
    for amount in requested_amounts:
        if amount < 5:
            continue
        gap = abs(transaction_amount - amount)
        if gap <= 6 or gap / max(amount, 1.0) <= 0.18:
            return True
    return False


def extract_currency_amounts(text: str) -> list[float]:
    values = []
    for token in CURRENCY_PATTERN.findall(text):
        number = re.sub(r"[^0-9.]", "", token)
        if not number:
            continue
        try:
            values.append(float(number))
        except ValueError:
            continue
    return values


def domain_matches(domain: str, allowed_domains: tuple[str, ...]) -> bool:
    return any(domain == allowed or domain.endswith(f".{allowed}") for allowed in allowed_domains)


def suspicious_domain_risk(body: str, domain: str) -> float:
    score = 0.0
    if not domain:
        return score

    labels = domain.split(".")
    if any(any(char.isdigit() for char in label) for label in labels):
        score += 0.12
    if domain.count("-") >= 2:
        score += 0.08

    if "amazon" in body and not domain_matches(domain, OFFICIAL_DOMAINS["amazon"]):
        score += 0.18
    if "dhl" in body and not domain_matches(domain, OFFICIAL_DOMAINS["dhl"]):
        score += 0.18
    if "paypal" in body and not domain_matches(domain, OFFICIAL_DOMAINS["paypal"]):
        score += 0.18
    if "fedex" in body and not domain_matches(domain, OFFICIAL_DOMAINS["fedex"]):
        score += 0.12
    if "government" in body and not domain_matches(domain, OFFICIAL_DOMAINS["government"]):
        score += 0.10
    return score


def infer_theme(keyword: str) -> str:
    if keyword in {"customs", "parcel", "delivery", "held"}:
        return "parcel_fee"
    if keyword in {"verify", "security", "password", "identity", "sign-in", "suspicious", "suspension"}:
        return "credential_theft"
    if keyword in {"lottery", "winner", "claim"}:
        return "reward_scam"
    if keyword in {"gift card", "wallet", "crypto"}:
        return "crypto_or_gift"
    return "payment_request"


def build_communication_event(
    user_id: str,
    channel: str,
    timestamp: datetime,
    body: str,
) -> CommunicationEvent | None:
    clean_body = compact_text(body, 600).lower()
    risk = 0.0
    theme_scores = Counter()

    for keyword, weight in PHISH_KEYWORDS.items():
        if keyword in clean_body:
            risk += weight
            theme_scores[infer_theme(keyword)] += weight

    urls = URL_PATTERN.findall(body)
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if any(shortener in domain for shortener in SHORTENERS):
            risk += 0.05
        risk += suspicious_domain_risk(clean_body, domain)

    if "48h" in clean_body or "24h" in clean_body:
        risk += 0.08
    if "reply stop" in clean_body and risk < 0.16:
        risk -= 0.04
    if "we will never ask for passwords" in clean_body:
        risk -= 0.08
    if "gov.uk" in clean_body or "dresden.de" in clean_body:
        risk -= 0.05

    risk = clamp(risk)
    if risk < 0.18:
        return None

    theme = theme_scores.most_common(1)[0][0] if theme_scores else "generic_phishing"
    excerpt = compact_text(body, 280)
    requested_amounts = extract_currency_amounts(body)
    summary = f"{channel} flagged as {theme} with risk {risk:.2f}"
    return CommunicationEvent(
        user_id=user_id,
        channel=channel,
        timestamp=timestamp,
        risk_score=risk,
        theme=theme,
        requested_amounts=requested_amounts,
        summary=summary,
        raw_excerpt=excerpt,
    )


def score_user_vulnerability(description: str) -> float:
    text = description.lower()
    score = 0.0
    markers = {
        "click": 0.22,
        "questionable": 0.18,
        "unfamiliar messages": 0.18,
        "attention can waver": 0.20,
        "not unflappable": 0.20,
        "impulsive": 0.18,
        "falls for": 0.22,
        "digital details": 0.10,
        "pragmatic, but not": 0.12,
        "can be distracted": 0.14,
    }
    for marker, weight in markers.items():
        if marker in text:
            score += weight
    return clamp(score)


def theme_matches_transaction(theme: str, transaction: TransactionRecord) -> bool:
    tx_type = transaction.transaction_type
    description = transaction.description.lower()
    location = transaction.location.lower()
    if theme == "parcel_fee":
        return tx_type in {"e-commerce", "transfer"} or "market" in location or "delivery" in description
    if theme == "credential_theft":
        return tx_type in {"e-commerce", "transfer", "withdrawal"}
    if theme == "reward_scam":
        return tx_type in {"transfer", "e-commerce"}
    if theme == "payment_request":
        return tx_type in {"transfer", "e-commerce"}
    if theme == "crypto_or_gift":
        return tx_type == "transfer"
    return tx_type in {"transfer", "e-commerce", "withdrawal"}


def parse_review_json(text: str) -> dict[str, object] | None:
    stripped = text.strip()
    match = JSON_BLOCK_PATTERN.search(stripped)
    if match:
        stripped = match.group(0)
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def dedupe_preserve_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    radius = 6371.0
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lng = math.radians(lng2 - lng1)
    a = (
        math.sin(delta_lat / 2) ** 2
        + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lng / 2) ** 2
    )
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return radius * c


class CommunicationScoutAgent:
    def __init__(self, users: dict[str, UserProfile]) -> None:
        self.users = users

    def build_events(
        self,
        sms_rows: list[sqlite3.Row],
        email_rows: list[sqlite3.Row],
    ) -> dict[str, list[CommunicationEvent]]:
        events_by_user: dict[str, list[CommunicationEvent]] = defaultdict(list)

        for event in self._build_sms_events(sms_rows):
            events_by_user[event.user_id].append(event)
        for event in self._build_email_events(email_rows):
            events_by_user[event.user_id].append(event)

        for user_id in events_by_user:
            events_by_user[user_id].sort(key=lambda item: item.timestamp)
        return events_by_user

    def _build_sms_events(self, sms_rows: list[sqlite3.Row]):
        grouped: dict[str, list[str]] = defaultdict(list)
        parsed_rows: list[tuple[str, str]] = []
        for row in sms_rows:
            raw_text = row["raw_text"]
            phone = extract_header_value(raw_text, "To")
            grouped[phone].append(raw_text)
            parsed_rows.append((phone, raw_text))

        phone_to_user = self._infer_sms_mapping(grouped)
        for phone, raw_text in parsed_rows:
            user_id = phone_to_user.get(phone)
            if not user_id:
                continue
            event = build_communication_event(
                user_id=user_id,
                channel="sms",
                timestamp=parse_timestamp(extract_header_value(raw_text, "Date")),
                body=raw_text,
            )
            if event is not None:
                yield event

    def _build_email_events(self, email_rows: list[sqlite3.Row]):
        name_lookup = {profile.full_name.lower(): profile.sender_id for profile in self.users.values()}
        for row in email_rows:
            raw_text = row["raw_text"]
            message = email.message_from_string(raw_text)
            to_header = message.get("To", "")
            user_id = ""
            for name, sender_id in name_lookup.items():
                if name in to_header.lower():
                    user_id = sender_id
                    break
            if not user_id:
                continue
            timestamp = parse_mail_datetime(message.get("Date", ""))
            body = extract_mail_text(raw_text)
            event = build_communication_event(
                user_id=user_id,
                channel="mail",
                timestamp=timestamp,
                body=body,
            )
            if event is not None:
                yield event

    def _infer_sms_mapping(self, grouped_messages: dict[str, list[str]]) -> dict[str, str]:
        candidates: list[tuple[str, list[tuple[float, str]]]] = []
        for phone, messages in grouped_messages.items():
            corpus = "\n".join(messages).lower()
            scores: list[tuple[float, str]] = []
            for profile in self.users.values():
                score = 0.0
                score += corpus.count(profile.first_name.lower()) * 3.0
                score += corpus.count(profile.full_name.lower()) * 5.0
                score += corpus.count(profile.city.lower()) * 0.5
                if score:
                    scores.append((score, profile.sender_id))
            scores.sort(reverse=True)
            candidates.append((phone, scores))

        assignments: dict[str, str] = {}
        used_users: set[str] = set()
        candidates.sort(key=lambda item: item[1][0][0] if item[1] else 0.0, reverse=True)
        for phone, scored_users in candidates:
            for _, sender_id in scored_users:
                if sender_id not in used_users:
                    assignments[phone] = sender_id
                    used_users.add(sender_id)
                    break
        return assignments


class MobilitySentinelAgent:
    def __init__(
        self,
        user_locations: dict[str, list[LocationEvent]],
        city_centroids: dict[str, tuple[float, float]],
        users: dict[str, UserProfile],
    ) -> None:
        self.user_locations = user_locations
        self.city_centroids = city_centroids
        self.users = users

    def score(self, transaction: TransactionRecord, history: SenderHistory) -> tuple[float, list[str]]:
        if not transaction.location or transaction.sender_id not in self.users:
            return 0.0, []

        city = transaction.city
        target = self.city_centroids.get(city)
        if target is None:
            return 0.0, []

        events = self.user_locations.get(transaction.sender_id, [])
        if not events:
            return 0.0, []

        nearest = min(events, key=lambda event: abs((transaction.timestamp - event.timestamp).total_seconds()))
        delta_hours = abs((transaction.timestamp - nearest.timestamp).total_seconds()) / 3600.0
        distance = haversine_km(target[0], target[1], nearest.lat, nearest.lng)
        score = 0.0
        reasons: list[str] = []

        if delta_hours <= 1 and distance > 180:
            score += 0.34
            reasons.append(f"location mismatch: {city} is {distance:.0f}km from closest GPS ping within 1h")
        elif delta_hours <= 6 and distance > 90:
            score += 0.24
            reasons.append(f"location mismatch: {city} is {distance:.0f}km from closest GPS ping within 6h")
        elif delta_hours <= 24 and distance > 160:
            score += 0.14
            reasons.append(f"location mismatch persists over 24h window ({distance:.0f}km)")

        profile = self.users[transaction.sender_id]
        recent_same_city = any(
            event.city == city and abs((transaction.timestamp - event.timestamp).total_seconds()) <= 7 * 24 * 3600
            for event in events
        )
        if history.city_counts[city] == 0 and not recent_same_city:
            distance_from_home = haversine_km(
                target[0], target[1], profile.residence_lat, profile.residence_lng
            )
            if distance_from_home > 300:
                score += 0.10
                reasons.append(f"new in-person city far from residence ({distance_from_home:.0f}km)")

        return clamp(score), reasons


class BehavioralAnomalyAgent:
    def __init__(self, users: dict[str, UserProfile], recipient_popularity: Counter[str]) -> None:
        self.users = users
        self.recipient_popularity = recipient_popularity

    def score(self, transaction: TransactionRecord, history: SenderHistory) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []
        prior_count = len(history.transactions)

        if self._looks_recurring_legit(transaction, history):
            score -= 0.40
            reasons.append("recurring pattern matches established legitimate payment")

        type_amounts = history.amounts_by_type[transaction.transaction_type]
        if len(type_amounts) >= 5:
            anomaly = robust_amount_score(transaction.amount, type_amounts)
            if transaction.transaction_type == "transfer":
                anomaly *= 0.80
            elif transaction.transaction_type == "direct debit":
                anomaly *= 0.60
            if anomaly >= 0.18:
                score += anomaly
                reasons.append("amount deviates from sender baseline for this transaction type")

        if transaction.recipient_id and prior_count >= 6 and history.recipient_counts[transaction.recipient_id] == 0:
            score += 0.16
            reasons.append("new recipient for this sender")
            if self.recipient_popularity[transaction.recipient_id] <= 1:
                score += 0.06
                reasons.append("recipient is globally rare in the dataset")

        if transaction.location and prior_count >= 8 and history.location_counts[transaction.location] == 0:
            score += 0.10
            reasons.append("new merchant or ATM location for this sender")

        if transaction.city and prior_count >= 8 and history.city_counts[transaction.city] == 0:
            score += 0.08
            reasons.append("new city for this sender's card-present activity")

        if is_rare_hour(transaction.timestamp.hour, history.hours_by_type[transaction.transaction_type]):
            score += 0.12
            reasons.append("unusual transaction hour for the sender")

        history.prune_recent(transaction.timestamp, timedelta(hours=3))
        recent = list(history.recent_window)
        if len(recent) >= 3:
            score += 0.08
            reasons.append("high short-term transaction burst")
        if transaction.transaction_type == "withdrawal":
            recent_withdrawals = sum(1 for item in recent if item.transaction_type == "withdrawal")
            if recent_withdrawals >= 2:
                score += 0.10
                reasons.append("clustered ATM withdrawals")

        balance_before = transaction.amount + transaction.balance_after
        if balance_before > 0:
            drain_ratio = transaction.amount / balance_before
            if drain_ratio >= 0.82:
                score += 0.22
                reasons.append("transaction drains most of the available balance")
            elif drain_ratio >= 0.55:
                score += 0.12
                reasons.append("transaction consumes an unusually large share of the balance")

        if transaction.sender_id not in self.users and transaction.sender_id.startswith("EMP") and transaction.description.startswith("Salary payment"):
            score -= 0.45
            reasons.append("salary transfer from employer pattern")

        if transaction.transaction_type == "direct debit" and "monthly" in transaction.description.lower():
            score -= 0.20
            reasons.append("direct debit description looks like a recurring bill")

        return clamp(score), reasons

    def _looks_recurring_legit(self, transaction: TransactionRecord, history: SenderHistory) -> bool:
        description_key = normalize_description(transaction.description)
        if description_key and history.description_counts[description_key] >= 2:
            return True

        if transaction.recipient_id and history.recipient_counts[transaction.recipient_id] >= 3:
            peer_amounts = history.recipient_amounts[transaction.recipient_id]
            peer_median = median(peer_amounts)
            if peer_median > 0 and abs(transaction.amount - peer_median) / peer_median <= 0.12:
                return True

        if transaction.description.lower().startswith("salary payment"):
            return True

        recurring_markers = (
            "rent payment",
            "insurance",
            "subscription",
            "phone bill",
            "water bill",
            "gas bill",
            "electricity bill",
            "payroll service",
        )
        return any(marker in transaction.description.lower() for marker in recurring_markers)


class SocialEngineeringAgent:
    def __init__(self, events_by_user: dict[str, list[CommunicationEvent]], users: dict[str, UserProfile]) -> None:
        self.events_by_user = events_by_user
        self.users = users

    def score(self, transaction: TransactionRecord) -> tuple[float, list[str]]:
        events = self.events_by_user.get(transaction.sender_id, [])
        if not events:
            return 0.0, []

        score = 0.0
        reasons: list[str] = []
        profile = self.users.get(transaction.sender_id)
        vulnerability = profile.vulnerability_score if profile else 0.0

        for event in reversed(events):
            delta = transaction.timestamp - event.timestamp
            if delta.total_seconds() < 0:
                continue
            if delta > timedelta(days=3):
                break

            age_factor = 1.0
            if delta > timedelta(hours=24):
                age_factor = 0.45
            elif delta > timedelta(hours=6):
                age_factor = 0.70

            event_score = event.risk_score * 0.34 * age_factor
            if vulnerability:
                event_score *= 1.0 + (0.35 * vulnerability)

            if event.requested_amounts and matches_requested_amount(transaction.amount, event.requested_amounts):
                event_score += 0.16
                reasons.append("amount resembles a value requested in a recent suspicious message")

            if theme_matches_transaction(event.theme, transaction):
                event_score += 0.10
                reasons.append("transaction type aligns with a recent scam message theme")

            if event_score >= 0.10:
                reasons.append(
                    f"recent {event.channel} with phishing markers ({event.theme}, score {event.risk_score:.2f})"
                )
                score += event_score

            if len(reasons) >= 4:
                break

        return clamp(score), dedupe_preserve_order(reasons)


class LLMCaseReviewAgent:
    def __init__(self, config: AgentConfig, session_id: str) -> None:
        self.config = config
        self.session_id = session_id
        self._model = None
        self._langfuse_client = None
        self._observe = None
        self._callback_handler_cls = None

    @property
    def available(self) -> bool:
        return self.config.llm_ready

    def review(self, case: ScoredTransaction, user: UserProfile | None, recent_events: list[CommunicationEvent]) -> ReviewResult | None:
        if not self.available:
            return None

        self._ensure_clients()
        assert self._model is not None
        assert self._observe is not None
        assert self._callback_handler_cls is not None

        payload = {
            "transaction": {
                "transaction_id": case.transaction.transaction_id,
                "sender_id": case.transaction.sender_id,
                "recipient_id": case.transaction.recipient_id,
                "transaction_type": case.transaction.transaction_type,
                "amount": case.transaction.amount,
                "location": case.transaction.location,
                "payment_method": case.transaction.payment_method,
                "balance_after": case.transaction.balance_after,
                "description": case.transaction.description,
                "timestamp": case.transaction.timestamp.isoformat(),
            },
            "base_score": round(case.base_score, 4),
            "base_reasons": case.reasons[:8],
            "user_profile": {
                "full_name": user.full_name if user else "",
                "city": user.city if user else "",
                "salary": user.salary if user else 0.0,
                "vulnerability_score": round(user.vulnerability_score, 4) if user else 0.0,
                "description_hint": compact_text(user.description, 280) if user else "",
            },
            "recent_suspicious_events": [
                {
                    "channel": event.channel,
                    "timestamp": event.timestamp.isoformat(),
                    "risk_score": round(event.risk_score, 3),
                    "theme": event.theme,
                    "summary": event.summary,
                }
                for event in recent_events[:4]
            ],
        }

        prompt = (
            "You are the final fraud adjudication agent for the Reply Mirror challenge. "
            "Use the supplied signals to decide whether this transaction should be treated "
            "as likely fraud. Output strict JSON only with keys "
            "fraud_probability, decision, confidence, reasons. "
            "decision must be one of fraud, legit, uncertain. "
            "reasons must contain at most 4 short strings.\n\n"
            f"{json.dumps(payload, ensure_ascii=True)}"
        )

        @self._observe()
        def traced_call() -> str:
            from langchain_core.messages import HumanMessage, SystemMessage

            handler = self._callback_handler_cls()
            response = self._model.invoke(
                [
                    SystemMessage(
                        content=(
                            "Judge fraud risk for a single financial transaction. "
                            "Return compact JSON and do not include markdown."
                        )
                    ),
                    HumanMessage(content=prompt),
                ],
                config={
                    "callbacks": [handler],
                    "metadata": {"langfuse_session_id": self.session_id},
                },
            )
            return response.content

        raw_response = traced_call()
        parsed = parse_review_json(raw_response)
        if parsed is None:
            return None
        return ReviewResult(
            fraud_probability=clamp(float(parsed.get("fraud_probability", 0.5))),
            decision=str(parsed.get("decision", "uncertain")).lower(),
            confidence=clamp(float(parsed.get("confidence", 0.5))),
            reasons=[str(item) for item in parsed.get("reasons", [])[:4]],
            raw_response=raw_response,
        )

    def flush(self) -> None:
        if self._langfuse_client is not None:
            self._langfuse_client.flush()

    def _ensure_clients(self) -> None:
        if self._model is not None:
            return

        import os

        from langchain_openai import ChatOpenAI
        from langfuse import Langfuse, observe
        from langfuse.langchain import CallbackHandler

        self._model = ChatOpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            model=self.config.model_name,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
        )
        self._langfuse_client = Langfuse(
            public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
            secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
            host=os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse"),
        )
        self._observe = observe
        self._callback_handler_cls = CallbackHandler


class BladeRunnerEngine:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        load_env(config.dataset_dir.parent)
        self.config.ensure_directories()
        self.session_id = generate_session_id()

    def run(self) -> dict[str, object]:
        conn = build_database(
            dataset_dir=self.config.dataset_dir,
            database_path=self.config.database_path,
            force_rebuild=self.config.force_rebuild_db,
        )
        reset_analysis_tables(conn)

        users = self._load_users(conn)
        transactions = self._load_transactions(conn)
        sms_rows = conn.execute("SELECT raw_text FROM sms_messages").fetchall()
        email_rows = conn.execute("SELECT raw_text FROM email_messages").fetchall()
        user_locations, city_centroids = self._load_locations(conn)
        recipient_popularity = Counter(
            transaction.recipient_id for transaction in transactions if transaction.recipient_id
        )

        communication_agent = CommunicationScoutAgent(users)
        events_by_user = communication_agent.build_events(sms_rows, email_rows)
        self._persist_communication_events(conn, events_by_user)

        mobility_agent = MobilitySentinelAgent(user_locations, city_centroids, users)
        behavior_agent = BehavioralAnomalyAgent(users, recipient_popularity)
        social_agent = SocialEngineeringAgent(events_by_user, users)
        review_agent = LLMCaseReviewAgent(self.config, self.session_id)

        histories: dict[str, SenderHistory] = defaultdict(SenderHistory)
        scored: list[ScoredTransaction] = []

        for transaction in transactions:
            history = histories[transaction.sender_id]
            behavior_score, behavior_reasons = behavior_agent.score(transaction, history)
            mobility_score, mobility_reasons = mobility_agent.score(transaction, history)
            social_score, social_reasons = social_agent.score(transaction)

            base_score = clamp(behavior_score + mobility_score + social_score)
            reasons = behavior_reasons[:4] + mobility_reasons[:3] + social_reasons[:4]
            scored_case = ScoredTransaction(
                transaction=transaction,
                base_score=base_score,
                final_score=base_score,
                reasons=dedupe_preserve_order(reasons),
            )
            scored.append(scored_case)
            history.add(transaction)

        self._run_llm_reviews(scored, users, events_by_user, review_agent)
        review_agent.flush()

        flagged = select_flagged_transactions(scored, self.config)
        self._persist_scores(conn, scored)
        self._persist_reviews(conn, scored)
        self._write_output(flagged)
        self._write_explanations(scored, flagged)

        return {
            "session_id": self.session_id,
            "database_path": str(self.config.database_path),
            "output_path": str(self.config.output_path),
            "explanation_path": str(self.config.explanation_path),
            "flagged_count": len(flagged),
            "reviewed_count": sum(1 for item in scored if item.reviewed),
            "llm_enabled": review_agent.available,
        }

    def _load_users(self, conn: sqlite3.Connection) -> dict[str, UserProfile]:
        profiles: dict[str, UserProfile] = {}
        for row in conn.execute("SELECT * FROM users").fetchall():
            description = row["description"]
            full_name = f"{row['first_name']} {row['last_name']}"
            profiles[row["sender_id"]] = UserProfile(
                sender_id=row["sender_id"],
                full_name=full_name,
                first_name=row["first_name"],
                city=row["residence_city"],
                residence_lat=float(row["residence_lat"]),
                residence_lng=float(row["residence_lng"]),
                salary=float(row["salary"]),
                description=description,
                vulnerability_score=score_user_vulnerability(description),
            )
        return profiles

    def _load_transactions(self, conn: sqlite3.Connection) -> list[TransactionRecord]:
        records = []
        rows = conn.execute(
            "SELECT * FROM transactions ORDER BY timestamp, transaction_id"
        ).fetchall()
        for row in rows:
            records.append(
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
                    timestamp=parse_timestamp(row["timestamp"]),
                )
            )
        return records

    def _load_locations(
        self, conn: sqlite3.Connection
    ) -> tuple[dict[str, list[LocationEvent]], dict[str, tuple[float, float]]]:
        user_locations: dict[str, list[LocationEvent]] = defaultdict(list)
        city_points: dict[str, list[tuple[float, float]]] = defaultdict(list)
        for row in conn.execute("SELECT * FROM locations ORDER BY timestamp").fetchall():
            event = LocationEvent(
                timestamp=parse_timestamp(row["timestamp"]),
                lat=float(row["lat"]),
                lng=float(row["lng"]),
                city=row["city"],
            )
            user_locations[row["biotag"]].append(event)
            city_points[row["city"]].append((event.lat, event.lng))

        city_centroids = {}
        for city, points in city_points.items():
            city_centroids[city] = (
                sum(lat for lat, _ in points) / len(points),
                sum(lng for _, lng in points) / len(points),
            )
        return user_locations, city_centroids

    def _run_llm_reviews(
        self,
        scored: list[ScoredTransaction],
        users: dict[str, UserProfile],
        events_by_user: dict[str, list[CommunicationEvent]],
        review_agent: LLMCaseReviewAgent,
    ) -> None:
        if not review_agent.available or self.config.max_llm_cases <= 0:
            return

        review_candidates = sorted(scored, key=lambda item: item.base_score, reverse=True)
        review_candidates = [
            item for item in review_candidates if item.base_score >= 0.42
        ][: self.config.max_llm_cases]

        for case in review_candidates:
            recent_events = [
                event
                for event in reversed(events_by_user.get(case.transaction.sender_id, []))
                if timedelta(0)
                <= case.transaction.timestamp - event.timestamp
                <= timedelta(days=3)
            ]
            review = review_agent.review(
                case=case,
                user=users.get(case.transaction.sender_id),
                recent_events=recent_events,
            )
            if review is None:
                continue

            adjustment = (review.fraud_probability - 0.5) * (0.60 * max(review.confidence, 0.35))
            case.final_score = clamp(case.base_score + adjustment)
            case.reviewed = True
            case.review = review
            if review.reasons:
                case.reasons = dedupe_preserve_order(case.reasons + review.reasons)

    def _persist_communication_events(
        self,
        conn: sqlite3.Connection,
        events_by_user: dict[str, list[CommunicationEvent]],
    ) -> None:
        rows = []
        for user_id, events in events_by_user.items():
            for event in events:
                rows.append(
                    (
                        user_id,
                        event.channel,
                        event.timestamp.isoformat(),
                        event.risk_score,
                        event.theme,
                        json.dumps(event.requested_amounts),
                        event.summary,
                        event.raw_excerpt,
                    )
                )
        with conn:
            conn.executemany(
                """
                INSERT INTO communication_events (
                    user_id, channel, timestamp, risk_score, theme,
                    requested_amounts, summary, raw_excerpt
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def _persist_scores(self, conn: sqlite3.Connection, scored: list[ScoredTransaction]) -> None:
        rows = [
            (
                item.transaction.transaction_id,
                item.transaction.sender_id,
                item.transaction.timestamp.isoformat(),
                item.base_score,
                item.final_score,
                int(item.reviewed),
                json.dumps(item.reasons, ensure_ascii=True),
            )
            for item in scored
        ]
        with conn:
            conn.executemany(
                """
                INSERT INTO transaction_scores (
                    transaction_id, sender_id, timestamp, base_score, final_score, reviewed, reasons
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def _persist_reviews(self, conn: sqlite3.Connection, scored: list[ScoredTransaction]) -> None:
        rows = []
        for item in scored:
            if item.review is None:
                continue
            rows.append(
                (
                    item.transaction.transaction_id,
                    item.review.fraud_probability,
                    item.review.decision,
                    item.review.confidence,
                    json.dumps(item.review.reasons, ensure_ascii=True),
                    item.review.raw_response,
                )
            )
        if not rows:
            return
        with conn:
            conn.executemany(
                """
                INSERT INTO llm_reviews (
                    transaction_id, fraud_probability, decision, confidence, reasons, raw_response
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def _write_output(self, flagged: list[ScoredTransaction]) -> None:
        lines = [item.transaction.transaction_id for item in flagged]
        self.config.output_path.write_text("\n".join(lines), encoding="ascii")

    def _write_explanations(self, scored: list[ScoredTransaction], flagged: list[ScoredTransaction]) -> None:
        flagged_ids = {item.transaction.transaction_id for item in flagged}
        payload = {
            "session_id": self.session_id,
            "llm_enabled": self.config.llm_ready,
            "flagged_count": len(flagged),
            "top_flagged": [
                {
                    "transaction_id": item.transaction.transaction_id,
                    "sender_id": item.transaction.sender_id,
                    "transaction_type": item.transaction.transaction_type,
                    "amount": item.transaction.amount,
                    "timestamp": item.transaction.timestamp.isoformat(),
                    "base_score": round(item.base_score, 4),
                    "final_score": round(item.final_score, 4),
                    "reviewed": item.reviewed,
                    "reasons": item.reasons[:8],
                }
                for item in flagged[:50]
            ],
            "score_summary": {
                "total_transactions": len(scored),
                "reviewed_transactions": sum(1 for item in scored if item.reviewed),
                "max_score": round(max(item.final_score for item in scored), 4),
                "min_score": round(min(item.final_score for item in scored), 4),
            },
            "non_flagged_high_scores": [
                {
                    "transaction_id": item.transaction.transaction_id,
                    "final_score": round(item.final_score, 4),
                    "reasons": item.reasons[:6],
                }
                for item in sorted(
                    (item for item in scored if item.transaction.transaction_id not in flagged_ids),
                    key=lambda case: case.final_score,
                    reverse=True,
                )[:20]
            ],
        }
        self.config.explanation_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=True),
            encoding="utf-8",
        )


def select_flagged_transactions(scored: list[ScoredTransaction], config: AgentConfig) -> list[ScoredTransaction]:
    ranked = sorted(scored, key=lambda item: item.final_score, reverse=True)
    scores = [item.final_score for item in ranked]
    threshold = max(percentile(scores, 0.96), mean_plus_sigma(scores, 1.65), 0.48)

    tentative = [item for item in ranked if item.final_score >= threshold]
    total = len(ranked)
    min_count = max(12, int(total * config.min_fraud_rate))
    target_count = max(min_count, int(total * config.target_fraud_rate))
    max_count = max(target_count, int(total * config.max_fraud_rate))

    if len(tentative) < min_count:
        tentative = ranked[:target_count]
    elif len(tentative) > max_count:
        tentative = ranked[:max_count]

    return sorted(tentative, key=lambda item: item.final_score, reverse=True)
