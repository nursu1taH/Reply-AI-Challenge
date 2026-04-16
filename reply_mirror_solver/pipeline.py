from __future__ import annotations

import csv
import json
import os
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from statistics import mean, median
from typing import Iterable


KNOWN_PHISHING_MARKERS = (
    "paypa1",
    "amaz0n",
    "ub3r",
    "r1d3share",
    "netfl1x",
    "secure-verify",
    "verify",
    "suspicious login",
    "suspicious sign-in",
    "unusual login",
    "account lock",
)

USER_ID_PREFIXES = ("RGNR", "GRSC", "BRCH")
FRAUD_THRESHOLD = 0.40


@dataclass
class Transaction:
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


@dataclass
class UserProfile:
    user_id: str
    first_name: str
    last_name: str
    birth_year: int
    salary: float
    job: str
    iban: str
    residence_city: str
    description: str


@dataclass
class CommunicationEvidence:
    suspicious_count: int = 0
    suspicious_themes: Counter = field(default_factory=Counter)
    benign_themes: Counter = field(default_factory=Counter)
    suspicious_examples: list[str] = field(default_factory=list)
    benign_examples: list[str] = field(default_factory=list)


@dataclass
class TransactionAssessment:
    transaction_id: str
    sender_id: str
    final_score: float
    heuristic_score: float
    decision: str
    reasons: list[str]
    timestamp: str
    amount: float
    transaction_type: str
    recipient_id: str
    payment_method: str


def parse_dataset(dataset_dir: Path) -> tuple[list[Transaction], dict[str, UserProfile], dict[str, list[dict]], dict[str, list[dict]], dict[str, list[dict]]]:
    transactions_path = dataset_dir / "transactions.csv"
    users_path = dataset_dir / "users.json"
    locations_path = dataset_dir / "locations.json"
    mails_path = dataset_dir / "mails.json"
    sms_path = dataset_dir / "sms.json"

    transactions = []
    with transactions_path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            transactions.append(
                Transaction(
                    transaction_id=row["transaction_id"],
                    sender_id=row["sender_id"],
                    recipient_id=row["recipient_id"],
                    transaction_type=row["transaction_type"],
                    amount=float(row["amount"]),
                    location=row["location"],
                    payment_method=row["payment_method"],
                    sender_iban=row["sender_iban"],
                    recipient_iban=row["recipient_iban"],
                    balance_after=float(row["balance_after"]),
                    description=row["description"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                )
            )

    user_id_by_iban = {
        tx.sender_iban: tx.sender_id
        for tx in transactions
        if tx.sender_id.startswith(USER_ID_PREFIXES)
    }

    users_json = json.loads(users_path.read_text(encoding="utf-8"))
    profiles = {}
    for item in users_json:
        user_id = user_id_by_iban.get(item["iban"], build_user_id(item["first_name"], item["last_name"], item["residence"]["city"]))
        profiles[user_id] = UserProfile(
            user_id=user_id,
            first_name=item["first_name"],
            last_name=item["last_name"],
            birth_year=int(item["birth_year"]),
            salary=float(item["salary"]),
            job=item["job"],
            iban=item["iban"],
            residence_city=item["residence"]["city"],
            description=item["description"],
        )

    locations_by_user: dict[str, list[dict]] = defaultdict(list)
    for row in json.loads(locations_path.read_text(encoding="utf-8")):
        locations_by_user[row["biotag"]].append(row)
    for values in locations_by_user.values():
        values.sort(key=lambda item: item["timestamp"])

    mails_by_user = map_communications_to_users(json.loads(mails_path.read_text(encoding="utf-8")), profiles, "mail")
    sms_by_user = map_communications_to_users(json.loads(sms_path.read_text(encoding="utf-8")), profiles, "sms")
    return transactions, profiles, locations_by_user, mails_by_user, sms_by_user


def build_user_id(first_name: str, last_name: str, city: str) -> str:
    safe_first = re.sub(r"[^A-Za-z]", "", first_name).upper()
    safe_last = re.sub(r"[^A-Za-z]", "", last_name).upper()
    safe_city = re.sub(r"[^A-Za-z]", "", city).upper()
    return f"{safe_last[:4]}-{safe_first[:4]}-{str(2000 + len(first_name) + len(last_name))[-3:]}-{safe_city[:3]}-0"


def map_communications_to_users(items: list[dict], profiles: dict[str, UserProfile], field_name: str) -> dict[str, list[dict]]:
    mapped: dict[str, list[dict]] = defaultdict(list)
    lookup: dict[str, str] = {}
    for user_id, profile in profiles.items():
        full_name = f"{profile.first_name.lower()} {profile.last_name.lower()}"
        lookup[full_name] = user_id
        lookup[profile.first_name.lower()] = user_id
        lookup[f"{profile.first_name.lower()}.{profile.last_name.lower()}"] = user_id
        lookup[f"{profile.first_name.lower()}-{profile.last_name.lower()}"] = user_id
    for item in items:
        content = item[field_name]
        user_id = infer_user_id_from_text(content, lookup)
        if user_id:
            mapped[user_id].append(item)
    return mapped


def infer_user_id_from_text(content: str, lookup: dict[str, str]) -> str | None:
    lower_content = content.lower()
    for needle, user_id in sorted(lookup.items(), key=lambda item: len(item[0]), reverse=True):
        if needle in lower_content:
            return user_id
    return None


def analyze_communications(mails_by_user: dict[str, list[dict]], sms_by_user: dict[str, list[dict]]) -> dict[str, CommunicationEvidence]:
    evidence_by_user: dict[str, CommunicationEvidence] = defaultdict(CommunicationEvidence)
    for source in (mails_by_user, sms_by_user):
        for user_id, items in source.items():
            evidence = evidence_by_user[user_id]
            for payload in items:
                text = next(iter(payload.values()))
                themes = detect_themes(text)
                if is_suspicious_message(text):
                    evidence.suspicious_count += 1
                    evidence.suspicious_themes.update(themes)
                    if len(evidence.suspicious_examples) < 5:
                        evidence.suspicious_examples.append(compact_text(text))
                else:
                    evidence.benign_themes.update(themes)
                    if len(evidence.benign_examples) < 5:
                        evidence.benign_examples.append(compact_text(text))
    return evidence_by_user


def detect_themes(text: str) -> list[str]:
    lower_text = text.lower()
    themes = []
    for label, markers in (
        ("paypal", ("paypal", "paypa1")),
        ("amazon", ("amazon", "amaz0n")),
        ("rideshare", ("uber", "rideshare", "driver account", "citydrive")),
        ("banking", ("bank", "statement", "deutschebank", "barclays")),
        ("shopping", ("order", "delivery", "marketplace", "parcel", "swiftcart")),
        ("utilities", ("bill", "subscription", "electricity", "internet", "phone")),
    ):
        if any(marker in lower_text for marker in markers):
            themes.append(label)
    return themes or ["general"]


def compact_text(text: str) -> str:
    clean = re.sub(r"\s+", " ", text).strip()
    return clean[:180]


def is_suspicious_message(text: str) -> bool:
    lower_text = text.lower()
    return any(marker in lower_text for marker in KNOWN_PHISHING_MARKERS)


def transaction_theme(tx: Transaction) -> str:
    lower = " ".join(
        part.lower()
        for part in (tx.transaction_type, tx.payment_method, tx.location, tx.description, tx.recipient_id)
        if part
    )
    if "paypal" in lower:
        return "paypal"
    if any(token in lower for token in ("market", "swiftcart", "urbancart", "e-commerce")):
        return "shopping"
    if any(token in lower for token in ("ride", "uber", "driver", "subscription")):
        return "rideshare"
    if any(token in lower for token in ("internet", "phone", "insurance", "bill")):
        return "utilities"
    if any(token in lower for token in ("bank", "transfer")):
        return "banking"
    return "general"


def evaluate_transactions(
    transactions: list[Transaction],
    profiles: dict[str, UserProfile],
    locations_by_user: dict[str, list[dict]],
    communication_evidence: dict[str, CommunicationEvidence],
) -> list[TransactionAssessment]:
    transactions = sorted(transactions, key=lambda item: item.timestamp)
    recipient_frequency = Counter(tx.recipient_id for tx in transactions)
    recipient_ibans: dict[str, set[str]] = defaultdict(set)
    for tx in transactions:
        recipient_ibans[tx.recipient_id].add(tx.recipient_iban)

    history_by_user: dict[str, list[Transaction]] = defaultdict(list)
    assessments: list[TransactionAssessment] = []
    for tx in transactions:
        if not tx.sender_id.startswith(USER_ID_PREFIXES):
            continue

        profile = profiles[tx.sender_id]
        evidence = communication_evidence.get(tx.sender_id, CommunicationEvidence())
        user_history = history_by_user[tx.sender_id]
        reasons: list[str] = []
        score = 0.0

        if not any(prev.recipient_id == tx.recipient_id and tx.recipient_id for prev in user_history):
            score += 0.24
            reasons.append("new-recipient")
        if not any(prev.transaction_type == tx.transaction_type for prev in user_history):
            score += 0.20
            reasons.append("new-transaction-type")
        if tx.payment_method and not any(prev.payment_method == tx.payment_method for prev in user_history):
            score += 0.08
            reasons.append("new-payment-method")
        if tx.location and not any(prev.location == tx.location for prev in user_history if prev.location):
            score += 0.08
            reasons.append("new-location")
        if not tx.description:
            score += 0.08
            reasons.append("missing-description")
        if tx.recipient_id and recipient_frequency[tx.recipient_id] == 1:
            score += 0.14
            reasons.append("one-off-recipient")
        if tx.recipient_id and len(recipient_ibans[tx.recipient_id]) > 1:
            score += 0.07
            reasons.append("recipient-uses-multiple-ibans")

        thematic_risk = thematic_risk_adjustment(tx, evidence, profile)
        if thematic_risk:
            score += thematic_risk
            reasons.append("message-transaction-theme-match")

        stability_penalty, stability_reasons = stability_adjustments(tx, user_history, locations_by_user.get(tx.sender_id, []), profile, evidence)
        score += stability_penalty
        reasons.extend(stability_reasons)

        score = max(0.0, min(score, 0.99))
        decision = "fraud" if score >= FRAUD_THRESHOLD else "legit"
        assessments.append(
            TransactionAssessment(
                transaction_id=tx.transaction_id,
                sender_id=tx.sender_id,
                final_score=round(score, 4),
                heuristic_score=round(score, 4),
                decision=decision,
                reasons=reasons,
                timestamp=tx.timestamp.isoformat(),
                amount=tx.amount,
                transaction_type=tx.transaction_type,
                recipient_id=tx.recipient_id,
                payment_method=tx.payment_method,
            )
        )
        history_by_user[tx.sender_id].append(tx)
    return assessments


def thematic_risk_adjustment(tx: Transaction, evidence: CommunicationEvidence, profile: UserProfile) -> float:
    theme = transaction_theme(tx)
    suspicious_hits = evidence.suspicious_themes[theme]
    benign_hits = evidence.benign_themes[theme]
    score = min(suspicious_hits * 0.05, 0.18)
    if theme == "shopping" and tx.payment_method == "PayPal":
        score += 0.06
    if theme == "rideshare" and "ride-share" in profile.job.lower():
        score += 0.03
    if benign_hits:
        score -= min(benign_hits * 0.03, 0.12)
    return score


def stability_adjustments(
    tx: Transaction,
    user_history: list[Transaction],
    locations: list[dict],
    profile: UserProfile,
    evidence: CommunicationEvidence,
) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    theme = transaction_theme(tx)

    if tx.transaction_type == "in-person payment" and tx.amount < 30 and profile.residence_city.lower() in tx.location.lower():
        score -= 0.28
        reasons.append("small-local-in-person-pattern")

    if "coffee" in tx.location.lower():
        score -= 0.10
        reasons.append("matches-daily-lifestyle")

    if "rent payment" in tx.description.lower():
        score -= 0.30
        reasons.append("recurring-rent-pattern")

    if "salary payment" in tx.description.lower():
        score -= 0.40
        reasons.append("salary-income")

    if "phone" in tx.description.lower() and tx.amount < 70:
        score -= 0.18
        reasons.append("small-phone-bill")

    if "insurance" in tx.description.lower():
        score -= 0.07
        reasons.append("essential-bill-plausible")

    if "internet bill" in tx.description.lower() and is_user_travelling(tx.timestamp, locations, profile.residence_city):
        score += 0.12
        reasons.append("utility-paid-while-abroad")

    if "subscription" in tx.description.lower():
        score += 0.07
        reasons.append("subscription-can-follow-account-takeover")

    if tx.transaction_type == "e-commerce" and evidence.benign_themes["shopping"]:
        score -= 0.06
        reasons.append("benign-shopping-signal-present")

    if len(user_history) >= 2:
        previous_by_type = [prev.amount for prev in user_history if prev.transaction_type == tx.transaction_type]
        if previous_by_type:
            baseline = median(previous_by_type)
            if baseline and tx.amount > baseline * 2:
                score += 0.14
                reasons.append("amount-spike-vs-history")
            if baseline and tx.amount < baseline * 0.3 and tx.transaction_type == "transfer":
                score += 0.06
                reasons.append("transfer-amount-pattern-break")

    if theme == "rideshare" and "ride-share" in profile.job.lower():
        score -= 0.08
        reasons.append("fits-user-job")

    return score, reasons


def is_user_travelling(timestamp: datetime, locations: list[dict], residence_city: str) -> bool:
    nearest_city = nearest_location_city(timestamp, locations)
    return bool(nearest_city and nearest_city.lower() != residence_city.lower())


def nearest_location_city(timestamp: datetime, locations: list[dict]) -> str | None:
    best_delta = None
    best_city = None
    for item in locations:
        item_ts = datetime.fromisoformat(item["timestamp"])
        delta = abs((item_ts - timestamp).total_seconds())
        if best_delta is None or delta < best_delta:
            best_delta = delta
            best_city = item["city"]
    return best_city


def choose_submission(assessments: Iterable[TransactionAssessment]) -> list[TransactionAssessment]:
    ranked = sorted(assessments, key=lambda item: (-item.final_score, item.timestamp))
    chosen = [item for item in ranked if item.final_score >= FRAUD_THRESHOLD]
    if not chosen and ranked:
        chosen = ranked[:1]
    return chosen


def write_outputs(
    dataset_name: str,
    output_dir: Path,
    assessments: list[TransactionAssessment],
) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_name = dataset_name.replace(" ", "_").replace("+", "_")
    submission_path = output_dir / f"{safe_name}_submission.txt"
    report_path = output_dir / f"{safe_name}_analysis.json"

    chosen = choose_submission(assessments)
    submission_path.write_text(
        "\n".join(item.transaction_id for item in chosen) + "\n",
        encoding="ascii",
    )

    report_payload = {
        "dataset": dataset_name,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "submission_transaction_ids": [item.transaction_id for item in chosen],
        "ranked_assessments": [asdict(item) for item in sorted(assessments, key=lambda item: (-item.final_score, item.timestamp))],
    }
    report_path.write_text(json.dumps(report_payload, indent=2), encoding="utf-8")
    return submission_path, report_path


def load_env_if_available() -> None:
    env_path = Path(".env")
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())
