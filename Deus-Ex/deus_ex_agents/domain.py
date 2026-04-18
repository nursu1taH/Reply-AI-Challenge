from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import re
from typing import Dict, List, Optional


MONTH_WORDS = {
    "jan",
    "feb",
    "mar",
    "apr",
    "may",
    "jun",
    "jul",
    "aug",
    "sep",
    "oct",
    "nov",
    "dec",
    "january",
    "february",
    "march",
    "april",
    "june",
    "july",
    "august",
    "september",
    "october",
    "november",
    "december",
}


def normalize_text(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9\s]", " ", value.lower())
    cleaned = re.sub(r"\b20\d{2}\b", " ", cleaned)
    cleaned = re.sub(r"\b\d+\b", " ", cleaned)
    parts = [part for part in cleaned.split() if part not in MONTH_WORDS]
    return " ".join(parts)


@dataclass(frozen=True)
class UserProfile:
    user_id: str
    first_name: str
    last_name: str
    annual_salary: float
    home_city: str
    home_lat: float
    home_lng: float
    description: str
    phishing_susceptibility: float

    @property
    def monthly_salary(self) -> float:
        return self.annual_salary / 12.0 if self.annual_salary else 0.0


@dataclass(frozen=True)
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

    @property
    def primary_target(self) -> str:
        return (
            self.recipient_id
            or self.recipient_iban
            or self.location
            or self.description
            or self.transaction_id
        )

    @property
    def merchant_label(self) -> str:
        return self.location or self.description or self.recipient_id or ""

    @property
    def location_city(self) -> Optional[str]:
        if " - " not in self.location:
            return None
        return self.location.split(" - ", 1)[0].strip()

    @property
    def prior_balance(self) -> float:
        return self.balance_after + self.amount

    @property
    def normalized_label(self) -> str:
        source = self.description or self.location or self.transaction_type
        return normalize_text(source) or self.transaction_type

    @property
    def is_salary(self) -> bool:
        return self.sender_id.startswith("EMP") and self.description.lower().startswith(
            "salary payment"
        )


@dataclass(frozen=True)
class CommunicationEvent:
    user_id: str
    timestamp: datetime
    channel: str
    risk_score: float
    summary: str


@dataclass(frozen=True)
class AudioEvent:
    user_id: str
    timestamp: datetime
    file_name: str


@dataclass
class TargetProfile:
    count: int = 0
    user_ids: set[str] = field(default_factory=set)
    categories: Dict[str, int] = field(default_factory=dict)
    transaction_types: Dict[str, int] = field(default_factory=dict)

    def register(self, user_id: str, category: str, transaction_type: str) -> None:
        self.count += 1
        self.user_ids.add(user_id)
        self.categories[category] = self.categories.get(category, 0) + 1
        self.transaction_types[transaction_type] = (
            self.transaction_types.get(transaction_type, 0) + 1
        )


@dataclass
class TransactionAssessment:
    transaction: Transaction
    score: float = 0.0
    reasons: List[str] = field(default_factory=list)
    agent_scores: Dict[str, float] = field(default_factory=dict)
    llm_review: Optional[Dict[str, str]] = None

    def add(self, agent_name: str, delta: float, reason: Optional[str] = None) -> None:
        if not delta:
            return
        self.score += delta
        self.agent_scores[agent_name] = self.agent_scores.get(agent_name, 0.0) + delta
        if reason:
            self.reasons.append(reason)


@dataclass
class DatasetContext:
    transactions: List[Transaction]
    users: Dict[str, UserProfile]
    communications: Dict[str, List[CommunicationEvent]]
    audio_events: Dict[str, List[AudioEvent]]
    target_profiles: Dict[str, TargetProfile]
