from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class UserProfile:
    first_name: str
    last_name: str
    birth_year: int
    salary: float
    job: str
    iban: str
    residence_city: str
    residence_lat: float
    residence_lng: float
    description: str

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"


@dataclass(frozen=True)
class LocationPing:
    biotag: str
    timestamp: datetime
    lat: float
    lng: float
    city: str


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
    balance_after: float | None
    description: str
    timestamp: datetime

    @property
    def location_city(self) -> str | None:
        if self.location and " - " in self.location:
            return self.location.split(" - ", 1)[0].strip()
        return None


@dataclass(frozen=True)
class MessageEvent:
    channel: str
    raw_text: str
    timestamp: datetime | None
    first_line: str
    subject: str


@dataclass(frozen=True)
class Evidence:
    agent: str
    score: float
    reason: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Candidate:
    transaction: Transaction
    evidences: list[Evidence] = field(default_factory=list)
    score: float = 0.0

    def add(self, evidence: Evidence) -> None:
        self.evidences.append(evidence)
        self.score += evidence.score


@dataclass(frozen=True)
class ResolvedIdentity:
    account_id: str
    user: UserProfile
    score: float


@dataclass(frozen=True)
class AccountBehavior:
    account_id: str
    gps_cities: frozenset[str]
    transactions: tuple[Transaction, ...]


@dataclass(frozen=True)
class DatasetBundle:
    source_path: str
    transactions: list[Transaction]
    users: list[UserProfile]
    locations: list[LocationPing]
    sms: list[MessageEvent]
    mails: list[MessageEvent]
