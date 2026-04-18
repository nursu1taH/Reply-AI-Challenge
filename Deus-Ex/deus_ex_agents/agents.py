from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import math
import statistics
from typing import Deque, Dict, List, Optional, Sequence, Tuple

from .domain import DatasetContext, Transaction, TransactionAssessment, UserProfile


FINANCEISH_MERCHANT_TERMS = (
    "transfer",
    "bill",
    "utility",
    "insurance",
    "subscription",
    "savings",
    "loan",
    "advisor",
    "brokerage",
    "portfolio",
    "investment",
    "fund",
)


ROUND_WITHDRAWAL_LEVELS = (50, 100, 150, 200, 250)


def quantile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = (len(ordered) - 1) * q
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    weight = index - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def robust_outlier_delta(history: Sequence[float], current: float) -> Tuple[float, Optional[str]]:
    if len(history) < 5:
        return 0.0, None
    median = statistics.median(history)
    deviations = [abs(value - median) for value in history]
    mad = statistics.median(deviations)
    if mad < 1e-9:
        q95 = quantile(history, 0.95)
        if q95 <= 0:
            return 0.0, None
        if current > q95 * 1.7:
            return min((current / q95) * 0.22, 1.1), "amount is much larger than the sender's usual range"
        return 0.0, None
    z_score = abs(current - median) / (1.4826 * mad)
    if z_score < 2.6:
        return 0.0, None
    delta = min((z_score - 2.6) * 0.28, 1.35)
    return delta, "amount is a strong outlier versus earlier transactions"


@dataclass
class SenderMemory:
    home_city: Optional[str]
    amounts_all: List[float] = field(default_factory=list)
    amounts_by_type: Dict[str, List[float]] = field(default_factory=dict)
    hours_by_type: Dict[str, List[int]] = field(default_factory=dict)
    targets_seen: set[str] = field(default_factory=set)
    label_targets: Dict[str, set[str]] = field(default_factory=dict)
    label_counts: Dict[str, int] = field(default_factory=dict)
    recent_transactions: Deque[Transaction] = field(default_factory=deque)
    recent_withdrawals: Deque[Transaction] = field(default_factory=deque)
    last_physical: Optional[Transaction] = None

    def trim(self, now: datetime) -> None:
        while self.recent_transactions and now - self.recent_transactions[0].timestamp > timedelta(days=3):
            self.recent_transactions.popleft()
        while self.recent_withdrawals and now - self.recent_withdrawals[0].timestamp > timedelta(hours=6):
            self.recent_withdrawals.popleft()

    def record(self, tx: Transaction) -> None:
        self.amounts_all.append(tx.amount)
        self.amounts_by_type.setdefault(tx.transaction_type, []).append(tx.amount)
        self.hours_by_type.setdefault(tx.transaction_type, []).append(tx.timestamp.hour)
        self.targets_seen.add(tx.primary_target)
        self.label_targets.setdefault(tx.normalized_label, set()).add(tx.primary_target)
        self.label_counts[tx.normalized_label] = self.label_counts.get(tx.normalized_label, 0) + 1
        self.recent_transactions.append(tx)
        if tx.transaction_type == "withdrawal":
            self.recent_withdrawals.append(tx)
        if tx.location_city:
            self.last_physical = tx


class BaseAgent:
    name = "base"

    def assess(
        self,
        assessment: TransactionAssessment,
        context: DatasetContext,
        memory: SenderMemory,
        user: Optional[UserProfile],
    ) -> None:
        raise NotImplementedError


class UserVulnerabilityAgent(BaseAgent):
    name = "user_vulnerability"

    def assess(
        self,
        assessment: TransactionAssessment,
        context: DatasetContext,
        memory: SenderMemory,
        user: Optional[UserProfile],
    ) -> None:
        if not user:
            return
        tx = assessment.transaction
        if tx.is_salary:
            return
        if user.phishing_susceptibility >= 0.48 and tx.transaction_type in {
            "e-commerce",
            "transfer",
            "direct debit",
        }:
            assessment.add(
                self.name,
                0.12,
                "sender profile indicates elevated phishing susceptibility",
            )


class CommunicationRiskAgent(BaseAgent):
    name = "communications"

    def assess(
        self,
        assessment: TransactionAssessment,
        context: DatasetContext,
        memory: SenderMemory,
        user: Optional[UserProfile],
    ) -> None:
        tx = assessment.transaction
        if tx.is_salary:
            return
        events = context.communications.get(tx.sender_id, [])
        if not events:
            return
        deltas: List[float] = []
        summaries: List[str] = []
        for event in events:
            if event.timestamp > tx.timestamp:
                break
            age_hours = (tx.timestamp - event.timestamp).total_seconds() / 3600.0
            if age_hours > 72.0:
                continue
            decay = max(0.15, 1.0 - age_hours / 72.0)
            channel_weight = 1.10 if tx.transaction_type in {"transfer", "direct debit"} else 0.85
            deltas.append(event.risk_score * 0.42 * decay * channel_weight)
            if len(summaries) < 2:
                summaries.append(event.summary)
        if not deltas:
            return
        assessment.add(
            self.name,
            min(sum(deltas), 1.65),
            f"risky communication preceded the transaction: {summaries[0]}",
        )


class CounterpartyRiskAgent(BaseAgent):
    name = "counterparty"

    def assess(
        self,
        assessment: TransactionAssessment,
        context: DatasetContext,
        memory: SenderMemory,
        user: Optional[UserProfile],
    ) -> None:
        tx = assessment.transaction
        if tx.is_salary:
            assessment.add(self.name, -2.5, None)
            return
        target_profile = context.target_profiles.get(tx.primary_target)
        if target_profile:
            diversity = len(target_profile.categories)
            user_count = len(target_profile.user_ids)
            if diversity >= 4 and user_count >= 2:
                assessment.add(
                    self.name,
                    min(0.18 * diversity + 0.07 * user_count, 1.15),
                    "counterparty is reused across unrelated users and payment categories",
                )
            elif diversity >= 3 and user_count >= 2:
                assessment.add(
                    self.name,
                    0.45,
                    "counterparty appears across several mismatched payment patterns",
                )

        merchant_label = tx.merchant_label.lower()
        if tx.transaction_type in {"e-commerce", "in-person payment"} and any(
            term in merchant_label for term in FINANCEISH_MERCHANT_TERMS
        ):
            assessment.add(
                self.name,
                0.95,
                "merchant label looks like a financial transfer or billing endpoint instead of a normal merchant",
            )

        if tx.primary_target not in memory.targets_seen and len(memory.targets_seen) >= 6:
            assessment.add(self.name, 0.22, "counterparty has not appeared in the sender's prior history")

        label_targets = memory.label_targets.get(tx.normalized_label, set())
        label_count = memory.label_counts.get(tx.normalized_label, 0)
        if label_count >= 2 and len(label_targets) == 1 and tx.primary_target not in label_targets:
            assessment.add(
                self.name,
                1.10,
                "recurring payment label switched to a new counterparty",
            )


class BehavioralAnomalyAgent(BaseAgent):
    name = "behavior"

    def assess(
        self,
        assessment: TransactionAssessment,
        context: DatasetContext,
        memory: SenderMemory,
        user: Optional[UserProfile],
    ) -> None:
        tx = assessment.transaction
        if tx.is_salary:
            return

        by_type_history = memory.amounts_by_type.get(tx.transaction_type, [])
        delta, reason = robust_outlier_delta(by_type_history or memory.amounts_all, tx.amount)
        assessment.add(self.name, delta, reason)

        if user and user.monthly_salary > 0:
            monthly_ratio = tx.amount / user.monthly_salary
            if monthly_ratio > 0.80:
                assessment.add(
                    self.name,
                    min(monthly_ratio * 0.32, 1.0),
                    "transaction size is large relative to the sender's monthly income",
                )
            elif monthly_ratio > 0.35:
                assessment.add(
                    self.name,
                    0.30,
                    "transaction is meaningfully large compared with the sender's monthly income",
                )

        if tx.prior_balance > 0:
            balance_ratio = tx.amount / tx.prior_balance
            if balance_ratio > 0.70:
                assessment.add(
                    self.name,
                    1.05,
                    "transaction drains most of the sender's available balance",
                )
            elif balance_ratio > 0.40:
                assessment.add(
                    self.name,
                    0.42,
                    "transaction consumes a large share of the available balance",
                )

        hours = memory.hours_by_type.get(tx.transaction_type, [])
        if len(hours) >= 4 and tx.timestamp.hour < 6:
            baseline_night_share = sum(1 for hour in hours if hour < 6) / len(hours)
            if baseline_night_share < 0.20:
                assessment.add(
                    self.name,
                    0.28,
                    "transaction occurred at an unusual overnight hour",
                )

        if tx.transaction_type == "withdrawal":
            recent_cash = [
                past
                for past in memory.recent_withdrawals
                if tx.timestamp - past.timestamp <= timedelta(hours=2)
            ]
            if len(recent_cash) >= 1:
                assessment.add(
                    self.name,
                    min(0.35 + 0.20 * len(recent_cash), 0.95),
                    "multiple cash withdrawals happened in a short time window",
                )
            if any(abs(tx.amount - level) <= 0.5 for level in ROUND_WITHDRAWAL_LEVELS):
                assessment.add(self.name, 0.18, "cash amount matches a common ATM extraction pattern")


class TravelPatternAgent(BaseAgent):
    name = "travel"

    def assess(
        self,
        assessment: TransactionAssessment,
        context: DatasetContext,
        memory: SenderMemory,
        user: Optional[UserProfile],
    ) -> None:
        tx = assessment.transaction
        current_city = tx.location_city
        previous = memory.last_physical
        if not current_city or not previous or not previous.location_city:
            return
        if current_city == previous.location_city:
            return
        delta_minutes = (tx.timestamp - previous.timestamp).total_seconds() / 60.0
        if delta_minutes <= 45:
            assessment.add(
                self.name,
                1.85,
                f"location jumped from {previous.location_city} to {current_city} in under an hour",
            )
        elif delta_minutes <= 180:
            assessment.add(
                self.name,
                0.95,
                f"location changed from {previous.location_city} to {current_city} very quickly",
            )
        elif user and current_city != user.home_city and previous.location_city == user.home_city and delta_minutes <= 720:
            assessment.add(
                self.name,
                0.35,
                f"transaction moved away from the sender's home city unusually fast",
            )


class AudioContextAgent(BaseAgent):
    name = "audio"

    def assess(
        self,
        assessment: TransactionAssessment,
        context: DatasetContext,
        memory: SenderMemory,
        user: Optional[UserProfile],
    ) -> None:
        events = context.audio_events.get(assessment.transaction.sender_id, [])
        if not events:
            return
        recent = [
            event
            for event in events
            if timedelta(0) <= assessment.transaction.timestamp - event.timestamp <= timedelta(days=14)
        ]
        if recent:
            assessment.reasons.append(
                f"recent audio context exists ({len(recent)} file(s) in the previous 14 days)"
            )


def build_default_agents() -> List[BaseAgent]:
    return [
        UserVulnerabilityAgent(),
        CommunicationRiskAgent(),
        CounterpartyRiskAgent(),
        BehavioralAnomalyAgent(),
        TravelPatternAgent(),
        AudioContextAgent(),
    ]
