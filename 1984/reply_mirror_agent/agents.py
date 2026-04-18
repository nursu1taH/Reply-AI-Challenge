from __future__ import annotations

import json
import os
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from .config import Settings
from .database import (
    DatasetBundle,
    TransactionRecord,
    canonical_city,
    extract_domain,
    haversine_km,
    normalize_text,
)


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def robust_center_and_spread(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 1.0
    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    mad = statistics.median(deviations) if deviations else 0.0
    spread = max(mad * 1.4826, median * 0.12, 25.0)
    return median, spread


def summarize_reasons(reasons: Iterable[str], limit: int = 3) -> list[str]:
    cleaned = []
    for reason in reasons:
        if reason and reason not in cleaned:
            cleaned.append(reason)
        if len(cleaned) >= limit:
            break
    return cleaned


@dataclass(slots=True)
class RiskContribution:
    transaction_id: str
    agent: str
    score: float
    reasons: list[str]
    metadata: dict[str, object]


@dataclass(slots=True)
class MessageRiskEvent:
    user_id: str
    timestamp: datetime
    score: float
    reasons: list[str]
    keywords: set[str]


class CommunicationRiskAgent:
    name = "communication"

    SUSPICIOUS_TERMS = {
        "verify": 1.3,
        "identity": 1.1,
        "account lock": 1.4,
        "suspicious": 0.9,
        "security": 0.9,
        "urgent": 1.2,
        "unusual login": 1.4,
        "sign in": 1.0,
        "otp": 1.2,
        "claim": 1.2,
        "prize": 1.8,
        "reward": 1.0,
        "processing fee": 1.8,
        "restore access": 1.2,
        "crypto": 1.9,
        "wallet": 1.4,
        "profit": 1.0,
        "pause activity": 1.1,
    }

    BENIGN_TERMS = {
        "training simulation": -3.2,
        "security awareness": -2.5,
        "simulated phishing": -3.2,
        "student services": -0.8,
        "city hall": -0.7,
        "community bulletin": -0.7,
    }

    LOOKALIKE_MARKERS = ("amaz0n", "paypa1", "coinb4se", "verify", "secure", "claim")

    def score(self, bundle: DatasetBundle) -> dict[str, list[RiskContribution]]:
        events_by_user = self._build_events(bundle)
        contributions: dict[str, list[RiskContribution]] = defaultdict(list)

        for tx in bundle.transactions:
            if not tx.user_id:
                continue
            user_events = events_by_user.get(tx.user_id, [])
            if not user_events:
                continue

            matched_scores = []
            tx_text = normalize_text(
                " ".join(
                    [
                        tx.transaction_type,
                        tx.description,
                        tx.location,
                        tx.counterparty_id,
                        tx.payment_method,
                    ]
                )
            )
            for event in user_events:
                delta_days = (tx.timestamp - event.timestamp).total_seconds() / 86400.0
                if delta_days < 0 or delta_days > 21:
                    continue
                decay = 1.0 if delta_days <= 3 else max(0.15, 1.0 - (delta_days / 24.0))
                score = event.score * decay
                if tx.direction == "incoming":
                    score *= 0.65
                if tx.transaction_type in {"transfer", "e-commerce"}:
                    score *= 1.1
                if event.keywords and any(keyword in tx_text for keyword in event.keywords):
                    score += 0.08
                matched_scores.append((score, event))

            if not matched_scores:
                continue

            matched_scores.sort(key=lambda item: item[0], reverse=True)
            top_score, top_event = matched_scores[0]
            if top_score < 0.12:
                continue
            reasons = summarize_reasons(
                [
                    f"High-risk message {max(0, int((tx.timestamp - top_event.timestamp).days))} day(s) earlier",
                    *top_event.reasons,
                ]
            )
            contributions[tx.transaction_id].append(
                RiskContribution(
                    transaction_id=tx.transaction_id,
                    agent=self.name,
                    score=clamp(top_score, 0.0, 0.42),
                    reasons=reasons,
                    metadata={"matched_event_time": top_event.timestamp.isoformat()},
                )
            )

        return contributions

    def _build_events(self, bundle: DatasetBundle) -> dict[str, list[MessageRiskEvent]]:
        events: dict[str, list[MessageRiskEvent]] = defaultdict(list)
        for message in bundle.messages:
            raw_text = normalize_text(
                " ".join(
                    [
                        message.sender_label,
                        message.sender_address,
                        message.subject,
                        message.body_text,
                    ]
                )
            )
            score = 0.0
            reasons = []
            keywords = set()

            for term, weight in self.SUSPICIOUS_TERMS.items():
                if term in raw_text:
                    score += weight
                    keywords.add(term)
            for term, weight in self.BENIGN_TERMS.items():
                if term in raw_text:
                    score += weight
            for url in message.urls:
                domain = extract_domain(url)
                if any(marker in domain for marker in self.LOOKALIKE_MARKERS):
                    score += 1.7
                    reasons.append(f"Lookalike domain: {domain}")
                if any(char.isdigit() for char in domain) and any(
                    brand in domain for brand in ("amazon", "paypal", "coinbase")
                ):
                    score += 1.6
                    reasons.append(f"Brand spoofing domain: {domain}")

            if "security" in raw_text and ("verify" in raw_text or "identity" in raw_text):
                score += 1.3
                reasons.append("Security-themed credential pressure")
            if "processing fee" in raw_text or ("claim" in raw_text and "prize" in raw_text):
                score += 1.8
                reasons.append("Advance-fee scam wording")

            normalized = clamp(score / 7.0, 0.0, 1.0)
            if normalized < 0.38:
                continue

            events[message.user_id].append(
                MessageRiskEvent(
                    user_id=message.user_id,
                    timestamp=message.timestamp,
                    score=normalized,
                    reasons=summarize_reasons(reasons or list(keywords)),
                    keywords=keywords,
                )
            )

        for user_events in events.values():
            user_events.sort(key=lambda item: item.timestamp)
        return events


class BehavioralBaselineAgent:
    name = "behavioral"

    def score(self, bundle: DatasetBundle) -> dict[str, list[RiskContribution]]:
        contributions: dict[str, list[RiskContribution]] = defaultdict(list)
        history_by_user: dict[str, list[TransactionRecord]] = defaultdict(list)
        seen_counterparties: dict[str, set[str]] = defaultdict(set)

        for tx in bundle.transactions:
            if not tx.user_id:
                continue
            user = bundle.users[tx.user_id]
            history = history_by_user[tx.user_id]
            same_direction = [item for item in history if item.direction == tx.direction]
            same_type = [
                item
                for item in same_direction
                if item.transaction_type == tx.transaction_type
            ]
            reasons = []
            score = 0.0

            if tx.direction == "outgoing":
                ref_values = [item.amount for item in (same_type if len(same_type) >= 5 else same_direction)]
                if len(ref_values) >= 5:
                    median, spread = robust_center_and_spread(ref_values)
                    z_like = abs(tx.amount - median) / spread
                    if z_like >= 3:
                        score += clamp((z_like - 2.8) / 10.0, 0.08, 0.24)
                        reasons.append(
                            f"Amount deviates from historical baseline (median {median:.2f})"
                        )

                if (
                    tx.counterparty_id
                    and tx.counterparty_id not in seen_counterparties[tx.user_id]
                    and len(seen_counterparties[tx.user_id]) >= 8
                ):
                    score += 0.18
                    reasons.append("New counterparty for this user")

                if self._is_rare_hour(tx, same_direction):
                    score += 0.11
                    reasons.append("Unusual transaction time for this user")

                if self._burst_count(same_direction, tx.timestamp, hours=6) >= 3:
                    score += 0.12
                    reasons.append("Burst of nearby transactions")

                available_before = tx.amount + tx.balance_after
                if available_before > 0:
                    drain_ratio = tx.amount / available_before
                    if drain_ratio >= 0.65 and tx.amount >= max(user.salary / 8.0, 250.0):
                        score += 0.12
                        reasons.append("Aggressive balance depletion")

                if tx.amount >= max(user.salary * 0.55, 4000.0) and len(same_direction) >= 6:
                    score += 0.09
                    reasons.append("High-value transaction relative to salary")
            else:
                incoming_values = [item.amount for item in same_direction]
                if len(incoming_values) >= 4:
                    median, spread = robust_center_and_spread(incoming_values)
                    z_like = abs(tx.amount - median) / spread
                    if z_like >= 3.5:
                        score += clamp((z_like - 3.2) / 12.0, 0.08, 0.22)
                        reasons.append("Unusual incoming amount")

                if (
                    tx.counterparty_id
                    and tx.counterparty_id not in seen_counterparties[tx.user_id]
                    and tx.amount >= max(user.salary * 0.7, 1000.0)
                ):
                    score += 0.16
                    reasons.append("Large inbound transfer from a new sender")

            if score >= 0.08:
                contributions[tx.transaction_id].append(
                    RiskContribution(
                        transaction_id=tx.transaction_id,
                        agent=self.name,
                        score=clamp(score, 0.0, 0.55),
                        reasons=summarize_reasons(reasons),
                        metadata={"history_count": len(history)},
                    )
                )

            history_by_user[tx.user_id].append(tx)
            if tx.counterparty_id:
                seen_counterparties[tx.user_id].add(tx.counterparty_id)

        return contributions

    def _is_rare_hour(
        self, tx: TransactionRecord, previous: list[TransactionRecord]
    ) -> bool:
        if len(previous) < 12:
            return False
        buckets = Counter(item.timestamp.hour // 6 for item in previous)
        bucket = tx.timestamp.hour // 6
        return buckets[bucket] <= max(1, int(len(previous) * 0.08))

    def _burst_count(
        self, previous: list[TransactionRecord], ts: datetime, hours: int
    ) -> int:
        window_start = ts - timedelta(hours=hours)
        return sum(1 for item in previous if item.timestamp >= window_start)


class GeoTemporalAgent:
    name = "geo_temporal"

    def score(self, bundle: DatasetBundle) -> dict[str, list[RiskContribution]]:
        contributions: dict[str, list[RiskContribution]] = defaultdict(list)
        for tx in bundle.transactions:
            if not tx.user_id or tx.transaction_type not in {
                "in-person payment",
                "withdrawal",
            }:
                continue
            tx_city_key = canonical_city(tx.location)
            if not tx_city_key or tx_city_key not in bundle.city_centroids:
                continue
            locations = bundle.locations_by_user.get(tx.user_id, [])
            user = bundle.users[tx.user_id]
            target_lat, target_lng = bundle.city_centroids[tx_city_key]

            nearby_locations = [
                point
                for point in locations
                if abs((tx.timestamp - point.timestamp).total_seconds()) <= 24 * 3600
            ]
            reasons = []
            score = 0.0

            if nearby_locations:
                distances = [
                    haversine_km(target_lat, target_lng, point.lat, point.lng)
                    for point in nearby_locations
                ]
                min_distance = min(distances)
                if min_distance >= 250:
                    score += 0.22
                    reasons.append(
                        f"Transaction city is {int(min_distance)} km away from recent GPS trail"
                    )
                recent_before = [
                    point
                    for point in nearby_locations
                    if point.timestamp <= tx.timestamp
                ]
                if recent_before:
                    last_point = recent_before[-1]
                    hours = max(
                        (tx.timestamp - last_point.timestamp).total_seconds() / 3600.0,
                        0.1,
                    )
                    distance = haversine_km(
                        target_lat,
                        target_lng,
                        last_point.lat,
                        last_point.lng,
                    )
                    if distance / hours >= 320:
                        score += 0.16
                        reasons.append("Implausible travel speed between GPS trace and payment")
            else:
                home_distance = haversine_km(
                    target_lat,
                    target_lng,
                    user.residence_lat,
                    user.residence_lng,
                )
                if home_distance >= 500:
                    score += 0.14
                    reasons.append(
                        f"In-person transaction far from residence ({int(home_distance)} km)"
                    )

            if score >= 0.12:
                contributions[tx.transaction_id].append(
                    RiskContribution(
                        transaction_id=tx.transaction_id,
                        agent=self.name,
                        score=clamp(score, 0.0, 0.40),
                        reasons=summarize_reasons(reasons),
                        metadata={"city": tx_city_key},
                    )
                )
        return contributions


class CounterpartyGraphAgent:
    name = "counterparty_graph"

    def score(self, bundle: DatasetBundle) -> dict[str, list[RiskContribution]]:
        contributions: dict[str, list[RiskContribution]] = defaultdict(list)
        entity_users: dict[str, set[str]] = defaultdict(set)
        entity_first_seen: dict[str, datetime] = {}
        per_user_seen: dict[str, set[str]] = defaultdict(set)
        user_timelines: dict[str, list[TransactionRecord]] = defaultdict(list)
        outgoing_to_entity: dict[str, list[TransactionRecord]] = defaultdict(list)

        for tx in bundle.transactions:
            if not tx.user_id or not tx.counterparty_id:
                continue
            entity = tx.counterparty_id
            prior_unique_users = len(entity_users[entity])
            prior_seen_by_user = entity in per_user_seen[tx.user_id]
            reasons = []
            score = 0.0

            if tx.direction == "outgoing":
                if not prior_seen_by_user and prior_unique_users >= 4:
                    score += 0.16
                    reasons.append("New counterparty already shared by multiple users")
                if not prior_seen_by_user and entity not in entity_first_seen:
                    score += 0.08
                    reasons.append("Brand new counterparty in the graph")
            else:
                if not prior_seen_by_user and tx.amount >= 1000 and prior_unique_users >= 2:
                    score += 0.14
                    reasons.append("Large inbound from a sender already touching multiple users")

            if score >= 0.08:
                contributions[tx.transaction_id].append(
                    RiskContribution(
                        transaction_id=tx.transaction_id,
                        agent=self.name,
                        score=clamp(score, 0.0, 0.28),
                        reasons=summarize_reasons(reasons),
                        metadata={"prior_unique_users": prior_unique_users},
                    )
                )

            entity_users[entity].add(tx.user_id)
            entity_first_seen.setdefault(entity, tx.timestamp)
            per_user_seen[tx.user_id].add(entity)
            user_timelines[tx.user_id].append(tx)
            if tx.direction == "outgoing":
                outgoing_to_entity[entity].append(tx)

        for entity, txs in outgoing_to_entity.items():
            unique_users = {tx.user_id for tx in txs}
            active_days = (max(tx.timestamp for tx in txs) - min(tx.timestamp for tx in txs)).days
            median_amount = statistics.median(tx.amount for tx in txs)
            if len(unique_users) >= 5 and active_days <= 45 and 40 <= median_amount <= 3000:
                first_touch_by_user: set[str] = set()
                for tx in txs:
                    if tx.user_id in first_touch_by_user:
                        continue
                    first_touch_by_user.add(tx.user_id)
                    contributions[tx.transaction_id].append(
                        RiskContribution(
                            transaction_id=tx.transaction_id,
                            agent=self.name,
                            score=0.10,
                            reasons=["Counterparty resembles a short-lived multi-user campaign"],
                            metadata={"entity": entity},
                        )
                    )

        for user_id, timeline in user_timelines.items():
            incoming = [
                tx
                for tx in timeline
                if tx.direction == "incoming" and tx.amount >= 500
            ]
            outgoing = [
                tx
                for tx in timeline
                if tx.direction == "outgoing" and tx.transaction_type in {"transfer", "e-commerce"}
            ]
            for inbound in incoming:
                window_end = inbound.timestamp + timedelta(hours=48)
                related = [
                    tx for tx in outgoing if inbound.timestamp <= tx.timestamp <= window_end
                ]
                if not related:
                    continue
                total_out = sum(tx.amount for tx in related)
                if total_out >= inbound.amount * 0.6:
                    contributions[inbound.transaction_id].append(
                        RiskContribution(
                            transaction_id=inbound.transaction_id,
                            agent=self.name,
                            score=0.12,
                            reasons=["Incoming funds quickly flowed back out"],
                            metadata={"user_id": user_id},
                        )
                    )
                    for tx in related[:3]:
                        contributions[tx.transaction_id].append(
                            RiskContribution(
                                transaction_id=tx.transaction_id,
                                agent=self.name,
                                score=0.16,
                                reasons=["Rapid pass-through after an incoming credit"],
                                metadata={"paired_incoming": inbound.transaction_id},
                            )
                        )

        return contributions


class LLMAdjudicatorAgent:
    name = "llm_adjudicator"

    def __init__(self, settings: Settings, session_id: str) -> None:
        self.settings = settings
        self.session_id = session_id
        self.available = False
        self.langfuse_client = None
        self.model = None
        self.observe = None
        self.callback_handler_cls = None
        self.human_message_cls = None
        self.system_message_cls = None

    def score(
        self,
        cases: list[dict[str, object]],
    ) -> tuple[dict[str, list[RiskContribution]], list[str]]:
        notes = []
        contributions: dict[str, list[RiskContribution]] = defaultdict(list)
        if self.settings.llm_mode == "off":
            return contributions, notes
        if not self._ensure_runtime():
            notes.append("LLM adjudication skipped because Langfuse/LangChain runtime is unavailable.")
            if self.settings.llm_mode == "on":
                notes.append("`--use-llm on` was requested, but challenge tracing dependencies were missing.")
            return contributions, notes

        for case in cases:
            verdict = self._run_case(case)
            if not verdict:
                continue
            label = verdict.get("label", "review")
            confidence = float(verdict.get("confidence", 0.0))
            reason = str(verdict.get("reason", ""))
            score = 0.0
            if label == "fraud":
                score = 0.28 * confidence
            elif label == "review":
                score = 0.10 * confidence
            elif label == "legit":
                score = -0.24 * confidence
            if score == 0.0:
                continue
            contributions[str(case["transaction_id"])].append(
                RiskContribution(
                    transaction_id=str(case["transaction_id"]),
                    agent=self.name,
                    score=score,
                    reasons=[reason] if reason else [f"LLM verdict: {label}"],
                    metadata={"label": label, "confidence": confidence},
                )
            )

        if self.langfuse_client is not None:
            self.langfuse_client.flush()
        if cases and not contributions:
            notes.append(
                "LLM adjudicator returned no usable verdicts; verify outbound access to OpenRouter and Langfuse."
            )
        return contributions, notes

    def _ensure_runtime(self) -> bool:
        if self.available:
            return True
        try:
            from langchain_core.messages import HumanMessage, SystemMessage
            from langchain_openai import ChatOpenAI
            from langfuse import Langfuse, observe
            from langfuse.langchain import CallbackHandler
        except Exception:
            return False

        self.langfuse_client = Langfuse(
            public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
            secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
            host=os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse"),
        )
        self.model = ChatOpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            model=self.settings.model_name,
            temperature=0.35,
            max_tokens=250,
        )
        self.observe = observe
        self.callback_handler_cls = CallbackHandler
        self.human_message_cls = HumanMessage
        self.system_message_cls = SystemMessage
        self.available = True
        return True

    def _run_case(self, case: dict[str, object]) -> dict[str, object] | None:
        if not self.available:
            return None
        system_prompt = (
            "You are the final adjudicator in a fraud detection committee. "
            "False positives are expensive, but adaptive fraud must still be flagged. "
            "Return only compact JSON with keys label, confidence, reason. "
            "label must be one of fraud, legit, review."
        )
        human_prompt = json.dumps(case, ensure_ascii=True)

        observe = self.observe
        callback_handler_cls = self.callback_handler_cls
        system_message_cls = self.system_message_cls
        human_message_cls = self.human_message_cls
        model = self.model
        session_id = self.session_id

        @observe()
        def invoke(prompt_system: str, prompt_human: str) -> str:
            handler = callback_handler_cls()
            response = model.invoke(
                [
                    system_message_cls(content=prompt_system),
                    human_message_cls(content=prompt_human),
                ],
                config={
                    "callbacks": [handler],
                    "metadata": {"langfuse_session_id": session_id},
                },
            )
            return str(response.content)

        try:
            raw = invoke(system_prompt, human_prompt)
            match = re.search(r"\{.*\}", raw, re.DOTALL)
            if not match:
                return None
            return json.loads(match.group(0))
        except Exception:
            return None


class FraudOrchestrator:
    def __init__(self, settings: Settings, session_id: str) -> None:
        self.settings = settings
        self.session_id = session_id
        self.base_agents = [
            CommunicationRiskAgent(),
            BehavioralBaselineAgent(),
            GeoTemporalAgent(),
            CounterpartyGraphAgent(),
        ]
        self.llm_agent = LLMAdjudicatorAgent(settings, session_id)

    def run(self, bundle: DatasetBundle) -> tuple[list[str], dict[str, object]]:
        all_contributions: dict[str, list[RiskContribution]] = defaultdict(list)
        notes: list[str] = []

        for agent in self.base_agents:
            result = agent.score(bundle)
            for tx_id, contributions in result.items():
                all_contributions[tx_id].extend(contributions)

        base_scores = self._aggregate_scores(bundle, all_contributions)
        llm_cases = self._prepare_llm_cases(bundle, all_contributions, base_scores)
        llm_contributions, llm_notes = self.llm_agent.score(llm_cases)
        notes.extend(llm_notes)
        for tx_id, contributions in llm_contributions.items():
            all_contributions[tx_id].extend(contributions)

        final_scores = self._aggregate_scores(bundle, all_contributions)
        suspects = self._select_suspects(final_scores)

        report = {
            "session_id": self.session_id,
            "database": str(self.settings.database_path),
            "llm_mode": self.settings.llm_mode,
            "selected_transactions": len(suspects),
            "notes": notes,
            "top_transactions": self._build_report_rows(bundle, all_contributions, final_scores),
        }
        return suspects, report

    def _aggregate_scores(
        self,
        bundle: DatasetBundle,
        contributions: dict[str, list[RiskContribution]],
    ) -> dict[str, float]:
        final_scores = {}
        for tx in bundle.transactions:
            tx_contribs = contributions.get(tx.transaction_id, [])
            raw = sum(item.score for item in tx_contribs)
            positive_support = sum(1 for item in tx_contribs if item.score >= 0.08)
            if positive_support <= 1 and raw < 0.46:
                raw -= 0.05
            final_scores[tx.transaction_id] = clamp(raw, 0.0, 1.0)
        return final_scores

    def _prepare_llm_cases(
        self,
        bundle: DatasetBundle,
        contributions: dict[str, list[RiskContribution]],
        base_scores: dict[str, float],
    ) -> list[dict[str, object]]:
        if self.settings.llm_mode == "off":
            return []

        ranked = sorted(
            bundle.transactions,
            key=lambda tx: base_scores.get(tx.transaction_id, 0.0),
            reverse=True,
        )
        cases = []
        for tx in ranked[: self.settings.candidate_limit]:
            score = base_scores.get(tx.transaction_id, 0.0)
            if score < 0.36:
                continue
            user = bundle.users.get(tx.user_id)
            tx_contribs = contributions.get(tx.transaction_id, [])
            cases.append(
                {
                    "transaction_id": tx.transaction_id,
                    "base_score": round(score, 4),
                    "transaction": {
                        "direction": tx.direction,
                        "type": tx.transaction_type,
                        "amount": tx.amount,
                        "timestamp": tx.timestamp.isoformat(),
                        "location": tx.location,
                        "description": tx.description,
                        "counterparty_id": tx.counterparty_id,
                    },
                    "user_profile": {
                        "name": user.full_name if user else "",
                        "job": user.job if user else "",
                        "city": user.city if user else "",
                        "salary": user.salary if user else 0.0,
                        "phishing_susceptibility": (
                            user.phishing_susceptibility if user else None
                        ),
                    },
                    "signals": [
                        {
                            "agent": item.agent,
                            "score": round(item.score, 4),
                            "reasons": item.reasons,
                        }
                        for item in tx_contribs[:6]
                    ],
                }
            )
        return cases

    def _select_suspects(self, final_scores: dict[str, float]) -> list[str]:
        tx_count = len(final_scores)
        minimum = max(25, int(tx_count * 0.02))
        target = max(minimum, int(tx_count * self.settings.target_alert_rate))
        maximum = min(tx_count - 1, max(target, int(tx_count * 0.14)))

        ordered = sorted(final_scores.items(), key=lambda item: item[1], reverse=True)
        cutoff = ordered[min(target - 1, len(ordered) - 1)][1]
        threshold = max(0.43, min(0.62, cutoff))
        suspects = [tx_id for tx_id, score in ordered if score >= threshold]

        if len(suspects) < minimum:
            suspects = [tx_id for tx_id, _ in ordered[:target]]
        if len(suspects) > maximum:
            suspects = suspects[:maximum]
        return suspects

    def _build_report_rows(
        self,
        bundle: DatasetBundle,
        contributions: dict[str, list[RiskContribution]],
        final_scores: dict[str, float],
    ) -> list[dict[str, object]]:
        tx_lookup = {tx.transaction_id: tx for tx in bundle.transactions}
        ordered = sorted(final_scores.items(), key=lambda item: item[1], reverse=True)[:100]
        rows = []
        for tx_id, score in ordered:
            tx = tx_lookup[tx_id]
            rows.append(
                {
                    "transaction_id": tx_id,
                    "score": round(score, 4),
                    "direction": tx.direction,
                    "user_id": tx.user_id,
                    "transaction_type": tx.transaction_type,
                    "amount": tx.amount,
                    "timestamp": tx.timestamp.isoformat(),
                    "counterparty_id": tx.counterparty_id,
                    "reasons": [
                        {
                            "agent": item.agent,
                            "score": round(item.score, 4),
                            "reasons": item.reasons,
                        }
                        for item in contributions.get(tx_id, [])[:8]
                    ],
                }
            )
        return rows
