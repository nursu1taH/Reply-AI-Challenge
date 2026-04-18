from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from .mapping import resolve_identities
from .models import AccountBehavior, Candidate, DatasetBundle, Evidence, MessageEvent, ResolvedIdentity, Transaction


SUSPICIOUS_MESSAGE_KEYWORDS = (
    "verify",
    "urgent",
    "suspicious",
    "locked",
    "suspend",
    "suspension",
    "security alert",
    "confirm identity",
    "restore access",
    "pay release fee",
)
SUSPICIOUS_TOKEN_HINTS = (
    "paypa1",
    "amaz0n",
    "natw3st",
    "pensi0n",
    "bit.ly",
    "hmrc-secure",
    "verify",
)
SUSPICIOUS_MONEY_MOVE_LABELS = (
    "donation",
    "emergency fund transfer",
)
SAFE_MESSAGE_MARKERS = (
    "phishing sim",
    "training alert",
    "security training",
    "i can't help create phishing texts",
    "i can’t help create phishing texts",
    "safe, educational examples instead",
)
ROUTINE_TRANSFER_LABEL_HINTS = (
    "savings deposit",
    "savings transfer",
)
POST_COMPROMISE_TRANSFER_LABEL_HINTS = (
    "emergency fund transfer",
)


class IdentityLinkingAgent:
    name = "identity_linking"

    def analyze(self, dataset: DatasetBundle) -> dict[str, ResolvedIdentity]:
        location_accounts = {location.biotag for location in dataset.locations}
        account_ids = [
            transaction.sender_id
            for transaction in dataset.transactions
            if transaction.sender_id in location_accounts
        ]
        return resolve_identities(dataset.users, account_ids)


class BehavioralProfileAgent:
    name = "behavioral_profile"

    def analyze(self, dataset: DatasetBundle) -> dict[str, AccountBehavior]:
        transactions_by_account: dict[str, list[Transaction]] = defaultdict(list)
        gps_cities_by_account: dict[str, set[str]] = defaultdict(set)
        for transaction in dataset.transactions:
            transactions_by_account[transaction.sender_id].append(transaction)
        for location in dataset.locations:
            gps_cities_by_account[location.biotag].add(location.city)

        behaviors: dict[str, AccountBehavior] = {}
        for account_id, transactions in transactions_by_account.items():
            ordered = tuple(sorted(transactions, key=lambda item: item.timestamp))
            behaviors[account_id] = AccountBehavior(
                account_id=account_id,
                gps_cities=frozenset(gps_cities_by_account.get(account_id, set())),
                transactions=ordered,
            )
        return behaviors


class CommunicationRiskAgent:
    name = "communication_risk"

    def analyze(
        self,
        dataset: DatasetBundle,
        identities: dict[str, ResolvedIdentity],
    ) -> tuple[dict[str, list[datetime]], dict[str, list[dict[str, str]]]]:
        alerts_by_account: dict[str, list[datetime]] = defaultdict(list)
        message_log: dict[str, list[dict[str, str]]] = defaultdict(list)
        account_lookup = {resolved.user.full_name.lower(): account_id for account_id, resolved in identities.items()}
        first_name_lookup = {resolved.user.first_name.lower(): account_id for account_id, resolved in identities.items()}

        def target_account(message: MessageEvent) -> str | None:
            lowered = message.raw_text.lower()
            for full_name, account_id in account_lookup.items():
                if full_name in lowered:
                    return account_id
            for first_name, account_id in first_name_lookup.items():
                if first_name in lowered:
                    return account_id
            return None

        for message in [*dataset.sms, *dataset.mails]:
            account_id = target_account(message)
            if not account_id or not message.timestamp:
                continue
            lowered = message.raw_text.lower()
            if any(marker in lowered for marker in SAFE_MESSAGE_MARKERS):
                continue
            keyword_hits = sum(1 for keyword in SUSPICIOUS_MESSAGE_KEYWORDS if keyword in lowered)
            token_hits = sum(1 for token in SUSPICIOUS_TOKEN_HINTS if token in lowered)
            score = keyword_hits + token_hits
            if keyword_hits >= 2 and ("http" in lowered or "bit.ly" in lowered):
                score += 2
            if score < 3:
                continue
            alerts_by_account[account_id].append(message.timestamp)
            message_log[account_id].append(
                {
                    "timestamp": message.timestamp.isoformat(),
                    "channel": message.channel,
                    "first_line": message.first_line,
                    "subject": message.subject,
                }
            )

        for account_id in alerts_by_account:
            alerts_by_account[account_id].sort()
        return alerts_by_account, message_log


class GeoTemporalAgent:
    name = "geo_temporal"

    def analyze(self, behaviors: dict[str, AccountBehavior]) -> tuple[dict[str, list[Evidence]], dict[str, list[datetime]]]:
        evidences_by_tx: dict[str, list[Evidence]] = defaultdict(list)
        anchors_by_account: dict[str, list[datetime]] = defaultdict(list)

        for account_id, behavior in behaviors.items():
            recent_withdrawals: list[Transaction] = []
            for transaction in behavior.transactions:
                if transaction.transaction_type != "withdrawal":
                    recent_withdrawals = [
                        candidate
                        for candidate in recent_withdrawals
                        if transaction.timestamp - candidate.timestamp <= timedelta(hours=1)
                    ]
                    continue

                location_city = transaction.location_city
                if location_city and location_city not in behavior.gps_cities:
                    score = 7.0
                    details = {
                        "transaction_city": location_city,
                        "known_gps_cities": sorted(behavior.gps_cities),
                    }
                    rapid_repeats = [
                        candidate
                        for candidate in recent_withdrawals
                        if candidate.location == transaction.location
                        and transaction.timestamp - candidate.timestamp <= timedelta(hours=1)
                    ]
                    if rapid_repeats:
                        score += 2.0 * len(rapid_repeats)
                        details["rapid_repeat_count"] = len(rapid_repeats)
                    evidences_by_tx[transaction.transaction_id].append(
                        Evidence(
                            agent=self.name,
                            score=score,
                            reason="withdrawal city absent from GPS history",
                            details=details,
                        )
                    )
                    anchors_by_account[account_id].append(transaction.timestamp)

                recent_withdrawals = [
                    candidate
                    for candidate in recent_withdrawals
                    if transaction.timestamp - candidate.timestamp <= timedelta(hours=1)
                ]
                recent_withdrawals.append(transaction)

        return evidences_by_tx, anchors_by_account


class CounterpartyNoveltyAgent:
    name = "counterparty_novelty"

    def analyze(
        self,
        behaviors: dict[str, AccountBehavior],
        phishing_alerts: dict[str, list[datetime]],
        anchors_by_account: dict[str, list[datetime]],
    ) -> tuple[dict[str, list[Evidence]], dict[str, list[datetime]]]:
        evidences_by_tx: dict[str, list[Evidence]] = defaultdict(list)
        updated_anchors: dict[str, list[datetime]] = defaultdict(list)
        global_compromise_cities = {
            transaction.location_city.lower()
            for account_id, behavior in behaviors.items()
            for transaction in behavior.transactions
            if transaction.transaction_type == "withdrawal"
            and transaction.timestamp in set(anchors_by_account.get(account_id, []))
            and transaction.location_city
        }

        for account_id, behavior in behaviors.items():
            transactions = list(behavior.transactions)
            anchor_timestamps = set(anchors_by_account.get(account_id, []))

            for index, transaction in enumerate(transactions):
                if transaction.transaction_type != "e-commerce" or transaction.amount > 5:
                    continue
                for follow_up in transactions[index + 1 : index + 6]:
                    if follow_up.timestamp - transaction.timestamp > timedelta(hours=2):
                        break
                    if (
                        follow_up.transaction_type == "e-commerce"
                        and follow_up.recipient_id == transaction.recipient_id
                        and follow_up.location == transaction.location
                        and follow_up.amount >= 100
                    ):
                        evidences_by_tx[transaction.transaction_id].append(
                            Evidence(
                                agent=self.name,
                                score=6.0,
                                reason="small card-test charge before larger merchant hit",
                                details={"follow_up_transaction_id": follow_up.transaction_id},
                            )
                        )
                        evidences_by_tx[follow_up.transaction_id].append(
                            Evidence(
                                agent=self.name,
                                score=7.0,
                                reason="large charge preceded by microcharge at same merchant",
                                details={"microcharge_transaction_id": transaction.transaction_id},
                            )
                        )
                        updated_anchors[account_id].append(transaction.timestamp)
                        updated_anchors[account_id].append(follow_up.timestamp)
                        break

            seen_recipients: set[str] = set()
            compromise_anchors = sorted(list(anchor_timestamps) + list(updated_anchors.get(account_id, [])))

            for transaction in transactions:
                recent_alert = any(
                    timedelta(0) <= transaction.timestamp - alert <= timedelta(hours=48)
                    for alert in phishing_alerts.get(account_id, [])
                )
                anchor_deltas = [
                    transaction.timestamp - anchor
                    for anchor in compromise_anchors
                    if timedelta(0) < transaction.timestamp - anchor <= timedelta(hours=48)
                ]
                recent_anchor = bool(anchor_deltas)
                closest_anchor_delta = min(anchor_deltas, default=None)
                is_new_recipient = bool(transaction.recipient_id) and transaction.recipient_id not in seen_recipients
                lowered_description = transaction.description.lower()
                lowered_location = transaction.location.lower()
                suspicious_label = any(label in lowered_description for label in SUSPICIOUS_MONEY_MOVE_LABELS)
                routine_label = any(label in lowered_description for label in ROUTINE_TRANSFER_LABEL_HINTS)

                evidence_score = 0.0
                details: dict[str, object] = {}
                reasons: list[str] = []
                if transaction.transaction_type in {"transfer", "e-commerce", "direct debit"} and recent_anchor:
                    if is_new_recipient and not routine_label:
                        evidence_score += 2.0
                        reasons.append("new counterparty after compromise")
                    if suspicious_label:
                        evidence_score += 2.0
                        reasons.append("vague money-move label after compromise")
                    if transaction.amount >= 150 and not routine_label:
                        evidence_score += 1.5
                        reasons.append("high-value movement after compromise")
                    if (
                        transaction.transaction_type == "transfer"
                        and any(label in lowered_description for label in POST_COMPROMISE_TRANSFER_LABEL_HINTS)
                    ):
                        evidence_score += 1.5
                        reasons.append("urgent transfer label immediately after compromise")

                if (
                    transaction.transaction_type == "e-commerce"
                    and recent_anchor
                    and closest_anchor_delta is not None
                    and closest_anchor_delta <= timedelta(hours=6)
                    and transaction.amount >= 100
                    and any(city in lowered_location for city in global_compromise_cities)
                ):
                    evidence_score += 5.0
                    reasons.append("merchant location matches a known remote cash-out corridor after compromise")

                if recent_alert and is_new_recipient and transaction.amount >= 150 and suspicious_label:
                    evidence_score += 2.5
                    reasons.append("high-value new transfer shortly after phishing signal")
                if (
                    recent_alert
                    and recent_anchor
                    and is_new_recipient
                    and not routine_label
                    and transaction.transaction_type in {"transfer", "e-commerce"}
                    and transaction.amount >= 200
                ):
                    evidence_score += 1.5
                    reasons.append("high-value new spend during active compromise window")

                if evidence_score >= 3.5:
                    details["recent_alert"] = recent_alert
                    details["recent_compromise_anchor"] = recent_anchor
                    details["routine_label"] = routine_label
                    evidences_by_tx[transaction.transaction_id].append(
                        Evidence(
                            agent=self.name,
                            score=evidence_score,
                            reason="; ".join(reasons),
                            details=details,
                        )
                    )

                if transaction.recipient_id:
                    seen_recipients.add(transaction.recipient_id)

        return evidences_by_tx, updated_anchors


class OrchestratorAgent:
    name = "orchestrator"

    @staticmethod
    def auto_backfill_floor(threshold: float) -> float:
        return max(0.0, threshold - max(1.0, threshold * 0.2))

    def select(
        self,
        dataset: DatasetBundle,
        evidence_groups: list[dict[str, list[Evidence]]],
        threshold: float,
        min_candidates: int | None = None,
        llm_adjustments: dict[str, Evidence] | None = None,
    ) -> list[Candidate]:
        candidate_map: dict[str, Candidate] = {
            transaction.transaction_id: Candidate(transaction=transaction)
            for transaction in dataset.transactions
        }

        for evidence_group in evidence_groups:
            for transaction_id, evidences in evidence_group.items():
                for evidence in evidences:
                    candidate_map[transaction_id].add(evidence)

        if llm_adjustments:
            for transaction_id, evidence in llm_adjustments.items():
                candidate_map[transaction_id].add(evidence)

        ordered = sorted(
            (candidate for candidate in candidate_map.values() if candidate.score > 0),
            key=lambda candidate: (-candidate.score, candidate.transaction.timestamp, candidate.transaction.transaction_id),
        )

        selected = [candidate for candidate in ordered if candidate.score >= threshold]
        auto_min_candidates = min_candidates is None
        backfill_pool = ordered
        if auto_min_candidates:
            eligible_auto_backfill = [
                candidate for candidate in ordered if candidate.score >= self.auto_backfill_floor(threshold)
            ]
            min_candidates = min(12, len(eligible_auto_backfill))
            backfill_pool = eligible_auto_backfill
        if len(selected) < min_candidates:
            selected_ids = {candidate.transaction.transaction_id for candidate in selected}
            for candidate in backfill_pool:
                if candidate.transaction.transaction_id in selected_ids:
                    continue
                selected.append(candidate)
                selected_ids.add(candidate.transaction.transaction_id)
                if len(selected) >= min_candidates:
                    break

        hard_cap = max(min_candidates, int(len(dataset.transactions) * 0.2))
        return selected[:hard_cap]
