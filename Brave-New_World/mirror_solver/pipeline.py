from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .agents import (
    BehavioralProfileAgent,
    CommunicationRiskAgent,
    CounterpartyNoveltyAgent,
    GeoTemporalAgent,
    IdentityLinkingAgent,
    OrchestratorAgent,
)
from .dataset import load_dataset
from .models import Candidate, DatasetBundle, Evidence, ResolvedIdentity
from .tracing import OptionalOpenRouterJudge


def _candidate_to_report_row(candidate: Candidate) -> dict[str, object]:
    transaction = candidate.transaction
    return {
        "transaction_id": transaction.transaction_id,
        "sender_id": transaction.sender_id,
        "timestamp": transaction.timestamp.isoformat(),
        "transaction_type": transaction.transaction_type,
        "amount": transaction.amount,
        "location": transaction.location,
        "recipient_id": transaction.recipient_id,
        "description": transaction.description,
        "score": round(candidate.score, 3),
        "evidences": [
            {
                "agent": evidence.agent,
                "score": evidence.score,
                "reason": evidence.reason,
                "details": evidence.details,
            }
            for evidence in candidate.evidences
        ],
    }


def _build_dataset_profile(dataset: DatasetBundle) -> dict[str, object]:
    return {
        "transaction_count": len(dataset.transactions),
        "user_count": len(dataset.users),
        "location_ping_count": len(dataset.locations),
        "sms_count": len(dataset.sms),
        "mail_count": len(dataset.mails),
        "transaction_type_counts": dict(sorted(Counter(item.transaction_type for item in dataset.transactions).items())),
        "payment_method_counts": dict(
            sorted(Counter((item.payment_method or "unlabeled") for item in dataset.transactions).items())
        ),
    }


def _build_heuristic_fit_summary(
    dataset: DatasetBundle,
    identities: dict[str, ResolvedIdentity],
    phishing_alerts: dict[str, list[object]],
    geo_evidence: dict[str, list[Evidence]],
    novelty_evidence: dict[str, list[Evidence]],
) -> dict[str, object]:
    transactions_by_id = {transaction.transaction_id: transaction for transaction in dataset.transactions}
    geo_accounts = {transactions_by_id[transaction_id].sender_id for transaction_id in geo_evidence}
    microcharge_transactions = {
        transaction_id
        for transaction_id, evidences in novelty_evidence.items()
        if any(
            "microcharge_transaction_id" in evidence.details or "follow_up_transaction_id" in evidence.details
            for evidence in evidences
        )
    }
    post_compromise_transactions = {
        transaction_id
        for transaction_id, evidences in novelty_evidence.items()
        if any(
            bool(evidence.details.get("recent_alert")) or bool(evidence.details.get("recent_compromise_anchor"))
            for evidence in evidences
        )
    }
    return {
        "resolved_account_count": len(identities),
        "accounts_with_message_alerts": len(phishing_alerts),
        "message_alert_count": sum(len(alerts) for alerts in phishing_alerts.values()),
        "geo_anomaly_transaction_count": len(geo_evidence),
        "geo_anomaly_account_count": len(geo_accounts),
        "microcharge_transaction_count": len(microcharge_transactions),
        "post_compromise_transaction_count": len(post_compromise_transactions),
    }


def _build_selection_summary(
    scored_candidates: list[Candidate],
    final_candidates: list[Candidate],
    threshold: float,
    requested_min_candidates: int | None,
) -> dict[str, object]:
    threshold_selected_count = sum(candidate.score >= threshold for candidate in scored_candidates)
    backfill_floor = OrchestratorAgent.auto_backfill_floor(threshold)
    eligible_auto_backfill_count = sum(candidate.score >= backfill_floor for candidate in scored_candidates)
    effective_min_candidates = (
        requested_min_candidates if requested_min_candidates is not None else min(12, eligible_auto_backfill_count)
    )
    return {
        "threshold": threshold,
        "requested_min_candidates": requested_min_candidates,
        "effective_min_candidates": effective_min_candidates,
        "auto_backfill_floor": round(backfill_floor, 3),
        "scored_candidate_count": len(scored_candidates),
        "threshold_selected_count": threshold_selected_count,
        "eligible_auto_backfill_count": eligible_auto_backfill_count,
        "final_selected_count": len(final_candidates),
        "backfilled_below_threshold_count": max(0, len(final_candidates) - threshold_selected_count),
        "top_candidate_scores": [round(candidate.score, 3) for candidate in scored_candidates[:10]],
    }


def _build_llm_review_pool(scored_candidates: list[Candidate], threshold: float) -> list[Candidate]:
    if threshold <= 0:
        return scored_candidates

    # The LLM judge can add at most +2.0, so prioritize borderline candidates
    # that can still cross the threshold if the model confirms the fraud signal.
    rescue_floor = max(0.0, threshold - 2.0)
    borderline = [candidate for candidate in scored_candidates if rescue_floor <= candidate.score < threshold]
    already_selected = [candidate for candidate in scored_candidates if candidate.score >= threshold]
    return [*borderline, *already_selected]


def run_pipeline(
    dataset_path: str | Path,
    output_path: str | Path,
    report_path: str | Path | None = None,
    threshold: float = 5.0,
    min_candidates: int | None = None,
    use_llm_judge: bool = False,
    llm_top_n: int = 8,
    session_id: str | None = None,
) -> dict[str, object]:
    dataset = load_dataset(dataset_path)

    identity_agent = IdentityLinkingAgent()
    behavior_agent = BehavioralProfileAgent()
    communication_agent = CommunicationRiskAgent()
    geo_temporal_agent = GeoTemporalAgent()
    novelty_agent = CounterpartyNoveltyAgent()
    orchestrator = OrchestratorAgent()

    identities = identity_agent.analyze(dataset)
    behaviors = behavior_agent.analyze(dataset)
    phishing_alerts, message_log = communication_agent.analyze(dataset, identities)
    geo_evidence, geo_anchors = geo_temporal_agent.analyze(behaviors)
    novelty_evidence, _ = novelty_agent.analyze(behaviors, phishing_alerts, geo_anchors)

    review_pool = _build_llm_review_pool(
        orchestrator.select(
            dataset=dataset,
            evidence_groups=[geo_evidence, novelty_evidence],
            threshold=0.0,
            min_candidates=0,
        ),
        threshold=threshold,
    )

    llm_judge = OptionalOpenRouterJudge(enabled=use_llm_judge, session_id=session_id)
    review_outcome = llm_judge.review(
        candidates=review_pool,
        identities=identities,
        dataset=dataset,
        top_n=llm_top_n,
    )

    final_candidates = orchestrator.select(
        dataset=dataset,
        evidence_groups=[geo_evidence, novelty_evidence],
        threshold=threshold,
        min_candidates=min_candidates,
        llm_adjustments=review_outcome.evidences,
    )
    scored_candidates = orchestrator.select(
        dataset=dataset,
        evidence_groups=[geo_evidence, novelty_evidence],
        threshold=0.0,
        min_candidates=0,
        llm_adjustments=review_outcome.evidences,
    )

    output_file = Path(output_path)
    output_file.write_text(
        "".join(f"{candidate.transaction.transaction_id}\n" for candidate in final_candidates),
        encoding="ascii",
    )

    report_payload = {
        "dataset_path": str(Path(dataset_path).resolve()),
        "output_path": str(output_file.resolve()),
        "selected_count": len(final_candidates),
        "threshold": threshold,
        "min_candidates": min_candidates,
        "llm_judge_enabled": review_outcome.enabled,
        "langfuse_session_id": review_outcome.session_id,
        "llm_judge_disabled_reason": llm_judge.disabled_reason,
        "dataset_profile": _build_dataset_profile(dataset),
        "heuristic_fit_summary": _build_heuristic_fit_summary(
            dataset=dataset,
            identities=identities,
            phishing_alerts=phishing_alerts,
            geo_evidence=geo_evidence,
            novelty_evidence=novelty_evidence,
        ),
        "selection_summary": _build_selection_summary(
            scored_candidates=scored_candidates,
            final_candidates=final_candidates,
            threshold=threshold,
            requested_min_candidates=min_candidates,
        ),
        "resolved_accounts": [
            {
                "account_id": account_id,
                "user": resolved.user.full_name,
                "residence_city": resolved.user.residence_city,
                "matching_score": round(resolved.score, 3),
            }
            for account_id, resolved in sorted(identities.items())
        ],
        "suspicious_messages": [
            {"account_id": account_id, "messages": messages}
            for account_id, messages in sorted(message_log.items())
        ],
        "candidates": [_candidate_to_report_row(candidate) for candidate in final_candidates],
    }

    if report_path is not None:
        Path(report_path).write_text(json.dumps(report_payload, indent=2, ensure_ascii=True), encoding="utf-8")

    return report_payload
