from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .agents import SenderMemory, build_default_agents
from .domain import TransactionAssessment
from .io import load_dataset_context
from .tracing import LLMReviewer


class FraudDetectionPipeline:
    def __init__(
        self,
        dataset_path: Path,
        output_path: Path,
        report_path: Optional[Path] = None,
        flag_rate: float = 0.09,
        review_limit: int = 0,
        enable_llm_review: bool = False,
    ) -> None:
        self.dataset_path = dataset_path
        self.output_path = output_path
        self.report_path = report_path
        self.flag_rate = flag_rate
        self.review_limit = review_limit
        self.enable_llm_review = enable_llm_review

    def run(self) -> Dict[str, object]:
        context = load_dataset_context(self.dataset_path)
        agents = build_default_agents()
        memories: Dict[str, SenderMemory] = {}
        assessments: List[TransactionAssessment] = []
        llm_review_info = {
            "requested": self.enable_llm_review,
            "enabled": False,
            "session_id": None,
            "reviewed_candidates": 0,
            "status": "LLM review not requested",
        }

        for tx in context.transactions:
            user = context.users.get(tx.sender_id)
            memory = memories.setdefault(
                tx.sender_id,
                SenderMemory(home_city=user.home_city if user else None),
            )
            memory.trim(tx.timestamp)

            assessment = TransactionAssessment(transaction=tx)
            for agent in agents:
                agent.assess(assessment, context, memory, user)
            if tx.is_salary:
                assessment.score = -9.0
                assessment.reasons = ["salary payment baseline event"]
            assessments.append(assessment)
            memory.record(tx)

        if self.enable_llm_review and self.review_limit > 0:
            llm_review_info = self.apply_llm_review(context, assessments)

        suspects = self.select_suspects(assessments)
        self.write_submission(suspects)
        if self.report_path:
            self.write_report(assessments, suspects, llm_review_info)

        return {
            "transaction_count": len(assessments),
            "suspect_count": len(suspects),
            "output_path": str(self.output_path),
            "report_path": str(self.report_path) if self.report_path else None,
            "llm_review": llm_review_info,
        }

    def apply_llm_review(self, context, assessments: List[TransactionAssessment]) -> Dict[str, object]:
        reviewer = LLMReviewer()
        if not reviewer.enabled:
            return {
                "requested": True,
                "enabled": False,
                "session_id": None,
                "reviewed_candidates": 0,
                "status": reviewer.disabled_reason,
            }
        candidates = []
        top_candidates = sorted(assessments, key=lambda item: item.score, reverse=True)[: self.review_limit]
        for assessment in top_candidates:
            tx = assessment.transaction
            user = context.users.get(tx.sender_id)
            candidates.append(
                {
                    "transaction_id": tx.transaction_id,
                    "sender_id": tx.sender_id,
                    "transaction_type": tx.transaction_type,
                    "amount": tx.amount,
                    "location": tx.location,
                    "description": tx.description,
                    "timestamp": tx.timestamp.isoformat(),
                    "heuristic_score": round(assessment.score, 4),
                    "reasons": assessment.reasons[:6],
                    "user_context": {
                        "monthly_salary": round(user.monthly_salary, 2) if user else None,
                        "home_city": user.home_city if user else None,
                    },
                }
            )
        decisions = reviewer.review(candidates)
        decision_map = {decision["transaction_id"]: decision for decision in decisions}
        for assessment in top_candidates:
            decision = decision_map.get(assessment.transaction.transaction_id)
            if not decision:
                continue
            try:
                adjustment = float(decision.get("adjustment", 0.0))
            except (TypeError, ValueError):
                adjustment = 0.0
            adjustment = max(-0.6, min(0.6, adjustment))
            assessment.score += adjustment
            assessment.llm_review = {
                "verdict": str(decision.get("verdict", "uncertain")),
                "rationale": str(decision.get("rationale", ""))[:240],
                "session_id": reviewer.session_id or "",
            }
            assessment.reasons.append(
                f"llm review: {assessment.llm_review['verdict']} ({assessment.llm_review['rationale']})"
            )
        return {
            "requested": True,
            "enabled": True,
            "session_id": reviewer.session_id,
            "reviewed_candidates": len(candidates),
            "status": "LLM review completed",
        }

    def select_suspects(self, assessments: List[TransactionAssessment]) -> List[TransactionAssessment]:
        eligible = [assessment for assessment in assessments if not assessment.transaction.is_salary]
        ranked = sorted(eligible, key=lambda item: item.score, reverse=True)
        desired = max(24, min(int(len(eligible) * self.flag_rate), int(len(eligible) * 0.18)))
        cut_score = ranked[desired - 1].score if ranked and desired <= len(ranked) else 0.0
        suspects = [assessment for assessment in ranked if assessment.score >= cut_score]
        if len(suspects) > int(len(eligible) * 0.18):
            suspects = suspects[: int(len(eligible) * 0.18)]
        if not suspects and ranked:
            suspects = ranked[:24]
        return suspects

    def write_submission(self, suspects: Iterable[TransactionAssessment]) -> None:
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        with self.output_path.open("w", encoding="ascii", newline="\n") as handle:
            for assessment in suspects:
                handle.write(f"{assessment.transaction.transaction_id}\n")

    def write_report(
        self,
        assessments: List[TransactionAssessment],
        suspects: List[TransactionAssessment],
        llm_review_info: Dict[str, object],
    ) -> None:
        assert self.report_path is not None
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "summary": {
                "transactions": len(assessments),
                "suspects": len(suspects),
                "flag_rate": round(len(suspects) / max(1, len(assessments)), 4),
                "llm_review": llm_review_info,
            },
            "top_suspects": [
                {
                    "transaction_id": assessment.transaction.transaction_id,
                    "sender_id": assessment.transaction.sender_id,
                    "transaction_type": assessment.transaction.transaction_type,
                    "amount": assessment.transaction.amount,
                    "location": assessment.transaction.location,
                    "description": assessment.transaction.description,
                    "timestamp": assessment.transaction.timestamp.isoformat(),
                    "score": round(assessment.score, 4),
                    "agent_scores": {
                        name: round(value, 4) for name, value in sorted(assessment.agent_scores.items())
                    },
                    "reasons": assessment.reasons[:8],
                    "llm_review": assessment.llm_review,
                }
                for assessment in suspects[:120]
            ],
        }
        self.report_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")
