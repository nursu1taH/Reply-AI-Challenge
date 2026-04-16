from __future__ import annotations

import json
import os
from dataclasses import dataclass

from .pipeline import FRAUD_THRESHOLD, TransactionAssessment


@dataclass
class LLMEnhancement:
    enabled: bool
    session_id: str | None = None
    notes: list[str] | None = None


def maybe_enrich_with_llm(assessments: list[TransactionAssessment], mode: str) -> LLMEnhancement:
    if mode == "off":
        return LLMEnhancement(enabled=False, notes=["LLM mode disabled."])

    required_env = (
        "OPENROUTER_API_KEY",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
        "TEAM_NAME",
    )
    if not all(os.getenv(name) for name in required_env):
        return LLMEnhancement(
            enabled=False,
            notes=[
                "LLM mode skipped because one or more environment variables are missing: "
                + ", ".join(name for name in required_env if not os.getenv(name))
            ],
        )

    try:
        import ulid
        from langchain_core.messages import HumanMessage
        from langchain_openai import ChatOpenAI
        from langfuse import Langfuse, observe
        from langfuse.langchain import CallbackHandler
    except ImportError as exc:
        if mode == "force":
            raise
        return LLMEnhancement(enabled=False, notes=[f"LLM mode skipped because optional packages are unavailable: {exc}"])

    model_id = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
    session_id = f"{os.getenv('TEAM_NAME', 'reply-mirror').replace(' ', '-')}-{ulid.new().str}"
    langfuse_client = Langfuse(
        public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
        secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
        host=os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse"),
    )
    model = ChatOpenAI(
        api_key=os.getenv("OPENROUTER_API_KEY"),
        base_url="https://openrouter.ai/api/v1",
        model=model_id,
        temperature=0.1,
        max_tokens=700,
    )

    @observe()
    def review_candidates(candidate_payload: list[dict]) -> list[dict]:
        handler = CallbackHandler()
        prompt = (
            "You are the final fraud-arbitration agent for the Reply Mirror challenge.\n"
            "Review the candidate transactions and return JSON with one object per item.\n"
            "Each object must contain transaction_id, llm_risk_score (0-1), and short_reason.\n"
            "Be conservative and focus on likely fraud only.\n\n"
            f"Candidates:\n{json.dumps(candidate_payload, indent=2)}"
        )
        response = model.invoke(
            [HumanMessage(content=prompt)],
            config={
                "callbacks": [handler],
                "metadata": {"langfuse_session_id": session_id},
            },
        )
        text = response.content if isinstance(response.content, str) else json.dumps(response.content)
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1:
            raise ValueError("LLM output did not contain a JSON array.")
        return json.loads(text[start : end + 1])

    ranked = sorted(assessments, key=lambda item: item.final_score, reverse=True)[:6]
    payload = [
        {
            "transaction_id": item.transaction_id,
            "sender_id": item.sender_id,
            "heuristic_score": item.heuristic_score,
            "reasons": item.reasons,
            "transaction_type": item.transaction_type,
            "amount": item.amount,
            "recipient_id": item.recipient_id,
            "payment_method": item.payment_method,
            "timestamp": item.timestamp,
        }
        for item in ranked
    ]
    llm_results = review_candidates(payload)
    llm_map = {item["transaction_id"]: item for item in llm_results}
    for assessment in assessments:
        result = llm_map.get(assessment.transaction_id)
        if not result:
            continue
        llm_score = float(result.get("llm_risk_score", assessment.final_score))
        assessment.final_score = round((assessment.heuristic_score * 0.65) + (llm_score * 0.35), 4)
        if result.get("short_reason"):
            assessment.reasons.append(f"llm:{result['short_reason']}")
        assessment.decision = "fraud" if assessment.final_score >= FRAUD_THRESHOLD else "legit"

    langfuse_client.flush()
    return LLMEnhancement(enabled=True, session_id=session_id, notes=[f"LLM arbitration ran with model {model_id}."])
