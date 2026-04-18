from __future__ import annotations

import json
import os
from typing import Dict, List, Optional

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    def load_dotenv() -> bool:  # type: ignore[no-redef]
        return False


try:
    from langchain_core.messages import HumanMessage
    from langchain_openai import ChatOpenAI
    from langfuse import Langfuse, observe
    from langfuse.langchain import CallbackHandler
    import ulid
except ImportError:  # pragma: no cover - optional dependency
    HumanMessage = None
    ChatOpenAI = None
    Langfuse = None
    CallbackHandler = None
    ulid = None

    def observe(*_args, **_kwargs):  # type: ignore[no-redef]
        def decorator(func):
            return func

        return decorator


load_dotenv()


class LLMReviewer:
    def __init__(self, model_name: Optional[str] = None) -> None:
        self.missing_components: List[str] = []
        if not ChatOpenAI or not HumanMessage:
            self.missing_components.append("langchain/langchain-openai")
        if not Langfuse or not CallbackHandler:
            self.missing_components.append("langfuse")
        if not ulid:
            self.missing_components.append("ulid-py")

        self.missing_env: List[str] = [
            env_name
            for env_name in ("OPENROUTER_API_KEY", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY")
            if not os.getenv(env_name)
        ]
        self.enabled = not self.missing_components and not self.missing_env
        self.session_id: Optional[str] = None
        if not self.enabled:
            self.model = None
            self.langfuse_client = None
            return
        self.model = ChatOpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
            model=model_name or os.getenv("OPENROUTER_MODEL", "gpt-4o-mini"),
            temperature=0.0,
            max_tokens=int(os.getenv("OPENROUTER_MAX_TOKENS", "350")),
        )
        self.langfuse_client = Langfuse(
            public_key=os.getenv("LANGFUSE_PUBLIC_KEY"),
            secret_key=os.getenv("LANGFUSE_SECRET_KEY"),
            host=os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse"),
        )
        self.session_id = self.generate_session_id()

    @property
    def disabled_reason(self) -> str:
        parts: List[str] = []
        if self.missing_components:
            parts.append(f"missing packages: {', '.join(self.missing_components)}")
        if self.missing_env:
            parts.append(f"missing env vars: {', '.join(self.missing_env)}")
        return "; ".join(parts) if parts else "LLM review is enabled"

    def generate_session_id(self) -> str:
        team = os.getenv("TEAM_NAME", "deus-ex").replace(" ", "-")
        return f"{team}-{ulid.new().str}"

    @observe()
    def review_candidate(self, session_id: str, prompt: str) -> Dict[str, object]:
        if not self.enabled or not self.model:
            return {"verdict": "uncertain", "adjustment": 0.0, "rationale": "LLM review disabled"}
        handler = CallbackHandler()
        response = self.model.invoke(
            [HumanMessage(content=prompt)],
            config={
                "callbacks": [handler],
                "metadata": {"langfuse_session_id": session_id},
            },
        )
        content = response.content if isinstance(response.content, str) else json.dumps(response.content)
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            return {"verdict": "uncertain", "adjustment": 0.0, "rationale": content[:220]}
        if not isinstance(parsed, dict):
            return {"verdict": "uncertain", "adjustment": 0.0, "rationale": str(parsed)[:220]}
        parsed.setdefault("verdict", "uncertain")
        parsed.setdefault("adjustment", 0.0)
        parsed.setdefault("rationale", "No rationale returned")
        return parsed

    def review(self, candidates: List[Dict[str, object]]) -> List[Dict[str, object]]:
        if not self.enabled or not self.session_id:
            return []
        decisions: List[Dict[str, object]] = []
        for candidate in candidates:
            prompt = (
                "You are the final fraud adjudication agent for Reply Mirror.\n"
                "Review one transaction and return compact JSON only.\n"
                '{"verdict":"fraud|legit|uncertain","adjustment":number,"rationale":"..."}\n'
                "Keep adjustment between -0.6 and 0.6.\n"
                "Use the heuristic reasons as your primary evidence.\n\n"
                f"Candidate:\n{json.dumps(candidate, ensure_ascii=True, indent=2)}"
            )
            decision = self.review_candidate(self.session_id, prompt)
            decision["transaction_id"] = candidate["transaction_id"]
            decisions.append(decision)
        if self.langfuse_client:
            self.langfuse_client.flush()
        return decisions
