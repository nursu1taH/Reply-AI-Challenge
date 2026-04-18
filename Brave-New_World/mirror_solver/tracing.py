from __future__ import annotations

import json
import os
import re
import site
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from .models import Candidate, DatasetBundle, Evidence, ResolvedIdentity


def _ensure_user_site_packages() -> None:
    workspace_site = Path(__file__).resolve().parent.parent / ".python_packages"
    if workspace_site.exists() and str(workspace_site) not in sys.path:
        sys.path.append(str(workspace_site))

    try:
        user_site = site.getusersitepackages()
    except Exception:  # pragma: no cover - defensive startup fallback
        return
    if not user_site or user_site in sys.path:
        return
    try:
        path_exists = Path(user_site).exists()
    except OSError:
        path_exists = True
    if path_exists:
        sys.path.append(user_site)


_ensure_user_site_packages()

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    load_dotenv = None

try:
    import ulid
except ImportError:  # pragma: no cover - optional dependency
    ulid = None

IMPORT_ERROR: str | None = None

try:
    from langchain_core.messages import HumanMessage
    from langchain_openai import ChatOpenAI
    from langfuse import Langfuse, observe, propagate_attributes
    from langfuse.langchain import CallbackHandler
except ImportError as error:  # pragma: no cover - optional dependency
    HumanMessage = None
    ChatOpenAI = None
    Langfuse = None
    CallbackHandler = None
    propagate_attributes = None
    IMPORT_ERROR = repr(error)

    def observe():
        def decorator(function):
            return function

        return decorator


def _load_env_file() -> None:
    candidate_paths: list[Path] = []
    for base in [Path.cwd(), Path(__file__).resolve().parent, Path(__file__).resolve().parent.parent]:
        for current in [base, *base.parents]:
            env_path = current / ".env"
            if env_path not in candidate_paths:
                candidate_paths.append(env_path)

    env_file = next((path for path in candidate_paths if path.exists()), None)
    if env_file is None:
        return

    if load_dotenv is not None:
        load_dotenv(dotenv_path=env_file, override=False)
        return

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def generate_session_id() -> str:
    _load_env_file()
    team = os.getenv("TEAM_NAME", "reply-mirror").replace(" ", "-")
    suffix = ulid.new().str if ulid is not None else uuid.uuid4().hex
    return f"{team}-{suffix}"


def _invoke_with_optional_session_propagation(model: ChatOpenAI, handler: CallbackHandler, session_id: str, prompt: dict[str, object] | str):
    if HumanMessage is None:
        raise RuntimeError("langchain_core.messages.HumanMessage is unavailable")

    messages = [HumanMessage(content=json.dumps(prompt, ensure_ascii=True) if isinstance(prompt, dict) else prompt)]
    config = {
        "callbacks": [handler],
        # Keep Reply's documented session metadata path and also propagate below for newer Langfuse builds.
        "metadata": {"langfuse_session_id": session_id},
    }

    if propagate_attributes is None:
        return model.invoke(messages, config=config)

    with propagate_attributes(session_id=session_id):
        return model.invoke(messages, config=config)


@observe()
def _warmup_llm_call(model: ChatOpenAI, session_id: str, prompt: str) -> str:
    if CallbackHandler is None:
        raise RuntimeError("langfuse.langchain.CallbackHandler is unavailable")

    handler = CallbackHandler()
    response = _invoke_with_optional_session_propagation(
        model=model,
        handler=handler,
        session_id=session_id,
        prompt=prompt,
    )
    return response.content if isinstance(response.content, str) else str(response.content)


def warm_up_session(session_id: str, prompt: str = "Reply with OK to initialize tracing for this session.") -> str:
    _load_env_file()
    api_key = os.getenv("OPENROUTER_API_KEY")
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    required = (ChatOpenAI, HumanMessage, Langfuse, CallbackHandler, api_key, public_key, secret_key)
    if any(item is None for item in required):
        missing = [
            name
            for name, value in [
                ("OPENROUTER_API_KEY", api_key),
                ("LANGFUSE_PUBLIC_KEY", public_key),
                ("LANGFUSE_SECRET_KEY", secret_key),
            ]
            if not value
        ]
        if missing:
            missing_text = ", ".join(missing)
            raise RuntimeError(f"Missing required environment variables: {missing_text}")
        if IMPORT_ERROR:
            raise RuntimeError(f"Optional LLM judge dependencies failed to import: {IMPORT_ERROR}")
        raise RuntimeError("Tracing dependencies are unavailable.")

    model = ChatOpenAI(
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        model=os.getenv("OPENROUTER_MODEL", "gpt-4o-mini"),
        temperature=0.0,
        max_tokens=20,
    )
    langfuse_client = Langfuse(
        public_key=public_key,
        secret_key=secret_key,
        host=os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse"),
    )

    _warmup_llm_call(model=model, session_id=session_id, prompt=prompt)
    langfuse_client.flush()
    langfuse_client.shutdown()
    return session_id


@dataclass(frozen=True)
class ReviewOutcome:
    evidences: dict[str, Evidence]
    session_id: str | None
    enabled: bool


class OptionalOpenRouterJudge:
    def __init__(self, enabled: bool, session_id: str | None = None) -> None:
        _load_env_file()
        self.enabled = enabled
        self.session_id: str | None = session_id
        self.model = None
        self.langfuse_client = None
        self.disabled_reason: str | None = None

        if not enabled:
            return
        api_key = os.getenv("OPENROUTER_API_KEY")
        public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
        secret_key = os.getenv("LANGFUSE_SECRET_KEY")
        required = (ChatOpenAI, HumanMessage, Langfuse, CallbackHandler, api_key, public_key, secret_key)
        if any(item is None for item in required):
            self.enabled = False
            missing = [
                name
                for name, value in [
                    ("OPENROUTER_API_KEY", api_key),
                    ("LANGFUSE_PUBLIC_KEY", public_key),
                    ("LANGFUSE_SECRET_KEY", secret_key),
                ]
                if not value
            ]
            if missing:
                missing_text = ", ".join(missing)
                self.disabled_reason = (
                    "Missing required environment variables: "
                    f"{missing_text}. Put them in a .env file next to main.py."
                )
            elif IMPORT_ERROR:
                self.disabled_reason = (
                    "Optional LLM judge dependencies failed to import: "
                    f"{IMPORT_ERROR}. Install the missing package(s) and rerun."
                )
            return

        self.session_id = self.session_id or generate_session_id()
        self.model = ChatOpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
            model=os.getenv("OPENROUTER_MODEL", "gpt-4o-mini"),
            temperature=0.1,
            max_tokens=350,
        )
        self.langfuse_client = Langfuse(
            public_key=public_key,
            secret_key=secret_key,
            host=os.getenv("LANGFUSE_HOST", "https://challenges.reply.com/langfuse"),
        )

    def review(
        self,
        candidates: list[Candidate],
        identities: dict[str, ResolvedIdentity],
        dataset: DatasetBundle,
        top_n: int = 8,
    ) -> ReviewOutcome:
        if not self.enabled or not self.model or not self.langfuse_client:
            return ReviewOutcome(evidences={}, session_id=None, enabled=False)

        evidence_map: dict[str, Evidence] = {}
        for candidate in candidates[:top_n]:
            try:
                evidence = self._review_single_candidate(candidate, identities, dataset)
            except Exception as error:  # pragma: no cover - network/runtime safety fallback
                self.disabled_reason = f"LLM judge failed during review: {type(error).__name__}: {error}"
                return ReviewOutcome(evidences={}, session_id=self.session_id, enabled=False)
            if evidence is not None:
                evidence_map[candidate.transaction.transaction_id] = evidence

        try:
            self.langfuse_client.flush()
        except Exception as error:  # pragma: no cover - network/runtime safety fallback
            self.disabled_reason = f"Langfuse flush failed: {type(error).__name__}: {error}"
        try:
            self.langfuse_client.shutdown()
        except Exception as error:  # pragma: no cover - network/runtime safety fallback
            self.disabled_reason = f"Langfuse shutdown failed: {type(error).__name__}: {error}"
        return ReviewOutcome(evidences=evidence_map, session_id=self.session_id, enabled=True)

    @observe()
    def _review_single_candidate(
        self,
        candidate: Candidate,
        identities: dict[str, ResolvedIdentity],
        dataset: DatasetBundle,
    ) -> Evidence | None:
        if not self.model or not self.session_id or HumanMessage is None or CallbackHandler is None:
            return None

        transaction = candidate.transaction
        resolved_identity = identities.get(transaction.sender_id)
        sender_name = resolved_identity.user.full_name if resolved_identity else transaction.sender_id
        recent_transactions = [
            tx
            for tx in dataset.transactions
            if tx.sender_id == transaction.sender_id and tx.timestamp <= transaction.timestamp
        ][-5:]
        prompt = {
            "task": "Rate whether the candidate transaction looks fraudulent in the Reply Mirror challenge.",
            "sender": sender_name,
            "candidate_transaction": {
                "transaction_id": transaction.transaction_id,
                "timestamp": transaction.timestamp.isoformat(),
                "type": transaction.transaction_type,
                "amount": transaction.amount,
                "location": transaction.location,
                "recipient_id": transaction.recipient_id,
                "description": transaction.description,
            },
            "heuristic_evidence": [
                {"reason": evidence.reason, "score": evidence.score, "details": evidence.details}
                for evidence in candidate.evidences
            ],
            "recent_transactions": [
                {
                    "timestamp": tx.timestamp.isoformat(),
                    "type": tx.transaction_type,
                    "amount": tx.amount,
                    "location": tx.location,
                    "recipient_id": tx.recipient_id,
                    "description": tx.description,
                }
                for tx in recent_transactions
            ],
            "response_format": {
                "label": "fraud | unclear | likely_legit",
                "risk_adjustment": "number between -1.0 and 2.0",
                "rationale": "short sentence",
            },
        }
        handler = CallbackHandler()
        response = _invoke_with_optional_session_propagation(
            model=self.model,
            handler=handler,
            session_id=self.session_id,
            prompt=prompt,
        )
        content = response.content if isinstance(response.content, str) else str(response.content)
        match = re.search(r"\{.*\}", content, re.DOTALL)
        if not match:
            return None
        try:
            payload = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

        label = str(payload.get("label", "")).lower()
        if label not in {"fraud", "unclear"}:
            return None
        try:
            adjustment = float(payload.get("risk_adjustment", 0.0))
        except (TypeError, ValueError):
            return None
        if adjustment <= 0:
            return None
        rationale = str(payload.get("rationale", "LLM review supported the fraud hypothesis.")).strip()
        return Evidence(
            agent="llm_judge",
            score=min(adjustment, 2.0),
            reason=rationale,
            details={"label": label, "session_id": self.session_id},
        )
