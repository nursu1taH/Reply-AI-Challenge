from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import ulid
from dotenv import load_dotenv


def load_env(search_root: Path | None = None) -> Path | None:
    root = (search_root or Path.cwd()).resolve()
    candidates = [
        root / ".env",
        root.parent / ".env",
        Path.cwd() / ".env",
    ]
    env_path = next((candidate for candidate in candidates if candidate.exists()), None)
    if env_path is not None:
        load_dotenv(dotenv_path=env_path, override=False)
    return env_path


def generate_session_id() -> str:
    team = os.getenv("TEAM_NAME", "blade-runner").replace(" ", "-")
    return f"{team}-{ulid.new().str}"


@dataclass(slots=True)
class AgentConfig:
    dataset_dir: Path
    database_path: Path
    output_path: Path
    explanation_path: Path
    model_name: str = "gpt-4o-mini"
    temperature: float = 0.1
    max_tokens: int = 300
    max_llm_cases: int = 36
    enable_llm: bool = True
    force_rebuild_db: bool = False
    target_fraud_rate: float = 0.045
    min_fraud_rate: float = 0.015
    max_fraud_rate: float = 0.10

    def ensure_directories(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.explanation_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def llm_ready(self) -> bool:
        return bool(
            self.enable_llm
            and os.getenv("OPENROUTER_API_KEY")
            and os.getenv("LANGFUSE_PUBLIC_KEY")
            and os.getenv("LANGFUSE_SECRET_KEY")
        )
