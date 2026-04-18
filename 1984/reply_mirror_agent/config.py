from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import ulid
from dotenv import load_dotenv


@dataclass(slots=True)
class Settings:
    project_root: Path
    dataset_dir: Path
    database_path: Path
    output_path: Path
    report_path: Path
    session_path: Path
    llm_mode: str
    model_name: str
    target_alert_rate: float
    candidate_limit: int
    rebuild_db: bool


def load_environment(env_path: Path | None = None) -> None:
    load_dotenv(dotenv_path=env_path)


def generate_session_id() -> str:
    team = os.getenv("TEAM_NAME", "tutorial").strip() or "tutorial"
    return f"{team.replace(' ', '-')}-{ulid.new().str}"


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
