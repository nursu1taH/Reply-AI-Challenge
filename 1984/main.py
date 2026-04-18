from __future__ import annotations

import argparse
import json
from pathlib import Path

from reply_mirror_agent.agents import FraudOrchestrator
from reply_mirror_agent.config import Settings, ensure_parent, generate_session_id, load_environment
from reply_mirror_agent.database import MirrorDatabase


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reply Mirror multi-agent fraud detector",
    )
    parser.add_argument(
        "--dataset",
        default="train/1984 - train",
        help="Path to the dataset directory",
    )
    parser.add_argument(
        "--database",
        default="1984.db",
        help="SQLite database path for the shared 1984 knowledge base",
    )
    parser.add_argument(
        "--output",
        default="artifacts/submission.txt",
        help="ASCII output file with one fraudulent transaction id per line",
    )
    parser.add_argument(
        "--report",
        default="artifacts/report.json",
        help="JSON report with top scored transactions and agent signals",
    )
    parser.add_argument(
        "--session-file",
        default="artifacts/session_id.txt",
        help="Where to persist the Langfuse session id",
    )
    parser.add_argument(
        "--use-llm",
        choices=("off", "auto", "on"),
        default="auto",
        help="Whether to run the optional LLM adjudicator",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="OpenRouter model name for the optional LLM adjudicator",
    )
    parser.add_argument(
        "--target-alert-rate",
        type=float,
        default=0.06,
        help="Approximate fraction of transactions to flag",
    )
    parser.add_argument(
        "--candidate-limit",
        type=int,
        default=80,
        help="Maximum number of transactions to send to the LLM adjudicator",
    )
    parser.add_argument(
        "--rebuild-db",
        action="store_true",
        help="Rebuild the local SQLite database from scratch",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parent
    settings = Settings(
        project_root=project_root,
        dataset_dir=(project_root / args.dataset).resolve(),
        database_path=(project_root / args.database).resolve(),
        output_path=(project_root / args.output).resolve(),
        report_path=(project_root / args.report).resolve(),
        session_path=(project_root / args.session_file).resolve(),
        llm_mode=args.use_llm,
        model_name=args.model,
        target_alert_rate=args.target_alert_rate,
        candidate_limit=args.candidate_limit,
        rebuild_db=args.rebuild_db,
    )

    load_environment(project_root / ".env")
    session_id = generate_session_id()

    ensure_parent(settings.output_path)
    ensure_parent(settings.report_path)
    ensure_parent(settings.session_path)
    settings.session_path.write_text(session_id + "\n", encoding="ascii")

    database = MirrorDatabase(settings.database_path)
    database.build_from_dataset(settings.dataset_dir, rebuild=settings.rebuild_db)
    bundle = database.load_bundle()

    orchestrator = FraudOrchestrator(settings, session_id)
    suspects, report = orchestrator.run(bundle)

    settings.output_path.write_text("\n".join(suspects) + "\n", encoding="ascii")
    settings.report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=True),
        encoding="utf-8",
    )

    print(f"session_id: {session_id}")
    print(f"database:   {settings.database_path}")
    print(f"flagged:    {len(suspects)} transactions")
    print(f"submission: {settings.output_path}")
    print(f"report:     {settings.report_path}")


if __name__ == "__main__":
    main()

