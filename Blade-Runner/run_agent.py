from __future__ import annotations

import argparse
import json
from pathlib import Path

from blade_runner_agent import AgentConfig, BladeRunnerEngine, load_env


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the Blade Runner multi-agent fraud detector."
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("Blade Runner - train"),
        help="Directory containing transactions.csv, users.json, sms.json, mails.json, and locations.json",
    )
    parser.add_argument(
        "--database-path",
        type=Path,
        default=Path("artifacts/blade_runner.sqlite"),
        help="SQLite database path for the local Blade Runner database",
    )
    parser.add_argument(
        "--output-path",
        type=Path,
        default=Path("artifacts/suspected_fraud.txt"),
        help="ASCII output file containing one flagged transaction id per line",
    )
    parser.add_argument(
        "--explanation-path",
        type=Path,
        default=Path("artifacts/review_summary.json"),
        help="Debug file with top scores, reasons, and session metadata",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="OpenRouter model name for the final LLM review agent",
    )
    parser.add_argument(
        "--max-llm-cases",
        type=int,
        default=36,
        help="How many high-risk transactions the LLM adjudicator is allowed to review",
    )
    parser.add_argument(
        "--disable-llm",
        action="store_true",
        help="Skip the LLM adjudicator and run the local anomaly agents only",
    )
    parser.add_argument(
        "--force-rebuild-db",
        action="store_true",
        help="Delete and rebuild the SQLite database from the raw challenge files",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    load_env(Path.cwd())

    config = AgentConfig(
        dataset_dir=args.dataset_dir.resolve(),
        database_path=args.database_path.resolve(),
        output_path=args.output_path.resolve(),
        explanation_path=args.explanation_path.resolve(),
        model_name=args.model,
        max_llm_cases=args.max_llm_cases,
        enable_llm=not args.disable_llm,
        force_rebuild_db=args.force_rebuild_db,
    )

    engine = BladeRunnerEngine(config)
    result = engine.run()
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
