from __future__ import annotations

import argparse
import os
from pathlib import Path

from deus_ex_agents import FraudDetectionPipeline

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    def load_dotenv() -> bool:  # type: ignore[no-redef]
        return False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the Reply Mirror multi-agent fraud detector on a Deus+Ex dataset."
    )
    parser.add_argument(
        "--dataset",
        type=Path,
        default=Path("dataset") / "Deus Ex - train",
        help="Path to the extracted dataset directory.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("outputs") / "deus_ex_train_submission.txt",
        help="ASCII output file containing one suspected fraudulent transaction ID per line.",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("outputs") / "deus_ex_train_report.json",
        help="Optional JSON report with top scored transactions and reasons.",
    )
    parser.add_argument(
        "--flag-rate",
        type=float,
        default=0.09,
        help="Fraction of non-salary transactions to flag as suspicious.",
    )
    parser.add_argument(
        "--enable-llm-review",
        action="store_true",
        help="Use OpenRouter + Langfuse for a final review pass on top candidates.",
    )
    parser.add_argument(
        "--review-limit",
        type=int,
        default=40,
        help="How many top candidates to send through the LLM review agent when enabled.",
    )
    return parser


def main() -> None:
    load_dotenv()
    args = build_parser().parse_args()
    env_enable_llm_review = os.getenv("ENABLE_LLM_REVIEW", "0").lower() in {"1", "true", "yes"}
    pipeline = FraudDetectionPipeline(
        dataset_path=args.dataset,
        output_path=args.output,
        report_path=args.report,
        flag_rate=args.flag_rate,
        review_limit=args.review_limit,
        enable_llm_review=args.enable_llm_review or env_enable_llm_review,
    )
    result = pipeline.run()
    print(
        f"Processed {result['transaction_count']} transactions and flagged "
        f"{result['suspect_count']} candidates."
    )
    print(f"Submission file: {result['output_path']}")
    if result["report_path"]:
        print(f"Report file: {result['report_path']}")
    llm_review = result["llm_review"]
    if llm_review["requested"]:
        if llm_review["enabled"]:
            print(f"Langfuse session ID: {llm_review['session_id']}")
            print(f"LLM-reviewed candidates: {llm_review['reviewed_candidates']}")
        else:
            print(f"LLM review disabled: {llm_review['status']}")


if __name__ == "__main__":
    main()
