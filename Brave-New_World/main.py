from __future__ import annotations

import argparse
from pathlib import Path

from mirror_solver.pipeline import run_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reply Mirror fraud solver")
    parser.add_argument("--dataset", required=True, help="Path to the challenge zip or extracted dataset folder.")
    parser.add_argument("--output", required=True, help="Path to the ASCII submission file.")
    parser.add_argument("--report", default="", help="Optional JSON report path with candidate explanations.")
    parser.add_argument(
        "--threshold",
        type=float,
        default=5.0,
        help="Minimum fraud score required before a transaction is selected.",
    )
    parser.add_argument(
        "--min-candidates",
        type=int,
        default=0,
        help="Minimum number of suspicious transactions to emit. Defaults to an automatic dataset-size-based value.",
    )
    parser.add_argument(
        "--use-llm-judge",
        action="store_true",
        help="Review the top heuristic candidates with OpenRouter and trace them to Langfuse.",
    )
    parser.add_argument(
        "--llm-top-n",
        type=int,
        default=8,
        help="How many heuristic candidates to send to the optional LLM judge.",
    )
    parser.add_argument(
        "--session-id",
        default="",
        help="Optional Langfuse session id to reuse for this run.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    report_path = args.report or None
    min_candidates = args.min_candidates or None
    result = run_pipeline(
        dataset_path=args.dataset,
        output_path=args.output,
        report_path=report_path,
        threshold=args.threshold,
        min_candidates=min_candidates,
        use_llm_judge=args.use_llm_judge,
        llm_top_n=args.llm_top_n,
        session_id=args.session_id or None,
    )

    print(f"Selected {result['selected_count']} suspicious transactions.")
    print(f"Submission file: {Path(result['output_path']).resolve()}")
    if report_path:
        print(f"Report file: {Path(report_path).resolve()}")
    if result["llm_judge_enabled"]:
        print(f"Langfuse session id: {result['langfuse_session_id']}")
    else:
        print("LLM judge disabled or unavailable; offline heuristic mode was used.")
        if result.get("llm_judge_disabled_reason"):
            print(result["llm_judge_disabled_reason"])


if __name__ == "__main__":
    main()
