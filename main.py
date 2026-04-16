from __future__ import annotations

import argparse
from pathlib import Path

from reply_mirror_solver.llm import maybe_enrich_with_llm
from reply_mirror_solver.pipeline import (
    analyze_communications,
    evaluate_transactions,
    load_env_if_available,
    parse_dataset,
    write_outputs,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reply Mirror agent-style fraud detector.")
    parser.add_argument(
        "--dataset",
        default="The+Truman+Show+-+train\\The Truman Show - train",
        help="Path to the extracted dataset directory.",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs",
        help="Directory where the ASCII submission and JSON analysis report will be written.",
    )
    parser.add_argument(
        "--llm-mode",
        choices=("off", "auto", "force"),
        default="auto",
        help="Use OpenRouter + Langfuse arbitration when credentials and optional packages are available.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    load_env_if_available()

    dataset_dir = Path(args.dataset)
    transactions, profiles, locations_by_user, mails_by_user, sms_by_user = parse_dataset(dataset_dir)
    communication_evidence = analyze_communications(mails_by_user, sms_by_user)
    assessments = evaluate_transactions(transactions, profiles, locations_by_user, communication_evidence)
    llm_info = maybe_enrich_with_llm(assessments, args.llm_mode)
    submission_path, report_path = write_outputs(dataset_dir.name, Path(args.output_dir), assessments)

    print(f"Submission file: {submission_path}")
    print(f"Analysis report:  {report_path}")
    if llm_info.enabled:
        print(f"Langfuse session: {llm_info.session_id}")
    for note in llm_info.notes or []:
        print(f"- {note}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
