from __future__ import annotations

import argparse

from mirror_solver.tracing import generate_session_id, warm_up_session


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a traced Langfuse session for challenge submissions.")
    parser.add_argument(
        "--session-id",
        default="",
        help="Optional existing session id to warm up instead of generating a new one.",
    )
    parser.add_argument(
        "--prompt",
        default="Reply with OK to initialize tracing for this session.",
        help="Short prompt used to create the warm-up trace.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    session_id = args.session_id or generate_session_id()
    warm_up_session(session_id=session_id, prompt=args.prompt)
    print(f"Langfuse session id: {session_id}")


if __name__ == "__main__":
    main()
