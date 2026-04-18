# Blade Runner Fraud Agent

This workspace now contains a submission-ready, agent-based fraud detector for the Reply Mirror challenge described in [AIAgentChallenge-ProblemStatement16April.pdf](D:/codexProjects/Blade-Runner/AIAgentChallenge-ProblemStatement16April.pdf). It is built around a local `blade_runner` SQLite database plus a cost-aware multi-agent pipeline:

- `CommunicationScoutAgent` parses `sms.json` and `mails.json`, identifies phishing-style messages, and builds user-level risk windows.
- `MobilitySentinelAgent` compares card-present transaction cities with GPS-derived location history from `locations.json`.
- `BehavioralAnomalyAgent` scores amount, time, recipient, merchant, burst, and balance-drain anomalies from `transactions.csv`.
- `LLMCaseReviewAgent` reviews only the highest-risk cases through LangChain/OpenRouter and traces every reviewed call to Langfuse using the session ID pattern from `track-your-submission` and `04-resource_management`.

## Files

- [run_agent.py](D:/codexProjects/Blade-Runner/run_agent.py): CLI entrypoint.
- [blade_runner_agent/config.py](D:/codexProjects/Blade-Runner/blade_runner_agent/config.py): environment loading and session ID generation.
- [blade_runner_agent/database.py](D:/codexProjects/Blade-Runner/blade_runner_agent/database.py): SQLite ingestion layer for the Blade Runner database.
- [blade_runner_agent/engine.py](D:/codexProjects/Blade-Runner/blade_runner_agent/engine.py): cooperating fraud agents and orchestration logic.
- [requirements.txt](D:/codexProjects/Blade-Runner/requirements.txt): reproducible dependency list.

## How To Run

1. Make sure the root `.env` contains:
   - `OPENROUTER_API_KEY`
   - `LANGFUSE_PUBLIC_KEY`
   - `LANGFUSE_SECRET_KEY`
   - `LANGFUSE_HOST`
   - `TEAM_NAME`
2. Install dependencies:

```powershell
py -m pip install -r requirements.txt
```

3. Run the agent on a dataset folder:

```powershell
py run_agent.py `
  --dataset-dir "Blade Runner - train" `
  --database-path "artifacts/blade_runner.sqlite" `
  --output-path "artifacts/suspected_fraud.txt" `
  --explanation-path "artifacts/review_summary.json"
```

4. Optional local-only run without external LLM calls:

```powershell
py run_agent.py --disable-llm
```

## Outputs

- `suspected_fraud.txt`: ASCII file with one suspected fraudulent transaction ID per line, matching the challenge output format.
- `review_summary.json`: a debug companion with the generated session ID, top flagged cases, and reasons.
- `blade_runner.sqlite`: the local Blade Runner database with raw challenge tables plus derived analysis tables.

## Session Tracing

The LLM reviewer uses the exact challenge-friendly session ID format:

- `{TEAM_NAME-with-spaces-replaced}-{ULID}`

Each LangChain review call passes:

- `config={"metadata": {"langfuse_session_id": session_id}}`

and creates the callback handler inside the traced function, matching the guidance in `track-your-submission` and `04-resource_management`.
