# Reply Mirror Solver

This project solves the task described in `AIAgentChallenge-ProblemStatement16April.pdf` for datasets shaped like `Brave+New+World+-+train.zip`.

The pipeline is intentionally agent-based:

- `IdentityLinkingAgent` maps people in `users.json` to account ids seen in transactions and GPS traces.
- `CommunicationRiskAgent` flags likely phishing or social-engineering messages from `sms.json` and `mails.json`.
- `BehavioralProfileAgent` builds per-account baselines from transactions and location history.
- `GeoTemporalAgent` detects remote ATM cash-out bursts that do not fit the GPS trail.
- `CounterpartyNoveltyAgent` looks for card-test patterns and suspicious follow-up money moves.
- `OrchestratorAgent` combines the evidence and writes the ASCII submission file.

## Files To Edit For Keys

Create a local `.env` file by copying `.env.example`, then replace the placeholder values for:

- `OPENROUTER_API_KEY`
- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_HOST`
- `TEAM_NAME`

No secrets are hardcoded in the solver. The optional OpenRouter/Langfuse review path reads only from `.env`.

## Recommended Setup

The challenge materials recommend Python 3.13 and `langfuse>=3,<4`.

Install dependencies:

```powershell
py -3 -m pip install -r requirements.txt
```

If your environment complains that `packaging` is missing, rerun the install command above. The optional OpenRouter/Langfuse review path depends on it through `langchain-openai` and `langfuse`.

Run the solver in offline heuristic mode:

```powershell
py -3 main.py `
  --dataset "Brave+New+World+-+train.zip" `
  --output "submission_train.txt" `
  --report "train_report.json"
```

Run with the optional OpenRouter judge and Langfuse tracing after filling `.env`:

```powershell
py -3 main.py `
  --dataset "Brave+New+World+-+train.zip" `
  --output "submission_train.txt" `
  --report "train_report.json" `
  --use-llm-judge
```

Run the prepared BladeRunner helper. It warms a Langfuse session, reuses that session for the scored run, and prints the session id plus the output paths at the end:

```powershell
.\run_bladerunner_best.ps1
```

If you want the fastest offline BladeRunner run with no network calls:

```powershell
.\run_bladerunner_best.ps1 -Offline
```

If the submission portal takes time to recognize a fresh Langfuse session, create a warm-up trace first and then reuse the same session id for the solver run:

```powershell
py -3 trace_session.py

py -3 main.py `
  --dataset "Brave+New+World+-+train.zip" `
  --output "submission_train.txt" `
  --report "train_report.json" `
  --use-llm-judge `
  --session-id "<paste-session-id-here>"
```

## Output Format

The submission file is ASCII text and contains one suspected fraudulent `transaction_id` per line, exactly as required by the challenge statement.

## What The Current Heuristics Prioritize

The current rule set is tuned to high-confidence fraud patterns visible in the provided training data:

- withdrawals in cities absent from a user's GPS history
- repeated cash-out withdrawals within a short interval
- e-commerce microcharges followed by a much larger charge at the same merchant
- suspicious follow-up transfers after phishing or after a confirmed compromise event

That keeps the output focused and reproducible while still leaving room for the optional LLM review stage.
