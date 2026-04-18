# Reply Mirror Agent

This project builds an agent-based fraud detector for the Reply Mirror challenge using the files in this folder and a shared SQLite database named `1984.db`.

## What It Does

The pipeline ingests:

- `transactions.csv`
- `users.json`
- `locations.json`
- `sms.json`
- `mails.json`
- `audio/*.mp3` metadata

It then runs a cooperative set of agents:

- `CommunicationRiskAgent`: scores phishing pressure and social-engineering windows from SMS and emails.
- `BehavioralBaselineAgent`: scores amount, timing, novelty, burst, and balance-depletion anomalies.
- `GeoTemporalAgent`: checks whether physical transactions align with the user GPS trail and residence.
- `CounterpartyGraphAgent`: scores suspicious shared counterparties, short-lived campaigns, and pass-through flows.
- `LLMAdjudicatorAgent`: optional OpenRouter + Langfuse challenge-traced final reviewer for the highest-risk candidates.

The required challenge session id is always generated in the correct format:

`{TEAM_NAME}-{ULID}`

and written to `artifacts/session_id.txt`.

## Run

```powershell
py -m pip install -r requirements.txt
py main.py --dataset "train/1984 - train" --database 1984.db --output artifacts/submission.txt
```

If you want the final LLM adjudicator enabled:

```powershell
py main.py --dataset "train/1984 - train" --database 1984.db --use-llm on
```

The root `.env` is used automatically. The challenge keys already present there are used for:

- OpenRouter
- Langfuse
- team name based session ids

## Outputs

- `1984.db`: shared SQLite knowledge base
- `artifacts/submission.txt`: newline-separated suspected fraudulent transaction ids
- `artifacts/report.json`: scored transaction report with agent reasons
- `artifacts/session_id.txt`: challenge session id

## Notes

- The default run works without pandas, numpy, or scikit-learn.
- The LLM step is optional and loaded lazily so the statistical agents still run if Langfuse or LangChain are unavailable locally.
- The output file contains only ASCII transaction ids, matching the challenge requirement.
