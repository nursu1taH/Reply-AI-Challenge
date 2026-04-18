# Deus+Ex Reply Mirror Submission

This repository now contains a runnable multi-agent fraud detection pipeline for the Reply Mirror challenge on the `Deus+Ex` dataset, plus the submission-tracing hooks required by the resource-management and tracking materials.

## What It Does

The pipeline is agent-based and scores each transaction with cooperating specialists:

- `UserVulnerabilityAgent`: weights the sender's phishing susceptibility from the user profile.
- `CommunicationRiskAgent`: looks for risky SMS/email events shortly before a transaction.
- `CounterpartyRiskAgent`: flags new or semantically inconsistent counterparties and finance-like merchants.
- `BehavioralAnomalyAgent`: detects amount, balance, timing, and cash-withdrawal anomalies.
- `TravelPatternAgent`: catches unrealistic location jumps between physical transactions.
- `AudioContextAgent`: indexes the audio files as additional context so the pipeline explicitly considers that modality.
- `LLMReviewer` (optional): runs a final OpenRouter review pass with Langfuse tracing using the exact `@observe() + CallbackHandler + langfuse_session_id` pattern from the supplied challenge material.

The required challenge output is written as an ASCII text file with one suspected fraudulent transaction ID per line.

## Where To Insert Your Keys

Create a `.env` file in the repo root by copying [`.env.example`](/D:/codexProjects/Deus-Ex/.env.example:1).

Insert your dataset-specific credentials in these variables:

- `OPENROUTER_API_KEY`
- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_HOST`
- `TEAM_NAME`

Those values are consumed in [`.env.example`](/D:/codexProjects/Deus-Ex/.env.example:1) and in the tracing client inside [deus_ex_agents/tracing.py](/D:/codexProjects/Deus-Ex/deus_ex_agents/tracing.py:1).

## Run It

The dataset zip has already been extracted to [dataset/Deus Ex - train](/D:/codexProjects/Deus-Ex/dataset/Deus%20Ex%20-%20train).

Heuristic mode, no API calls:

```powershell
py run_submission.py
```

LLM review mode with OpenRouter + Langfuse tracing:

```powershell
py run_submission.py --enable-llm-review --review-limit 40
```

Outputs:

- Submission file: [outputs/deus_ex_train_submission.txt](/D:/codexProjects/Deus-Ex/outputs/deus_ex_train_submission.txt)
- Diagnostic report: [outputs/deus_ex_train_report.json](/D:/codexProjects/Deus-Ex/outputs/deus_ex_train_report.json)

## Notes On The Supplied Challenge Files

- The core challenge constraints from `AIAgentChallenge-ProblemStatement16April.pdf` are satisfied by producing the ASCII transaction-ID submission file and shipping executable code plus dependency instructions.
- The Langfuse session tracing flow from `04-resource_management.pdf` and the extracted `track-your-submission/how-to-track-your-submission/main.py` starter is implemented in [deus_ex_agents/tracing.py](/D:/codexProjects/Deus-Ex/deus_ex_agents/tracing.py:1).
- I only found the extracted `track-your-submission` folder in this workspace, not a separate `track-your-submission.zip`, so the implementation uses the files that are present on disk.
