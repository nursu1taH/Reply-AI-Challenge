# Reply Mirror Solver

This repo now contains a runnable, reproducible solution for the `AIAgentChallenge-ProblemStatement16April` task on `The+Truman+Show+-+train`.

It follows the challenge requirements:

- agent-style workflow instead of a single static rule
- ASCII submission output with one suspected fraudulent transaction ID per line
- reproducible execution steps
- optional Langfuse tracing grouped by `langfuse_session_id`

## What was added

- `main.py`: CLI entrypoint
- `reply_mirror_solver/pipeline.py`: data loading, profiling, communication analysis, fraud scoring, output writing
- `reply_mirror_solver/llm.py`: optional OpenRouter + Langfuse arbitration layer
- `.env.example`: where to place your OpenRouter and Langfuse credentials
- `requirements.txt`: challenge dependencies for traced LLM mode

## Where to insert your keys

Create a `.env` file in the repo root and copy the variables from [.env.example](/D:/codexProjects/Reply-AI-Challenge/.env.example).

Insert your values here:

- `OPENROUTER_API_KEY=...`
- `LANGFUSE_PUBLIC_KEY=...`
- `LANGFUSE_SECRET_KEY=...`
- `LANGFUSE_HOST=...`
- `TEAM_NAME=...`

You said you already have one OpenRouter key and Langfuse host/public/private keys for each dataset. This code is ready for that setup; just swap the `.env` values before running a different dataset.

## How to run

Heuristic-only run:

```powershell
py -3 main.py --llm-mode off
```

Traced OpenRouter + Langfuse run:

```powershell
py -3 main.py --llm-mode auto
```

The default dataset path already points to:

`The+Truman+Show+-+train\The Truman Show - train`

Outputs are written to `outputs/`:

- `*_submission.txt`: required ASCII submission file
- `*_analysis.json`: ranked evidence and scores for inspection

## Agent workflow

The solution uses four cooperating stages:

1. `Profile Agent`
   Builds each citizen's financial baseline from recurring salaries, rent, job context, and residence.

2. `Communication Agent`
   Reads mail and SMS threads, separates suspicious vs benign messages, and extracts themes such as PayPal, shopping, banking, utilities, and rideshare.

3. `Anomaly Agent`
   Scores every user-originated transaction for novelty, one-off counterparties, amount breaks, travel mismatch, and description/payment anomalies.

4. `Decision Agent`
   Produces the final fraud list. When `.env` credentials and optional dependencies are available, it can also call OpenRouter and trace that arbitration in Langfuse using the same session grouping pattern described in `04-resource_management`.

## Current default submission

Running the heuristic pipeline on `The Truman Show - train` produces the submission file in `outputs/`.

The current highest-risk transactions are expected to be:

- Alain's PayPal marketplace purchase
- Karl-Hermann's one-off internet bill transfer while travelling
- Tracy's one-off rideshare subscription debit

If you want to run the exact same pipeline on the other training datasets, point `--dataset` to the extracted folder and replace the `.env` credentials with the dataset-specific keys before launching.
