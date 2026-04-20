# Reply AI Challenge Workspace

This repository is an active workspace for the Reply Mirror fraud-detection challenge. It contains several independent solver implementations, multiple training datasets, generated submission artifacts, tracking helper projects, local SQLite databases, and archived solution bundles.

The root project is only one solver. The folders `1984/`, `Blade-Runner/`, `Brave-New_World/`, and `Deus-Ex/` are separate workspaces with their own source code, requirements, run commands, datasets, and outputs.

## Dataset Inventory

The challenge datasets all use the same core files:

- `transactions.csv`
- `users.json`
- `sms.json`
- `mails.json`
- `locations.json`
- optional `audio/*.mp3`

Current datasets in this repository:

| Dataset | Where it lives | Transactions | Users | SMS | Mails | Locations | MP3 audio | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| The Truman Show | `The+Truman+Show+-+train/The Truman Show - train` | 80 | 3 | 162 | 8 | 829 | 0 | Default dataset for the root `main.py`. |
| Brave New World | `Brave+New+World+-+train.zip` | 522 | 7 | 378 | 21 | 1917 | 0 | Stored as a zip at the repo root; `Brave-New_World/main.py` can read zip or extracted folders. |
| Deus Ex | `Deus-Ex/dataset/Deus Ex - train` | 2017 | 12 | 648 | 39 | 3263 | 48 | Also present as `Deus+Ex+-+train.zip` at the repo root and inside `Deus-Ex/`. |
| Blade Runner | `Blade-Runner/Blade Runner - train` | 7387 | 20 | 1080 | 73 | 5482 | 80 | Also present as `Blade-Runner/Blade+Runner+-+train.zip`. |
| 1984 | `1984/train/1984 - train` | 14574 | 40 | 2160 | 140 | 10971 | 160 | Also present as `1984/1984+-+train.zip`. |

## Source Code Inventory

### Root Truman Show Solver

The root solver is a small standalone pipeline for `The Truman Show`.

- `main.py`: CLI entrypoint.
- `reply_mirror_solver/pipeline.py`: parses CSV/JSON files, maps communications to users, scores transaction anomalies, chooses suspected fraud IDs, and writes output files.
- `reply_mirror_solver/llm.py`: optional OpenRouter plus Langfuse arbitration for top candidates.
- `requirements.txt`: root solver dependencies.
- `outputs/`: generated Truman Show submission and analysis JSON.

### `1984/`

Standalone multi-agent solver for the `1984` dataset.

- `1984/main.py`: CLI entrypoint.
- `1984/reply_mirror_agent/database.py`: dataset ingestion, normalization, email parsing, URL/domain extraction, geo helpers, audio metadata, and SQLite-backed data access.
- `1984/reply_mirror_agent/agents.py`: `CommunicationRiskAgent`, `BehavioralBaselineAgent`, `GeoTemporalAgent`, `CounterpartyGraphAgent`, optional `LLMAdjudicatorAgent`, and `FraudOrchestrator`.
- `1984/reply_mirror_agent/config.py`: settings, `.env` loading, session ID generation, and output path helpers.
- `1984/1984.db`: generated SQLite knowledge base.
- `1984/artifacts/`: generated submission, report, and Langfuse session ID.
- `1984/_vendor/`: vendored `packaging` dependency copy.

### `Blade-Runner/`

Standalone multi-agent solver for the Blade Runner dataset.

- `Blade-Runner/run_agent.py`: CLI entrypoint.
- `Blade-Runner/blade_runner_agent/database.py`: SQLite database builder for transactions, users, messages, locations, and derived analysis tables.
- `Blade-Runner/blade_runner_agent/engine.py`: communication, mobility, behavioral, social-engineering, and optional LLM review agents.
- `Blade-Runner/blade_runner_agent/config.py`: environment loading, runtime config, and session ID generation.
- `Blade-Runner/artifacts/`: generated SQLite database, suspected fraud submission, and review summary.

### `Brave-New_World/`

Standalone generic zip-or-folder solver used for Brave New World style datasets. This folder also contains saved output variants with `bladerunner` in the filename, so treat the filename labels as historical run names rather than the folder's only purpose.

- `Brave-New_World/main.py`: CLI entrypoint that requires `--dataset`, `--output`, and optional `--report`.
- `Brave-New_World/mirror_solver/dataset.py`: loads challenge data from either a zip archive or an extracted dataset directory.
- `Brave-New_World/mirror_solver/models.py`: data models for users, locations, transactions, messages, evidence, candidates, and identity resolution.
- `Brave-New_World/mirror_solver/mapping.py`: identity matching between users and account IDs.
- `Brave-New_World/mirror_solver/agents.py`: identity linking, behavioral profiling, communication risk, geo-temporal checks, counterparty novelty, and orchestration agents.
- `Brave-New_World/mirror_solver/pipeline.py`: end-to-end candidate scoring, selection, report building, and output writing.
- `Brave-New_World/mirror_solver/tracing.py`: optional OpenRouter/Langfuse judge and session warm-up helpers.
- `Brave-New_World/trace_session.py`: creates a traced Langfuse session.
- `Brave-New_World/run_bladerunner_best.ps1`: convenience script for a BladeRunner-named run; pass `-Dataset` explicitly if the default zip is not in that folder.
- `Brave-New_World/.python_packages/`: local package copy.

### `Deus-Ex/`

Standalone multi-agent solver for the Deus Ex dataset.

- `Deus-Ex/run_submission.py`: CLI entrypoint.
- `Deus-Ex/deus_ex_agents/io.py`: dataset loading, ASCII folding, user matching, communication parsing, audio event parsing, and target profile creation.
- `Deus-Ex/deus_ex_agents/domain.py`: domain models for profiles, transactions, communication events, audio events, targets, assessments, and dataset context.
- `Deus-Ex/deus_ex_agents/agents.py`: user vulnerability, communication risk, counterparty risk, behavioral anomaly, travel pattern, and audio context agents.
- `Deus-Ex/deus_ex_agents/pipeline.py`: orchestrates scoring, optional LLM review, report writing, and submission writing.
- `Deus-Ex/deus_ex_agents/tracing.py`: optional OpenRouter/Langfuse reviewer.
- `Deus-Ex/outputs/`: generated Deus Ex submission and report.
- `Deus-Ex/submission_deus_ex.txt` and `Deus-Ex/deus_ex_report.json`: additional generated outputs kept at the folder root.

## How To Run

Install dependencies from the workspace you are running. The root `requirements.txt` does not cover every scenario-specific folder.

Run the root Truman Show solver from the repository root:

```powershell
py -3 -m pip install -r requirements.txt
py -3 main.py --llm-mode off
```

Run the `1984` solver:

```powershell
Set-Location 1984
py -3 -m pip install -r requirements.txt
py -3 main.py --use-llm off
```

Run the Blade Runner solver:

```powershell
Set-Location Blade-Runner
py -3 -m pip install -r requirements.txt
py -3 run_agent.py --disable-llm
```

Run the Brave New World zip solver:

```powershell
Set-Location Brave-New_World
py -3 -m pip install -r requirements.txt
py -3 main.py --dataset "..\Brave+New+World+-+train.zip" --output "submission_brave_new_world.txt" --report "report_brave_new_world.json"
```

Run the Deus Ex solver:

```powershell
Set-Location Deus-Ex
py -3 -m pip install -r requirements.txt
py -3 run_submission.py
```

## Optional LLM And Tracing

Most solvers can run in offline heuristic mode. Optional LLM review uses OpenRouter and Langfuse.

Environment variables used across the solvers:

- `OPENROUTER_API_KEY`
- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `LANGFUSE_HOST`
- `TEAM_NAME`
- `OPENROUTER_MODEL` in the root solver
- `ENABLE_LLM_REVIEW` in the Deus Ex solver

LLM-related flags:

- Root: `--llm-mode off|auto|force`
- `1984/`: `--use-llm off|auto|on`
- `Blade-Runner/`: LLM is enabled by default; use `--disable-llm` for local-only runs.
- `Brave-New_World/`: use `--use-llm-judge`, optionally with `--session-id`.
- `Deus-Ex/`: use `--enable-llm-review`.

Several `.env` files are present in this workspace, including in scenario folders and copied tracking helpers. Treat them as local secrets and do not paste their values into issues, logs, or documentation.

## Generated Outputs And Artifacts

Current generated outputs include:

| Location | Contents |
| --- | --- |
| `outputs/` | Truman Show submission and analysis report. |
| `1984/artifacts/` | `submission.txt`, `report.json`, and `session_id.txt`. |
| `1984/1984.db` | SQLite database generated from the 1984 dataset. |
| `Blade-Runner/artifacts/` | `suspected_fraud.txt`, `review_summary.json`, and `blade_runner.sqlite`. |
| `Brave-New_World/` | `submission_bladerunner_*` text files and `report_bladerunner_*` JSON files from prior runs. |
| `Deus-Ex/outputs/` | `deus_ex_train_submission.txt` and `deus_ex_train_report.json`. |
| `Deus-Ex/` | Additional `submission_deus_ex.txt` and `deus_ex_report.json` files. |

Submission files are plain ASCII text with one suspected fraudulent `transaction_id` per line.

## Challenge Materials And Helper Projects

Challenge/reference material:

- `AIAgentChallenge-ProblemStatement16April.pdf`
- `04-resource_management.pdf`
- extracted `.txt` copies of those PDFs inside some scenario folders

Submission tracking helper:

- `track-your-submission.zip`
- `track-your-submission/how-to-track-your-submission/`
- copied helper folders under `1984/`, `Blade-Runner/`, `Brave-New_World/`, and `Deus-Ex/`

The helper projects demonstrate Langfuse session ID generation and traced LangChain calls. They are reference utilities, not the main fraud-detection code.

## Archives In The Repo

Dataset archives:

- `The+Truman+Show+-+train.zip`
- `Brave+New+World+-+train.zip`
- `Deus+Ex+-+train.zip`
- `1984/1984+-+train.zip`
- `Blade-Runner/Blade+Runner+-+train.zip`
- `Deus-Ex/Deus+Ex+-+train.zip`

Archived solution bundles:

- `fraudAgenttt.zip`
- `fraudAgent4.zip`
- `fraudAgent5.zip`

Those `fraudAgent*.zip` files are preserved packaged bundles from prior solver/export attempts. They are not imported by the live root solver.

## Generated Or Non-Source Folders

The repository currently includes files that are useful for local experimentation but are not hand-written solver source:

- `__pycache__/` folders
- `__MACOSX/` folders from macOS zip archives
- `1984/_vendor/`
- `Brave-New_World/.python_packages/`
- SQLite databases under scenario folders
- generated JSON reports and text submissions

This explains why the repo is larger and noisier than a clean source-only project.

## Practical Notes

- Start from the folder for the dataset you want to work on; do not assume the root `main.py` controls every scenario.
- Use offline flags first if you only want reproducible local behavior.
- Use LLM flags only after the matching `.env` values and dependencies are available.
- Pass dataset paths explicitly for `Brave-New_World/` because its solver supports both zip archives and extracted folders.
