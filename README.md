# Reply AI Challenge Workspace

This repository is a workspace for multiple solutions to the Reply Mirror fraud-detection challenge. It is not a single package with one pipeline. Instead, it contains:

- a root solver for the `The+Truman+Show+-+train` dataset
- several standalone scenario folders with their own code, dependencies, and outputs
- the supplied challenge PDFs, submission-tracking starter files, original dataset archives, and generated artifacts

## What Is In The Repo

| Path | Purpose |
| --- | --- |
| `main.py` | Root CLI entrypoint for the `The Truman Show` solver. |
| `reply_mirror_solver/` | Root heuristic pipeline and optional LLM review logic. |
| `outputs/` | Root output folder with the generated `The Truman Show` submission and analysis report. |
| `The+Truman+Show+-+train/` | Extracted dataset used by the root solver. |
| `1984/` | Standalone solution for the `1984` dataset, including its own database, requirements, and artifacts. |
| `Blade-Runner/` | Standalone Blade Runner solution with its own agent package and SQLite artifacts. |
| `Brave-New_World/` | Standalone Brave New World workspace with multiple submission variants and tracing helpers. |
| `Deus-Ex/` | Standalone Deus Ex multi-agent pipeline and outputs. |
| `track-your-submission/` | Extracted helper project from the challenge materials. |
| `AIAgentChallenge-ProblemStatement16April.pdf` | Main challenge statement. |
| `04-resource_management.pdf` | Resource-management and tracing guidance from the challenge. |
| `*.zip` files in the repo root | Original dataset or helper archives kept alongside the extracted folders. |

## Root Solver

The root-level code is the simplest entrypoint in this workspace. It targets the extracted dataset at:

`The+Truman+Show+-+train\The Truman Show - train`

Main files:

- `main.py`: parses CLI arguments and writes the final output files
- `reply_mirror_solver/pipeline.py`: dataset parsing, communication analysis, transaction scoring, and output generation
- `reply_mirror_solver/llm.py`: optional OpenRouter plus Langfuse review pass
- `requirements.txt`: dependencies for the root solver

The root pipeline produces two files in `outputs/`:

- `The_Truman_Show_-_train_submission.txt`
- `The_Truman_Show_-_train_analysis.json`

## Run The Root Solver

Install the root dependencies:

```powershell
py -3 -m pip install -r requirements.txt
```

Run in heuristic-only mode:

```powershell
py -3 main.py --llm-mode off
```

Run with optional LLM review when credentials are available:

```powershell
py -3 main.py --llm-mode auto
```

Useful flags:

- `--dataset`: override the dataset directory
- `--output-dir`: choose a different output folder
- `--llm-mode off|auto|force`: disable review, enable it when possible, or require it

## Optional Environment Variables

The root solver reads a local `.env` file if one exists. Heuristic mode does not require any credentials.

For LLM review, the code expects:

- `OPENROUTER_API_KEY`
- `LANGFUSE_PUBLIC_KEY`
- `LANGFUSE_SECRET_KEY`
- `TEAM_NAME`

Optional variables:

- `LANGFUSE_HOST` (defaults to the Reply challenge host in code)
- `OPENROUTER_MODEL` (defaults to `openai/gpt-4o-mini`)

If the required variables or optional packages are missing, `--llm-mode auto` skips the LLM pass and continues with the heuristic pipeline.

## Standalone Scenario Folders

The other top-level folders are separate experiments or submission workspaces rather than modules used by the root `main.py`.

- `1984/`: contains `main.py`, a `reply_mirror_agent/` package, `1984.db`, and outputs under `artifacts/`
- `Blade-Runner/`: contains `run_agent.py`, the `blade_runner_agent/` package, extracted training data, and outputs under `artifacts/`
- `Brave-New_World/`: contains its own `main.py`, `mirror_solver/`, a tracing helper, and multiple saved submission/report variants
- `Deus-Ex/`: contains `run_submission.py`, the `deus_ex_agents/` package, extracted data under `dataset/`, and outputs under `outputs/`

Each of those folders also has its own `README.md` and `requirements.txt`.

## Notes

- This repo intentionally includes extracted datasets, audio files, reports, submission text files, and helper archives, so it is much larger than a normal source-only repository.
- The root `requirements.txt` only covers the root solver. Install dependencies from a scenario folder if you are working inside that folder instead.
- Several folders include generated files such as `__pycache__/`, local databases, and prior submission artifacts because this workspace appears to be used for active experimentation, not only for source storage.
