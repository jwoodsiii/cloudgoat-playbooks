# AGENTS.md

## Purpose

This repo contains attack playbooks for CloudGoat scenarios. Each scenario
reproduces an exploitation path against intentionally misconfigured AWS
infrastructure. The goal is to understand the attack deeply enough to write
detection rules and OPA policies against it.

## Repo structure

```
shared/
  auth.py / auth.go     — session factory, STS assume-role. Import this, don't rewrite it.
  utils.py / utils.go   — step narration, start.txt parsing, findings output.
scenarios/
  <scenario-name>/
    README.md            — written after the attack is tested, not before.
    attack.py            — Python rapid-iteration script
    attack.go            — Go final artifact (may not exist yet)
    start.txt            — CloudGoat output, gitignored
    findings.json        — generated output, gitignored
```

## Language conventions

- **Python** — rapid iteration, exploration. Use for first-pass attack scripts.
- **Go** — final artifacts. Rewrite interesting paths in Go after the Python
  version is tested and understood.
- Never mix languages within a single attack script.
- Python scripts use `shared/auth.py` and `shared/utils.py`.
- Go scripts import the `shared` package (`shared/auth.go`, `shared/utils.go`).

## Script conventions

- Accept `--region` flag (default `us-east-1`). Never hardcode region.
- Accept `--start-file` flag pointing at the CloudGoat start.txt (default `./start.txt`).
- Accept `--role-arn` flag for explicit assume-role. If absent, use ambient creds.
- Print each step to stdout as it executes using `step()`/`Step()` so the
  operator can follow along in real time.
- Write `findings.json` on completion via `write_findings()`/`WriteFindings()`.
- Never destroy or modify resources — enumerate and read-path exploitation only.
- Never print raw AWS credentials to stdout.

## What agents should not do

- Modify `shared/` without explicit instruction.
- Add Python dependencies beyond `boto3` and standard library.
- Add Go dependencies beyond `aws-sdk-go-v2` and standard library.
- Write a scenario README before the attack script is tested end-to-end.
- Hardcode account IDs, ARNs, or region strings in scripts.
- Write destructive API calls (`DeleteRole`, `TerminateInstances`, etc.).

## Skills

`/obsidian-to-playbook` — use this whenever we develop python attack automation scripts from Obsidian attack playbooks containing aws cli commands used to complete a scenario. The obsidian note will provide the attack narrative + commands + flags, and this skill will accept the Obsidian note's location and the scenario name to parse the note and generate the python script.

Reference files the skill reads:
- `skills/obsidian-to-playbook/references/cli-to-boto3.md` — mapping cli commands to boto3, build on this file as new cli commands are converted to the script.

`/playbook-py-to-go` - converts a tested Python playbook into idiomatic Go after the Python version is committed and tested. Reads scenario README as primary source, attack.py as an API reference. Do not execute unless findings.json exists to prove attack.py was tested.

Reference files the skill reads:
- `skills/playbook-py-to-go/references/sdk-v2-patterns.md` - leverage for guidance on paginators, pointer handling, json parsing patterns


## Adding a new scenario

1. Create `scenarios/<scenario-name>/` directory.
2. Write `attack.py` first — get it working end-to-end against a live CloudGoat deploy.
3. Capture `findings.json` output.
4. Write `README.md` — attack narrative, what misconfiguration makes it possible,
   what detection would have caught it.
5. Rewrite as `attack.go` if the scenario is a Go target (see tracker).

## Writing Go artifacts
We will only develop Go artifacts after the Python attack scripts have been committed and tested. 

## The design doc rule

Before writing any attack script, write two paragraphs in the scenario README:
- What misconfiguration you're exploiting and why it exists
- What the attack path is step by step

## Off-limits paths
Never read from, write to, or create files under:
- ~/Library/Mobile Documents/
- ~/Documents/Obsidian/
- Any path containing "Obsidian" or "iCloud"

Note content is provided as a read-once input argument only.
