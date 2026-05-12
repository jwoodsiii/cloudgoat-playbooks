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

## Adding a new scenario

1. Create `scenarios/<scenario-name>/` directory.
2. Write `attack.py` first — get it working end-to-end against a live CloudGoat deploy.
3. Capture `findings.json` output.
4. Write `README.md` — attack narrative, what misconfiguration makes it possible,
   what detection would have caught it.
5. Rewrite as `attack.go` if the scenario is a Go target (see tracker).

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
