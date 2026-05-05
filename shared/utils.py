"""
utils.py — shared helpers for CloudGoat attack playbooks.

Provides:
    - start.txt parser   (load CloudGoat scenario output)
    - step printer       (narrate execution as it runs)
    - findings writer    (persist results to findings.json)
"""

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# start.txt parsing
# ---------------------------------------------------------------------------


def load_start(path: str | Path = "start.txt") -> dict[str, str]:
    """
    Parse a CloudGoat start.txt file into a flat key/value dict.

    CloudGoat writes start.txt in one of two formats depending on scenario:

        cloudgoat_output_aws_account_id = 123456789012
        cloudgoat_output_target_role_arn = arn:aws:iam::...

    or as raw key=value with no prefix:

        aws_access_key_id = AKIA...

    Both formats are handled. Keys are lowercased and stripped of the
    "cloudgoat_output_" prefix so callers get clean names like
    "aws_account_id" or "target_role_arn".

    Args:
        path: Path to start.txt. Defaults to ./start.txt.

    Returns:
        Dict of key -> value strings.

    Raises:
        FileNotFoundError: if path does not exist.
        ValueError: if the file contains no parseable key=value lines.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"start.txt not found at {p.resolve()}")

    result: dict[str, str] = {}
    pattern = re.compile(r"^\s*(?:cloudgoat_output_)?(\w+)\s*=\s*(.+?)\s*$")

    for line in p.read_text().splitlines():
        m = pattern.match(line)
        if m:
            result[m.group(1).lower()] = m.group(2)

    if not result:
        raise ValueError(f"No key=value pairs found in {p}")

    return result


# ---------------------------------------------------------------------------
# Step narration
# ---------------------------------------------------------------------------


def step(msg: str) -> None:
    """Print a timestamped step banner to stdout."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"\n[{ts}] >>> {msg}", flush=True)


def info(msg: str) -> None:
    """Print an indented info line."""
    print(f"    {msg}", flush=True)


def finding(msg: str) -> None:
    """Print a highlighted finding line."""
    print(f"    [FINDING] {msg}", flush=True)


def error(msg: str, fatal: bool = False) -> None:
    """Print an error. If fatal=True, exit with code 1."""
    print(f"    [ERROR] {msg}", file=sys.stderr, flush=True)
    if fatal:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Findings persistence
# ---------------------------------------------------------------------------


def write_findings(
    findings: list[dict],
    scenario: str,
    path: str | Path = "findings.json",
) -> None:
    """
    Write findings list to a JSON file.

    Each finding should be a dict with at minimum:
        {
            "title": str,
            "detail": str,         # what was found
            "resource": str,       # ARN or resource identifier
            "severity": str,       # "critical" | "high" | "medium" | "low"
        }

    Args:
        findings: List of finding dicts.
        scenario: CloudGoat scenario name — included in output metadata.
        path:     Output path. Defaults to ./findings.json.
    """
    output = {
        "scenario": scenario,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": findings,
    }
    Path(path).write_text(json.dumps(output, indent=2, default=str))
    step(f"Wrote {len(findings)} finding(s) to {path}")
