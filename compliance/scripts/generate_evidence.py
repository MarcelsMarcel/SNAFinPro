#!/usr/bin/env python3
"""
generate_evidence.py
Generates a structured, SHA-256 signed compliance evidence artifact
for a single SOC 2 / ISO 27001 control evaluation.

Usage:
  python3 generate_evidence.py \
    --control CC7.1 --iso A.8.8 --framework SOC2 \
    --status passed --actor marcelsmarcel \
    --commit abc123 --run-id 999 \
    --tool semgrep --findings 0 \
    --output evidence_cc71.json
"""

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone


def sha256_of(data: dict) -> str:
    """Return SHA-256 hex digest of a JSON-serialized dict."""
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def build_evidence(args) -> dict:
    core = {
        "control_id":   args.control,
        "iso_mapping":  args.iso,
        "framework":    args.framework,
        "status":       args.status,
        "pipeline": {
            "actor":    args.actor,
            "commit":   args.commit,
            "run_id":   args.run_id,
            "ref":      os.environ.get("GITHUB_REF", "unknown"),
            "repo":     os.environ.get("GITHUB_REPOSITORY", "unknown"),
            "workflow": os.environ.get("GITHUB_WORKFLOW", "ComplianceAsCode Pipeline"),
        },
        "scan": {
            "tool":     args.tool,
            "findings": int(args.findings),
        },
        "collected_at": datetime.now(timezone.utc).isoformat(),
    }

    # Attach SHA-256 of the core payload (tamper-evident)
    core["sha256"] = sha256_of(core)
    return core


def main():
    parser = argparse.ArgumentParser(description="Generate compliance evidence artifact")
    parser.add_argument("--control",   required=True,  help="SOC 2 control ID e.g. CC7.1")
    parser.add_argument("--iso",       required=True,  help="ISO 27001 control e.g. A.8.8")
    parser.add_argument("--framework", required=True,  help="Framework e.g. SOC2")
    parser.add_argument("--status",    required=True,  help="passed or violated")
    parser.add_argument("--actor",     required=True,  help="GitHub actor")
    parser.add_argument("--commit",    required=True,  help="Commit SHA")
    parser.add_argument("--run-id",    required=True,  help="GitHub run ID")
    parser.add_argument("--tool",      required=True,  help="Scanning tool used")
    parser.add_argument("--findings",  required=True,  help="Number of findings")
    parser.add_argument("--output",    required=True,  help="Output JSON filename")
    args = parser.parse_args()

    evidence = build_evidence(args)

    with open(args.output, "w") as f:
        json.dump(evidence, f, indent=2)

    # Print to pipeline logs
    icon = "✅" if args.status == "passed" else "❌"
    print(f"\n{icon} Evidence artifact generated: {args.output}")
    print(f"   Control  : {args.control} ({args.iso})")
    print(f"   Status   : {args.status}")
    print(f"   Actor    : {args.actor}")
    print(f"   Commit   : {args.commit[:12]}...")
    print(f"   Findings : {args.findings}")
    print(f"   SHA-256  : {evidence['sha256'][:32]}...")
    print()


if __name__ == "__main__":
    main()
