#!/usr/bin/env python3
"""Verify the latest trusted workflow runs for one exact candidate source SHA."""
import argparse
import datetime
import json
import re
import subprocess
from pathlib import Path

WORKFLOWS = ("rust-core.yml", "web-build.yml", "android.yml", "secret-scan.yml", "codeql.yml")
REPOSITORY = "ZHanry/NestLink"


def select_runs(source, workflows):
    selected = []
    for workflow in WORKFLOWS:
        runs = [run for run in workflows.get(workflow, [])
                if run.get("head_sha") == source and run.get("event") in ("push", "pull_request", "workflow_dispatch", "merge_group")
                and run.get("path", "").split("@", 1)[0] == ".github/workflows/" + workflow]
        if not runs:
            raise ValueError("Required workflow missing at exact SHA: " + workflow)
        run = max(runs, key=lambda item: (item["run_number"], item["run_attempt"]))
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise ValueError("Latest required workflow is not successful: " + workflow + " / " + str(run.get("conclusion") or run.get("status")))
        selected.append({key: run[key] for key in ("id", "run_attempt", "head_sha", "path", "html_url", "status", "conclusion")})
    return selected


def api(path):
    return json.loads(subprocess.check_output(["gh", "api", "--method", "GET", path], timeout=60))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source):
        raise ValueError("Full lowercase source SHA required")
    if api("repos/" + REPOSITORY)["node_id"] != "R_kgDOVNHMvg":
        raise ValueError("Unexpected repository identity")
    workflows = {}
    for workflow in WORKFLOWS:
        workflows[workflow] = api(f"repos/{REPOSITORY}/actions/workflows/{workflow}/runs?head_sha={args.source}&per_page=100")["workflow_runs"]
    evidence = {"schema_version": 1, "repository": REPOSITORY, "source_revision": args.source,
                "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "required_runs": select_runs(args.source, workflows), "quality_state": "required-checks-passed"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
