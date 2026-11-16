"""Report record construction and JSON serialisation."""

import json
import os

FIELDS = ("file", "detected", "declared", "verdict", "evidence")


def make_record(path, detected, declared, verdict, evidence):
    return {
        "file": path,
        "detected": list(detected),
        "declared": declared,
        "verdict": verdict,
        "evidence": list(evidence),
    }


def write_report(records, out_path):
    directory = os.path.dirname(out_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def summarize(records):
    allowed = sum(1 for record in records if record["verdict"] == "allow")
    return len(records), allowed, len(records) - allowed
