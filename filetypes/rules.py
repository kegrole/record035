"""Verdict rules: whitelist, extension consistency, internal checks."""

import os

from . import archive, imagecheck, polyglot, sniffer

WHITELIST = {"png", "jpeg", "gif", "pdf", "zip", "gzip", "elf", "text"}

EXT_TO_TYPE = {
    ".png": "png",
    ".jpg": "jpeg",
    ".jpeg": "jpeg",
    ".gif": "gif",
    ".pdf": "pdf",
    ".zip": "zip",
    ".gz": "gzip",
    ".elf": "elf",
    ".txt": "text",
    ".exe": "pe",
    ".class": "class",
    ".wav": "wav",
}

ALLOW = "allow"
REJECT = "reject"


def declared_type(filename):
    ext = os.path.splitext(filename)[1].lower()
    return EXT_TO_TYPE.get(ext, "unknown")


def analyze_bytes(data, filename):
    """Return (detected, declared, verdict, evidence) for raw bytes."""
    detected = sniffer.detect_types(data)
    declared = declared_type(filename)
    evidence = []

    if polyglot.is_polyglot(detected):
        evidence.append(polyglot.polyglot_evidence(detected))
        evidence.append("polyglot files are always rejected")
        return detected, declared, REJECT, evidence

    actual = detected[0]
    verdict = ALLOW

    if declared != actual:
        evidence.append(
            "type mismatch: declared=%s (extension) but actual=%s (magic bytes)"
            % (declared, actual)
        )
        verdict = REJECT

    if actual not in WHITELIST:
        evidence.append("type %r is not in the whitelist" % actual)
        verdict = REJECT

    check = imagecheck.IMAGE_CHECKS.get(actual)
    if check is not None:
        ok, message = check(data)
        evidence.append(message)
        if not ok:
            verdict = REJECT

    if actual == "zip":
        bad = archive.find_traversal_entries(data)
        for name in bad:
            evidence.append("zip entry traversal: %r" % name)
        if bad:
            verdict = REJECT
        else:
            evidence.append("zip: no path-traversal entries")

    return detected, declared, verdict, evidence


def analyze_file(path):
    with open(path, "rb") as fh:
        data = fh.read()
    return analyze_bytes(data, os.path.basename(path))
