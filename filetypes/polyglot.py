"""Multi-format (polyglot) detection."""


def is_polyglot(detected):
    """More than one signature hit means the file is a polyglot."""
    return len(detected) > 1


def polyglot_evidence(detected):
    return "polyglot: multiple formats detected (%s)" % ", ".join(detected)
