"""Content-based type sniffing: magic bytes plus text/binary heuristic."""

from .signatures import SCAN_WHOLE_BUFFER, SIGNATURES


def _rule_matches(data, rule):
    return all(
        data[offset:offset + len(magic)] == magic for offset, magic in rule
    )


def matches_at_offset_zero(data, type_name):
    return any(_rule_matches(data, rule) for rule in SIGNATURES[type_name])


def detect_types(data):
    """Return every signature type that matches *data*.

    When no magic bytes match, fall back to a content heuristic: any NUL
    byte means binary, otherwise the content is treated as text.
    """
    matched = []
    for name in SIGNATURES:
        if matches_at_offset_zero(data, name):
            matched.append(name)
            continue
        markers = SCAN_WHOLE_BUFFER.get(name)
        if markers and any(marker in data for marker in markers):
            matched.append(name)
    if not matched:
        matched.append("binary" if b"\x00" in data else "text")
    return matched
