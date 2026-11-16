"""Archive entry safety checks (stdlib zipfile only)."""

import io
import zipfile


def is_traversal_name(name):
    """True if a zip entry name escapes the extraction directory."""
    normalized = name.replace("\\", "/")
    if normalized.startswith("/"):
        return True
    if len(normalized) >= 2 and normalized[1] == ":":
        return True
    return any(part == ".." for part in normalized.split("/"))


def find_traversal_entries(data):
    """Return the list of offending entry names in a ZIP archive."""
    bad = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in zf.namelist():
            if is_traversal_name(name):
                bad.append(name)
    return bad
