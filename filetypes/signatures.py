"""Magic-byte signature table used to identify real file types.

Each entry maps a type name to a list of rules. A rule is a list of
(offset, magic) pairs that must *all* match; a type matches when any
of its rules matches.
"""

ZIP_LOCAL_HEADER = b"PK\x03\x04"
ZIP_EOCD = b"PK\x05\x06"

SIGNATURES = {
    "png": [[(0, b"\x89PNG\r\n\x1a\n")]],
    "jpeg": [[(0, b"\xff\xd8\xff")]],
    "gif": [[(0, b"GIF87a")], [(0, b"GIF89a")]],
    "pdf": [[(0, b"%PDF-")]],
    "zip": [[(0, ZIP_LOCAL_HEADER)], [(0, ZIP_EOCD)]],
    "gzip": [[(0, b"\x1f\x8b")]],
    "elf": [[(0, b"\x7fELF")]],
    "pe": [[(0, b"MZ")]],
    "class": [[(0, b"\xca\xfe\xba\xbe")]],
    "wav": [[(0, b"RIFF"), (8, b"WAVE")]],
}

# A ZIP archive is located by readers via its end-of-central-directory
# record, so ZIP data appended after another format still opens in unzip
# tools. Scan the whole buffer for ZIP markers to catch such polyglots.
SCAN_WHOLE_BUFFER = {
    "zip": (ZIP_LOCAL_HEADER, ZIP_EOCD),
}
