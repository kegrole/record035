"""Fixture builders shared by the demo generator and the test suite.

Everything is synthesised from format specifications (no third-party
files), so the fixtures can be regenerated anywhere and the sniffer's
verdicts must stay identical.
"""

import gzip
import io
import os
import struct
import zipfile
import zlib


def _png_chunk(tag, payload):
    return (
        struct.pack(">I", len(payload))
        + tag
        + payload
        + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
    )


def png_bytes(width=100, height=50):
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IEND", b"")
    )


def jpeg_bytes():
    return (
        b"\xff\xd8"  # SOI
        b"\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00\x43\x00" + bytes(64)
        + b"\xff\xd9"  # EOI
    )


def gif_bytes():
    return (
        b"GIF89a"
        + struct.pack("<HH", 1, 1)
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\xff\xff\xff"
        + b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00"
        + b"\x3b"
    )


def pdf_bytes():
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"trailer\n<<>>\n%%EOF\n"
    )


def zip_bytes(entries=("hello.txt",)):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name in entries:
            zf.writestr(name, "content of %s\n" % name)
    return buf.getvalue()


def gzip_bytes():
    return gzip.compress(b"hello from gzip\n")


def elf_bytes():
    return (
        b"\x7fELF"
        b"\x02\x01\x01\x00"
        + b"\x00" * 8
        + struct.pack("<HHIQQQIHHHHHH",
                      2, 0x3E, 1, 0x400000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    )


def text_bytes():
    return (
        b"The quick brown fox jumps over the lazy dog.\n"
        b"Plain ASCII text, no NUL bytes.\n"
    )


def polyglot_bytes():
    # Valid PNG stream with a ZIP archive appended: opens as both.
    return png_bytes() + zip_bytes()


def mismatched_bytes():
    # JPEG content that will be stored under a .png file name.
    return jpeg_bytes()


BASELINE_FILES = {
    "sample.png": png_bytes,
    "sample.jpg": jpeg_bytes,
    "sample.gif": gif_bytes,
    "sample.pdf": pdf_bytes,
    "sample.zip": zip_bytes,
    "sample.gz": gzip_bytes,
    "sample.elf": elf_bytes,
    "sample.txt": text_bytes,
    "polyglot.png": polyglot_bytes,
    "fake.png": mismatched_bytes,
}


def write_baseline_files(directory):
    os.makedirs(directory, exist_ok=True)
    for name, builder in BASELINE_FILES.items():
        with open(os.path.join(directory, name), "wb") as fh:
            fh.write(builder())
