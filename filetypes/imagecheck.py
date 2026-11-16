"""Internal consistency checks for image formats."""

import struct

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"
GIF_TRAILER = b"\x3b"


def check_png(data):
    """Validate PNG structure and read width/height from the IHDR chunk."""
    if not data.startswith(PNG_SIGNATURE):
        return False, "png: missing 8-byte signature"
    if len(data) < 24 or data[12:16] != b"IHDR":
        return False, "png: missing IHDR chunk"
    width, height = struct.unpack(">II", data[16:24])
    if width == 0 or height == 0:
        return False, "png: IHDR width/height must be non-zero"
    return True, "png ihdr: width=%d height=%d" % (width, height)


def check_jpeg(data):
    """A JPEG stream must open with SOI and close with EOI."""
    if not data.startswith(JPEG_SOI):
        return False, "jpeg: missing SOI marker"
    if not data.endswith(JPEG_EOI):
        return False, "jpeg: missing EOI marker (truncated or corrupt)"
    return True, "jpeg: SOI/EOI markers paired"


def check_gif(data):
    """A GIF must carry a GIF87a/89a header and a 0x3B trailer."""
    if not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        return False, "gif: missing GIF87a/GIF89a header"
    if not data.endswith(GIF_TRAILER):
        return False, "gif: missing trailer marker 0x3B"
    return True, "gif: header and trailer markers present"


IMAGE_CHECKS = {"png": check_png, "jpeg": check_jpeg, "gif": check_gif}
