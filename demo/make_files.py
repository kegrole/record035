#!/usr/bin/env python3
"""Regenerate the 10 baseline sample files under demo/files/."""

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from tests.fixtures import BASELINE_FILES, write_baseline_files

if __name__ == "__main__":
    target = os.path.join(REPO_ROOT, "demo", "files")
    write_baseline_files(target)
    print("wrote %d files to %s" % (len(BASELINE_FILES), target))
