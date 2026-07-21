"""Shared pytest setup: put the unpacked SDK and our src/ on the import path."""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
for p in (REPO / "sdk", REPO / "src", REPO / "tests"):
    sp = str(p)
    if sp not in sys.path:
        sys.path.insert(0, sp)
