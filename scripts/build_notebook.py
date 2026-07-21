"""
Generate notebooks/submission.ipynb from src/attack.py (single source of truth).

The notebook:
  1. Writes attack.py to /kaggle/working/ via a %%writefile cell (no string-escaping hazards —
     attack.py contains triple-quoted docstrings, so embedding it as a Python string would break).
  2. Runs the competition inference server. On a normal commit ("Save Version") it runs a fast
     local gateway pinned to the deterministic agent; the scored rerun (KAGGLE_IS_COMPETITION_RERUN
     set) serves the real gpt_oss/gemma evaluation and ignores that pin.

Regenerate after editing src/attack.py:  python scripts/build_notebook.py
"""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
ATTACK_SRC = (REPO / "src" / "attack.py").read_text()
OUT = REPO / "notebooks" / "submission.ipynb"


def code_cell(src: str) -> dict:
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": src.splitlines(keepends=True)}


def md_cell(src: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": src.splitlines(keepends=True)}


INTRO = """# AI Agent Security — Multi-Step Tool Attacks

This notebook writes `attack.py` to `/kaggle/working/` and runs the competition inference server.
The scored rerun loads `attack.py`, runs the `AttackAlgorithm` against gpt_oss and gemma, replays
the returned candidates against the public (OptimalGuardrail) and private guardrails, and scores.

> Harness reconstructed from the competition SDK. If the official starter notebook differs, prefer
> its server-run cell and keep only the `%%writefile attack.py` cell below.
"""

WRITE_CELL = "%%writefile /kaggle/working/attack.py\n" + ATTACK_SRC

RUN_CELL = """import os

# Commit / interactive runs (no rerun flag) execute a LOCAL gateway. Pin it to the fast
# deterministic agent so "Save Version" validates quickly instead of running the full
# 2-model x 9000s evaluation. The scored rerun sets KAGGLE_IS_COMPETITION_RERUN and ignores this.
if not os.getenv("KAGGLE_IS_COMPETITION_RERUN"):
    os.environ.setdefault("AICOMP_MODEL_NAMES", "deterministic")

from kaggle_evaluation.jed_attack_134815.jed_attack_inference_server import (
    JEDAttackInferenceServer,
)

JEDAttackInferenceServer().run()
"""

nb = {
    "cells": [md_cell(INTRO), code_cell(WRITE_CELL), code_cell(RUN_CELL)],
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

OUT.write_text(json.dumps(nb, indent=1))
print(f"Wrote {OUT} ({OUT.stat().st_size} bytes); embedded attack.py = {len(ATTACK_SRC)} chars")
