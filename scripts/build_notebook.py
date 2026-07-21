"""
Generate notebooks/submission.ipynb from src/attack.py (single source of truth).

Harness (robust pattern used by top public notebooks):
  Cell 1 — locate kaggle_evaluation under /kaggle/input and add it to sys.path (it's mounted as a
           competition input, not pip-installed).
  Cell 2 — %%writefile /kaggle/working/attack.py with the full src/attack.py.
  Cell 3 — compile + contract sanity check.
  Cell 4 — on the scored rerun (KAGGLE_IS_COMPETITION_RERUN) call the inference server's serve();
           on a normal commit just write a placeholder submission.csv (no slow local gateway).

Regenerate after editing src/attack.py:  python scripts/build_notebook.py  (or: make notebook)
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

Writes `attack.py` to `/kaggle/working/` and, on the scored rerun, serves the competition
inference server. The evaluator loads `AttackAlgorithm`, runs it against gpt_oss + gemma, replays
the returned candidates against the public (OptimalGuardrail) and private guardrails, and scores.
"""

SETUP_CELL = """import glob, os, sys
from pathlib import Path

# kaggle_evaluation is mounted under /kaggle/input for this competition (not pip-installed).
for c in glob.glob('/kaggle/input/**/kaggle_evaluation', recursive=True):
    root = str(Path(c).parent)
    if root not in sys.path:
        sys.path.insert(0, root)
    break

Path('/kaggle/working').mkdir(parents=True, exist_ok=True)
print('setup done | IS_RERUN:', bool(os.getenv('KAGGLE_IS_COMPETITION_RERUN')))
"""

WRITE_CELL = "%%writefile /kaggle/working/attack.py\n" + ATTACK_SRC

CHECK_CELL = """import py_compile
py_compile.compile('/kaggle/working/attack.py', doraise=True)
src = open('/kaggle/working/attack.py').read()
assert 'class AttackAlgorithm(AttackAlgorithmBase)' in src and 'def run(' in src
print('attack.py compiled + contract OK')
"""

RUN_CELL = """import os, csv

if os.getenv('KAGGLE_IS_COMPETITION_RERUN'):
    # Scored rerun: serve the attack to the competition gateway (runs the real gpt_oss/gemma eval).
    import kaggle_evaluation.jed_attack_134815.jed_attack_inference_server as server
    server.JEDAttackInferenceServer().serve()
else:
    # Commit / interactive: write a placeholder so Save Version is instant. The rerun overwrites it.
    with open('/kaggle/working/submission.csv', 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['Id', 'Score'])
        for row in ['gpt_oss_public', 'gpt_oss_private', 'gemma_public', 'gemma_private']:
            w.writerow([row, 0.0])
    print('placeholder submission.csv written')
"""

nb = {
    "cells": [md_cell(INTRO), code_cell(SETUP_CELL), code_cell(WRITE_CELL),
              code_cell(CHECK_CELL), code_cell(RUN_CELL)],
    "metadata": {
        "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
        "language_info": {"name": "python"},
    },
    "nbformat": 4,
    "nbformat_minor": 5,
}

OUT.write_text(json.dumps(nb, indent=1))
print(f"Wrote {OUT} ({OUT.stat().st_size} bytes); embedded attack.py = {len(ATTACK_SRC)} chars")
