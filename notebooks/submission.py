"""
Kaggle notebook body for the "AI Agent Security: Multi-Step Tool Attacks" submission.

Paste this into a Kaggle Notebook (or use `jupytext`/`nbconvert` to convert it). When run, it
writes `attack.py` into /kaggle/working/ where the hosted evaluator picks it up.

Requirements for the "Submit" button to activate:
  - GPU notebook, <= 15 h runtime
  - Internet access DISABLED
  - Any external data / pretrained models must be attached as Kaggle datasets (offline)

Keep this file in sync with src/attack.py — it embeds the same source. The `_ATTACK_SRC` string
below is the single source of truth that gets written to disk at eval time.
"""
import os
from pathlib import Path

# --- Where the evaluator expects the file ---------------------------------------------
WORKING = Path(os.environ.get("KAGGLE_WORKING", "/kaggle/working"))
WORKING.mkdir(parents=True, exist_ok=True)

# --- The attack source ----------------------------------------------------------------
# During development we read it from the repo; on Kaggle, replace this block by pasting the
# contents of src/attack.py directly into `_ATTACK_SRC = r'''...'''`.
try:
    _ATTACK_SRC = Path(__file__).resolve().parent.parent.joinpath("src", "attack.py").read_text()
except Exception:
    _ATTACK_SRC = r'''# <<< PASTE THE CONTENTS OF src/attack.py HERE FOR THE KAGGLE NOTEBOOK >>>'''

(WORKING / "attack.py").write_text(_ATTACK_SRC)
print(f"Wrote {WORKING / 'attack.py'} ({len(_ATTACK_SRC)} bytes)")

# --- Optional: local sanity check before committing -----------------------------------
# The evaluator runs the real gateway; this just confirms attack.py imports cleanly.
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location("attack", WORKING / "attack.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore
    assert hasattr(mod, "AttackAlgorithm"), "AttackAlgorithm class not found"
    print("attack.py imports OK and defines AttackAlgorithm")
except Exception as e:
    print(f"WARNING: attack.py failed local import check: {e}")
