"""
Local smoke test for src/attack.py against the competition SDK.

Runs OUTSIDE Kaggle. It needs the real `aicomp_sdk-3.1.0` wheel installed (see scripts/fetch_sdk.sh).
If the SDK isn't installed yet, it degrades to import-only checks so CI/dev still gives fast feedback.

Usage:
    python tests/smoke_test.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import attack  # noqa: E402


def check_import() -> None:
    assert hasattr(attack, "AttackAlgorithm"), "AttackAlgorithm class missing"
    algo = attack.AttackAlgorithm()
    assert hasattr(algo, "run"), "AttackAlgorithm.run missing"
    print("[ok] attack.py imports and AttackAlgorithm.run exists")


def check_against_sdk() -> bool:
    """Return True if we actually exercised the SDK env, False if it wasn't available."""
    try:
        # CONFIRM: the exact factory for a local environment in aicomp_sdk 3.1.0.
        # Common shapes: aicomp_sdk.make_env(...) or aicomp_sdk.Environment(...).
        import aicomp_sdk  # type: ignore
    except Exception as e:
        print(f"[skip] aicomp_sdk not installed ({e}); run scripts/fetch_sdk.sh first")
        return False

    make_env = getattr(aicomp_sdk, "make_env", None) or getattr(aicomp_sdk, "Environment", None)
    if make_env is None:
        print("[warn] aicomp_sdk present but no make_env/Environment found — CONFIRM the factory name")
        return False

    env = make_env(seed=123)  # CONFIRM kwargs
    algo = attack.AttackAlgorithm()
    candidates = algo.run(env)
    print(f"[ok] ran attack against SDK env — {len(candidates)} candidate(s)")
    assert len(candidates) <= attack.MAX_CANDIDATES
    for c in candidates[:3]:
        msgs = getattr(c, "messages", None)
        assert msgs is not None, "candidate missing .messages"
        assert len(msgs) <= attack.MAX_MESSAGES_PER_CANDIDATE
        print(f"     - {getattr(c, 'label', '?')}: {len(msgs)} msg(s), "
              f"predicates={getattr(c, 'meta', {}).get('predicates')}")
    return True


if __name__ == "__main__":
    check_import()
    exercised = check_against_sdk()
    print("\nSMOKE TEST:", "FULL (SDK exercised)" if exercised else "IMPORT-ONLY (install SDK for full run)")
