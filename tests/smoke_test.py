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


def _get_env_factory():
    """Prefer the real SDK env; fall back to the local mock for offline development.

    Returns (factory, source_label).
    """
    try:
        import aicomp_sdk  # type: ignore
        # CONFIRM: exact factory name in aicomp_sdk 3.1.0 (make_env / Environment / ...).
        factory = getattr(aicomp_sdk, "make_env", None) or getattr(aicomp_sdk, "Environment", None)
        if factory is not None:
            return factory, "aicomp_sdk (REAL)"
        print("[warn] aicomp_sdk present but no make_env/Environment — CONFIRM the factory name")
    except Exception as e:
        print(f"[info] aicomp_sdk not installed ({e}); using local mock env")

    from mock_env import make_env  # local dev stand-in
    return make_env, "mock_env (DEV)"


def check_end_to_end() -> str:
    """Run the attack loop against whichever env is available; return the source label."""
    factory, source = _get_env_factory()
    env = factory(seed=123)
    algo = attack.AttackAlgorithm()
    candidates = algo.run(env)
    assert len(candidates) <= attack.MAX_CANDIDATES
    print(f"[ok] ran attack against {source} — {len(candidates)} candidate(s)")
    for c in candidates:
        msgs = getattr(c, "messages", None)
        assert msgs is not None, "candidate missing .messages"
        assert len(msgs) <= attack.MAX_MESSAGES_PER_CANDIDATE
        print(f"     - {getattr(c, 'label', '?'):24s} "
              f"predicates={getattr(c, 'meta', {}).get('predicates')} "
              f"cell={getattr(c, 'meta', {}).get('cell')}")

    # Score them with our local scorer so we get an offline signal.
    sys.path.insert(0, str(REPO / "src"))
    import scoring  # noqa: E402
    result = scoring.score(scoring.findings_from_candidates(candidates))
    print(f"[ok] local score: raw={result['raw_score']} "
          f"normalized={result['normalized_score']:.3f} "
          f"unique_cells={result['unique_cell_count']}")
    return source


if __name__ == "__main__":
    check_import()
    source = check_end_to_end()
    full = source.endswith("(REAL)")
    print("\nSMOKE TEST:", "FULL (SDK exercised)" if full else "DEV (mock env — install SDK for real run)")
