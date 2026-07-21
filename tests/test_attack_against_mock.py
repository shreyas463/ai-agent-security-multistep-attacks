"""End-to-end test: run AttackAlgorithm against the mock env and assert it finds attacks.

This validates the attack *loop* (replay -> detect -> dedupe by cell -> build candidate) without
the real SDK. When the real wheel lands, the same test can point at aicomp_sdk instead.
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests"))

import attack        # noqa: E402
import scoring       # noqa: E402
from mock_env import make_env  # noqa: E402


def _run():
    env = make_env(seed=123)
    algo = attack.AttackAlgorithm()
    return algo.run(env)


def test_finds_candidates():
    candidates = _run()
    assert len(candidates) > 0, "attack found nothing against the (vulnerable) mock agent"
    assert len(candidates) <= attack.MAX_CANDIDATES


def test_candidates_respect_limits():
    for c in _run():
        assert len(c.messages) <= attack.MAX_MESSAGES_PER_CANDIDATE
        for m in c.messages:
            assert len(m) <= attack.MAX_MESSAGE_LEN


def test_covers_multiple_predicates():
    preds = set()
    for c in _run():
        preds.update(c.meta.get("predicates", []))
    # The mock is vulnerable to all four; a healthy baseline should hit several.
    assert len(preds) >= 3, f"expected diverse predicate coverage, got {preds}"


def test_cells_are_unique():
    cells = [tuple(c.meta.get("cell", ())) for c in _run()]
    assert len(cells) == len(set(cells)), "duplicate cells should be deduped by the search"


def test_scores_positive():
    r = scoring.score(scoring.findings_from_candidates(_run()))
    assert r["raw_score"] > 0
    assert r["unique_cell_count"] >= 1
