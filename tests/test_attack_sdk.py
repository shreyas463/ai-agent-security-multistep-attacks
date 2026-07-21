"""End-to-end tests for AttackAlgorithm against the REAL SDK env.

Uses the packaged deterministic vulnerable agent. Skips cleanly if the SDK isn't installed
(sdk/ is gitignored; run `make fetch-sdk` first). Two guardrail settings:
  * allow-all (GuardrailBase)  -> proves the attack loop actually produces breaching findings.
  * OptimalGuardrail (public)  -> the real public-leaderboard guardrail (may legitimately be 0
    against the simple deterministic agent; the real models behave differently).
"""
import pytest

pytest.importorskip("aicomp_sdk", reason="SDK not installed; run `make fetch-sdk`")

from aicomp_sdk.agents.factory import build_agent_factory, AgentSelection  # noqa: E402
from aicomp_sdk.attacks import AttackCandidate, AttackRunConfig  # noqa: E402
from aicomp_sdk.evaluation.ops import build_attack_env, resolve_fixtures_dir  # noqa: E402
from aicomp_sdk.core.predicates import eval_predicates  # noqa: E402
from aicomp_sdk.guardrails.base import GuardrailBase  # noqa: E402

import attack  # noqa: E402


def _run(guardrail):
    fx = resolve_fixtures_dir(None)
    af = build_agent_factory(AgentSelection.DETERMINISTIC)
    env = build_attack_env(
        seed=123, fixtures_dir=fx, agent_factory=af,
        guardrail=guardrail, env_selection="sandbox", max_tool_hops=8,
    )
    env.reset()
    algo = attack.AttackAlgorithm()
    return algo.run(env, AttackRunConfig(time_budget_s=45.0))


def test_returns_valid_candidates():
    cands = _run(GuardrailBase())
    assert isinstance(cands, list)
    assert all(isinstance(c, AttackCandidate) for c in cands)
    for c in cands:
        assert 1 <= len(c.user_messages) <= attack.MAX_MESSAGES_PER_CANDIDATE
        for m in c.user_messages:
            assert isinstance(m, str) and m.strip()
            assert len(m) <= attack.MAX_USER_MESSAGE_CHARS


def test_breaches_against_permissive_guardrail():
    """The core pipeline must find at least one real breach when nothing blocks it."""
    cands = _run(GuardrailBase())
    assert len(cands) >= 1, "expected >=1 breaching candidate against allow-all guardrail"


def test_candidates_are_unique_cells():
    """run() dedupes by score-cell hash, so no two returned candidates share a score cell."""
    from aicomp_sdk.core.cells import cell_signature
    fx = resolve_fixtures_dir(None)
    af = build_agent_factory(AgentSelection.DETERMINISTIC)
    cands = _run(GuardrailBase())
    hashes = []
    for c in cands:
        env = build_attack_env(seed=123, fixtures_dir=fx, agent_factory=af,
                               guardrail=GuardrailBase(), env_selection="sandbox", max_tool_hops=8)
        env.reset()
        for m in c.user_messages:
            env.interact(m, max_tool_hops=8)
        tr = env.export_trace_dict()
        assert eval_predicates(tr), "every returned candidate must actually breach on replay"
        hashes.append(cell_signature(tr.get("tool_events", []))["hash"])
    assert len(hashes) == len(set(hashes)), "returned candidates must occupy distinct score cells"
