"""
Quick smoke test for src/attack.py against the real SDK env.

Runs OUTSIDE Kaggle. Needs the unpacked SDK under sdk/ (run `make fetch-sdk`). Exercises the
attack loop against the deterministic vulnerable agent with an allow-all guardrail (which is
guaranteed to surface breaches, proving the pipeline), then reports contract compliance.

Usage:
    .venv/bin/python tests/smoke_test.py
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk"))
sys.path.insert(0, str(REPO / "src"))

import attack  # noqa: E402


def check_import() -> None:
    assert hasattr(attack, "AttackAlgorithm"), "AttackAlgorithm class missing"
    algo = attack.AttackAlgorithm()
    assert hasattr(algo, "run"), "AttackAlgorithm.run missing"
    print("[ok] attack.py imports and AttackAlgorithm.run exists")


def check_end_to_end() -> bool:
    try:
        from aicomp_sdk.agents.factory import build_agent_factory, AgentSelection
        from aicomp_sdk.attacks import AttackCandidate, AttackRunConfig
        from aicomp_sdk.evaluation.ops import build_attack_env, resolve_fixtures_dir
        from aicomp_sdk.guardrails.base import GuardrailBase
    except Exception as e:
        print(f"[skip] SDK not installed ({e}); run `make fetch-sdk` for the full smoke test")
        return False

    fx = resolve_fixtures_dir(None)
    af = build_agent_factory(AgentSelection.DETERMINISTIC)
    env = build_attack_env(seed=123, fixtures_dir=fx, agent_factory=af,
                           guardrail=GuardrailBase(), env_selection="sandbox", max_tool_hops=8)
    env.reset()
    cands = attack.AttackAlgorithm().run(env, AttackRunConfig(time_budget_s=30.0))
    assert isinstance(cands, list) and cands and all(isinstance(c, AttackCandidate) for c in cands)
    # The deterministic agent won't http.post from a user message, so run() returns fallback
    # single-post candidates. That validates the contract; real gpt_oss/gemma execute the post.
    print(f"[ok] ran attack vs deterministic agent — {len(cands)} candidate(s) (fallback expected)")
    for c in cands[:3]:
        print(f"     - {list(c.user_messages)[0][:90]}")
    return True


if __name__ == "__main__":
    check_import()
    full = check_end_to_end()
    print("\nSMOKE TEST:", "FULL (SDK exercised)" if full else "IMPORT-ONLY (install SDK for full run)")
