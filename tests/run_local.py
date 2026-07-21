"""
Local scorer-equivalent run of our AttackAlgorithm.

Uses the SDK's own `evaluate_redteam` harness (the same one `aicomp evaluate redteam` calls):
our attack runs against an opaque env, candidates are replayed, and scoring uses the
evaluator-owned traces + OptimalGuardrail (the public leaderboard guardrail).

We run against the DETERMINISTIC vulnerable agent locally — the real gpt_oss / gemma models
are GGUF-on-GPU and only available in the Kaggle runtime. This still exercises the full
pipeline and gives a real normalized score to iterate against.

Usage:
    .venv/bin/python tests/run_local.py [budget_seconds]
"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "sdk"))   # unpacked aicomp_sdk
sys.path.insert(0, str(REPO / "src"))   # our attack.py

from aicomp_sdk.agents.factory import AgentSelection, build_agent_factory  # noqa: E402
from aicomp_sdk.evaluation.runner import evaluate_redteam  # noqa: E402
from aicomp_sdk.evaluation.ops import AttackEvalOptions, eval_attack, unique_cell_count  # noqa: E402
from aicomp_sdk.attacks import AttackRunConfig  # noqa: E402
from aicomp_sdk.guardrails.base import GuardrailBase  # noqa: E402
from aicomp_sdk.scoring import score_attack, score_attack_raw  # noqa: E402

import attack  # noqa: E402


def _tally(findings) -> str:
    t: dict[str, int] = {}
    for f in findings:
        for p in f.get("predicates", []):
            t[p["predicate"]] = t.get(p["predicate"], 0) + 1
    return ", ".join(f"{k}={v}" for k, v in sorted(t.items())) or "(none)"


def official(budget_s: float) -> None:
    """Scorer-equivalent run: OptimalGuardrail (public leaderboard), deterministic agent."""
    print(f"\n[OFFICIAL] evaluate_redteam vs DETERMINISTIC agent + OptimalGuardrail, budget={budget_s}s")
    a = evaluate_redteam(
        attack.AttackAlgorithm, budget_s=budget_s,
        agent_selection=AgentSelection.DETERMINISTIC,
    ).attack
    print(f"  normalized={a.score:.3f}  raw={a.score_raw:.1f}  findings={a.findings_count}  "
          f"cells={a.unique_cells}  guardrail={a.guardrail_id}  t={a.time_taken:.1f}s")
    print(f"  predicates: {_tally(a.findings)}")
    print("  NOTE: 0 here is expected — the simple deterministic agent can't evade OptimalGuardrail;")
    print("        the real gpt_oss/gemma targets (GPU-only) comply differently.")


def sanity_allow_all(budget_s: float) -> None:
    """Allow-all guardrail: proves the pipeline finds breaches + shows diversity ceiling."""
    print(f"\n[SANITY] eval_attack vs DETERMINISTIC agent + allow-all guardrail, budget={budget_s}s")
    af = build_agent_factory(AgentSelection.DETERMINISTIC)
    findings = eval_attack(
        attack.AttackAlgorithm, budget_s=budget_s, agent_factory=af, env_selection="sandbox",
        options=AttackEvalOptions(
            run_config=AttackRunConfig(time_budget_s=budget_s),
            attack_config={}, env_seed=123, guardrail_factory=GuardrailBase,
        ),
    )
    print(f"  normalized={score_attack(findings):.3f}  raw={score_attack_raw(findings):.1f}  "
          f"findings={len(findings)}  cells={unique_cell_count(findings)}")
    print(f"  predicates: {_tally(findings)}")


if __name__ == "__main__":
    budget = float(sys.argv[1]) if len(sys.argv) > 1 else 60.0
    official(budget)
    sanity_allow_all(budget)
