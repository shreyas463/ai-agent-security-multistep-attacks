# How to submit

The submission is a Kaggle **notebook** that writes `attack.py` to `/kaggle/working/` and runs the
competition inference server. The scored rerun loads `attack.py`, runs `AttackAlgorithm` against
gpt_oss + gemma, replays candidates against the public/private guardrails, and scores.

`notebooks/submission.ipynb` is generated from `src/attack.py` — regenerate after any edit:

```bash
python scripts/build_notebook.py      # or: make notebook
```

## Option A — push via CLI, then submit in the UI (fastest)

```bash
make push-kernel        # kaggle kernels push -p notebooks/   (private kernel, GPU, internet off)
```

Then on Kaggle:
1. Open the kernel (it auto-runs on push). Wait for the **commit** run to finish — it validates
   quickly because it's pinned to the deterministic agent (`AICOMP_MODEL_NAMES=deterministic`).
2. Click **Submit to Competition** on the kernel/competition page and pick this notebook version.
   The scored rerun then runs the real gpt_oss/gemma evaluation (this consumes 1 of your 5/day).

## Option B — official starter notebook (most robust)

If the official starter notebook's server-run cell differs from ours, prefer it:
1. Open the competition's starter notebook and **Copy & Edit**.
2. Replace its attack-writing cell with the `%%writefile /kaggle/working/attack.py` cell from
   `notebooks/submission.ipynb` (the full contents of `src/attack.py`).
3. Keep the starter's server-run cell as-is. Save Version → Submit.

## What to expect on the leaderboard

Four scores: `gpt_oss_public`, `gpt_oss_private`, `gemma_public`, `gemma_private`.

Realistically the **public** scores may be low at first: OptimalGuardrail blocks the naive paths,
so only EXFILTRATION (SECRET_MARKER + taint laundering) and CONFUSED_DEPUTY (benign email.send)
are reachable there, and both depend on the target model actually complying (see
`notes/guardrail-analysis.md`). This first submission is about establishing a real baseline and
seeing which families the actual models fall for — then we iterate.

## Notes / caveats

- Internet is **off** in the notebook; the SDK + `kaggle_evaluation` come from the attached
  competition sources, not pip. Don't add internet-dependent code to `attack.py`.
- The commit run writes a `submission.csv` with deterministic-agent scores; the **scored rerun
  overwrites it** with the real gpt_oss/gemma scores. Don't be alarmed by low commit numbers.
- 5 submissions/day; up to 2 final. Keep an eye on the daily quota.
