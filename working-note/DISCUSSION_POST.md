# Discussion post — ready to paste

**Timing note (recommended):** post this **after the Sept 1 final-submission deadline** (the working
note is due Sept 8). The note publishes no tuned exploit and single-post is already the public
plateau, so the risk is low — but posting after Sept 1 removes any chance of amplifying the technique
to rivals before submissions lock. Paste into the competition's **Discussion → New Topic**.

---

## Title

`Working Note: Payload-blind egress — a benchmark-design finding, a runnable guardrail fix, and a falsifiable private-board prediction`

## Body

Sharing our working note for the competition. It's a **defensive, benchmark-design** analysis — no
tuned exploit, everything scoped to the offline `aicomp_sdk` sandbox — with three contributions I
think are useful to the maintainers and to other participants:

**1. A named vulnerability class: *payload-blind egress inspection*.** The reference
`OptimalGuardrail` judges an `http.post` by its *destination* (it reads the first-present of
`path, url, cmd, data, body, content`, so `url` shadows `data`) and never inspects the payload. That
single target-precedence choice — not any linguistic jailbreak — is what makes single-post sentinel
exfiltration near-optimal *by construction* under the severity+diversity scoring. The note derives the
scoring contract first and shows the strategy falls out of it.

**2. A runnable defensive artifact.** We ship a `HardenedGuardrail` (drop-in `GuardrailBase`) that
closes four leaks — payload-blind egress, filename-substring resource protection, the taint-window /
predicate-lookback mismatch, and missing session-level egress aggregation — with a `pytest` suite
(11/11) where **each test denies on `OptimalGuardrail` and passes on the hardened one**. Full source
is in the notebook appendix.

**3. A falsifiable prediction the competition will adjudicate.** Define the *payload-blind gap* =
`(public exfil score − private exfil score)` as a direct measure of egress-guardrail quality. If the
private guardrail closes payload-blind egress, the single-post plateau should **collapse field-wide on
the private board.** And it collapses *cleanly*: because the `EXFILTRATION` predicate matches the
`SECRET_MARKER` sentinel literally (no decode), any obfuscation that hides it from a payload scanner
also hides it from the predicate — the exploit and its fix are perfectly coupled, so there is no
encoded escape hatch.

The note also reports our honest v3→v9 journey (including four regressions trying to beat single-post)
and a **benchmark-integrity note for the maintainers**: cell-dedup on destination *hostname* lets the
diversity term farm breadth-of-hostnames rather than breadth-of-technique; de-duping on attack
*semantics* or capping the diversity contribution per predicate class would measure the intended thing.

📓 **Notebook:** https://www.kaggle.com/code/shreyascppsc/jed-payload-blind-egress-working-note

Happy to discuss the guardrail design or the payload-blind-gap metric.
