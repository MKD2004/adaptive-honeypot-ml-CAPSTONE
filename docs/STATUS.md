# STATUS

Shared reference — **committed**, machine-tagged. Update at the end of every
session: what's done, what's running, what's next. Keep it short — this is a
snapshot, not a log (that's DECISIONS.md / ERRORS.md).

---

## Last updated: 2026-11-25 (Dhanya laptop) — GROUP D DEDUPLICATED, DATASET REBUILT

### Session summary (2026-11-25) — the group-D leak is closed and final_v2 is rebuilt on it

**Read `DATA_INTEGRITY.md` section 16.** `extract_semantic_batch` encodes each
DISTINCT command text once (761,108 of 1,749,809 rows) and scatters the result
back, so identical text yields a bit-identical embedding. The watermark is
removed at its cause, not quantised over -- the rounding attempt failed and is
in `ERRORS.md`.

**Verified.** 850 texts appear in both a real and a generated row; group-D maxabs
difference between them went 2.999e-06 -> **0.000e+00**. Within class the block
is now at chance -- 0.5000 / 0.5000 / 0.4998 / 0.4722 on the four
real-supported classes, against 0.9701 pooled before. Pooled is 0.8948 and
should stay high: class identity alone is worth 0.9702 (section 12d).

**So section 12e's claim is now fully supported** -- the synthetic data is
indistinguishable from real in network, payload AND semantic features within a
micro-state, and distinguishable by inter-arrival structure.

**`data/final_v2/` was rebuilt** (notebooks 02 then 05, in place). Row counts per
split, per generator and per `donor_origin` are identical to the 2026-11-24
build, `NaN count: 10,185,865` came back exactly, and the Part 3 gate PASSES all
four splits with 0 NaN. Two pooled numbers moved and neither is a fidelity
measure (sections 9a, 13d): adversarial AUC 0.9981 -> 0.9921, 45-class TSTR
0.036 -> 0.0278.

**The pipeline is 2.7x faster:** notebook 02 went 66.2 -> 24.5 min. Cell 5
54.6 -> 17.0 (dedup); cell 3 11.4 -> 7.4 (chunked `to_dict("records")` instead
of `iterrows`, verified value-identical on 6,000 rows). Notebook 05 is 30 s.

**A profiling lesson, recorded because it cost real time:** a timing taken while
notebook 02 was running reported `iterrows` at 1.000 ms/row against a true
0.391, and pointed at the wrong bottleneck entirely. The notebooks store
per-cell `execution` metadata -- read that instead.

**CLAUDE.md Current Status was rewritten.** It still described `data/final/`:
the model table, the "~83 informative features" count and the 29.74%
duplication figure were all measured on the retired build and are now marked
retired.

### Next

- **Retrain on `final_v2`** -- now unblocked, the last reason not to is gone. As
  an ablation, reported per class AND per `donor_origin`, on the DGX (this
  laptop is the 15 GB / RTX 3050 machine).
- **Open the PR** for `rebuild/part1-cowrie-event-generator` (15 commits). Body
  drafted; `gh` is not installed on this machine, so it needs doing from the web
  UI or a machine that has it.
- **The A/B intelligence-yield study** (ROADMAP section 5) is still the paper.
- Not incorporated: the 23-day capture (`cowrie_logs_20261124/`). Section 15 --
  it must REPLACE the 13-day capture, not join it, and every measured constant
  would need re-deriving.

---

## Last updated: 2026-11-24 (Dhanya laptop) — ADVERSARIAL EVALUATION

### Session summary (2026-11-24, latest) — six adversarial experiments on the shipped dataset

**Read `DATA_INTEGRITY.md` section 12.** Six controlled experiments on
`data/final_v2/`, equal n per side, random sampling, fixed seed.

**Headline: the synthetic data preserves network, payload and TLS
characteristics, and does NOT preserve timing.** Within class, `B_network`
0.515-0.575, `C_payload` 0.496-0.555, `F_tls_host` 0.500-0.553 -- chance.
`A_temporal` 0.74-0.98 against a strict standard of 0.50.

**Two findings that change how earlier numbers must be read:**

1. **Pooled AUC measures protocol and class, not provenance.** Two REAL netflow
   datasets separate at 1.0000; class identity alone is worth 0.9702 inside the
   synthetic data. Only same-protocol, within-class figures mean anything.
2. **Group D is quarantined.** It carries a provenance watermark (~3.0e-6 from
   DistilBERT batch padding), not content, and my rounding mitigation FAILED --
   0.8980 on raw, 0.9701 on scaled, identical rows. Rounding is space-dependent
   and is not a valid control. Worse than a measurement issue: **any model
   trained on these 128 features can learn provenance from those 30 columns.**
   Fix is deduplicating text before encoding (761,142 distinct of 1,749,809 rows,
   also 2.3x less encoding work). NOT DONE.

**A reproducibility gap closed:** `final_v2` could not say which rows were
synthetic, because `cowrie_real` and `simulated_cowrie_events` are both
`event_stream` in `prov_*.npy`. Notebook 05 now saves `gen_<split>.npy`, split
with identical seeds so `X_*`/`y_*` are byte-unchanged.

**A correction to my own earlier framing** (section 9g): the real-vs-real
reference band of 0.93-1.00 came from STRUCTURED splits and is the lenient
standard. A random half-split gives 0.4942-0.5100. Under the strict standard
`A_temporal` fails; B, C and F still pass.

### Next

- **Deduplicate text before encoding** -- closes the group-D leakage channel and
  speeds notebook 02. Highest-value remaining dataset item.
- **Retrain as an ablation** (DATA_INTEGRITY 11a), reporting per class AND per
  provenance. Note group D leaks provenance until the item above is done.
- **The A/B intelligence-yield study** (ROADMAP section 5) is still the paper.

---

## Last updated: 2026-11-24 (Dhanya laptop) — PART 0

### Session summary (2026-11-24, later) — PART 0 DONE: no more fabricated temporal features

**Read `DATA_INTEGRITY.md` section 10.** Part 0 was listed first in section 4 and
skipped through two rebuilds. The audit forced it: **915,320 of 1,749,809 rows
(52.3%)** of the rebuilt corpus carried a fabricated inter-arrival time -- every
CIC and UNSW row, because a netflow record has no event stream.

**Why it survived:** the fabricated row is ARITHMETICALLY CONSISTENT. `min <=
mean <= max` holds with equality, `cv == std/mean` holds at 0/x. Every invariant
passed. The validator was asking "is this self-consistent?", never "could this
have been measured?".

**The good news from inspecting the raw files:** CIC-IDS2017 ships genuine
`Flow IAT Mean/Std/Max/Min` (microseconds; min<=mean<=max coherent in 100.00% of
225,745 rows), so 657,646 rows now get REAL statistics instead of a constant.
UNSW gives a real mean via `sinpkt` (milliseconds, confirmed). `sjit` is NOT
mapped to `iat_std` -- Argus jitter is a mean deviation, and mapping it would
launder one statistic as another.

**What changed:**
- `extractors/temporal.py` -- four provenance levels, NaN for anything
  unmeasurable, NaN-safe presence checks for pandas records
- `extractors/pipeline.py` -- NaN preserved; `verify_schema` allows it only in
  the temporal block
- `validators/feature_integrity.py` -- `fabricated_iat_mask`,
  `validate_provenance` (new violation kind `fabricated`), `provenance_from_nan`
- `notebooks/01` -- passes CIC/UNSW real timing through, records
  `temporal_provenance` per row; `notebooks/02` -- carries it into real_meta
- zero-fill removed in THREE places, the third found only because the first two
  were fixed and the NaN count was still zero
- `extractors/semantic.py` -- chunked encode+project; the unchunked version
  peaked at 10.75 GB on a 15 GB machine and was OS-killing notebook 02

**Tests:** 14 new in `tests/test_temporal_provenance.py`, 98 in the suite. The
one that matters is `test_a_consistent_fabrication_is_still_rejected` -- it builds
a row passing every arithmetic invariant and asserts refusal.

### Open decision this creates

`data/final_v2/` now carries NaN by design. `StandardScaler` handles it natively,
but **the imputation strategy is deliberately undecided** (DATA_INTEGRITY 10e):
impute with a documented mask, restrict training to `event_stream` rows, or train
the temporal branch only where it has evidence. The point of Part 0 is that this
is now an explicit choice rather than a `nan_to_num` side effect.

### Next

- Rebuild in flight at the time of writing; the provenance audit (by source,
  class and split) runs against it. `data/final/` stays frozen.
- **Then assess Part 2** -- retrain, evaluate, or further experiments -- only
  once the temporal representation is defensible.
- Part 3 (`assert_valid` / `assert_temporal_provenance` at the training entry
  point) still not wired.

---

## Last updated: 2026-11-24 (Dhanya laptop)

### Session summary (2026-11-24) — FIDELITY: generated sessions now match real data as well as real data matches itself

**Read `DATA_INTEGRITY.md` section 9.** Section 8 (2026-11-15) fixed dataset
INTEGRITY; this session fixed FIDELITY, and corrected how the project reads its
own fidelity metric.

**The metric was being misread.** `adversarial_auc` fails above 0.6 and both
datasets score ~1.0, which had been taken as proof of bad fidelity. Controls on
the real capture alone: a random half-vs-half split scores **0.476-0.516** (the
method is sound), but **one real bot vs other real bots scores 0.93-1.00**. Real
data is trivially separable from itself. Fidelity is now judged per feature block
against that real-vs-real band.

**Four fixes to `cowrie_simulator.py`**, each driven by a measurement:
1. gaps bootstrapped from the real capture, keyed by (event type, session bucket)
   — replaces the fitted quantile grid and DELETES the long-pause gate
2. whole gap SEQUENCES copied from one real session — the residual signal was
   entirely in between-feature correlations, which per-gap draws destroy
3. walk pinned to a single state for the 5 real-supported classes — real sessions
   are single-action (`DISC_ENV_PROBE` is 1 command in 45,710 of 45,712)
4. real command sequences bootstrapped, carrying each one's measured ttylog size

**Result** — every block now inside its real-vs-real band, A_temporal below it:

```
class               A_temporal   B_network   C_payload
ACCESS_BRUTE_SSH      0.6693      0.4944      0.5000
DISC_ENV_PROBE        0.8158      0.5352      0.5000
RECON_IP_SCAN         0.7600      0.5897      0.5000
EXEC_SHELL_OPEN       0.9481      0.5494      0.5751
reference band      0.93-1.00   0.49-0.61   0.50-0.62
```

A_temporal went 0.98 -> 0.67-0.95 across the four classes; `C_payload` 1.0000 ->
0.50-0.58; `B_network` for EXEC_SHELL_OPEN 0.9265 -> 0.5494.

**Two new committed calibration artefacts** beside the module, both regenerable:
`cowrie_gaps.npz` (450 KB) and `cowrie_commands.json.gz` (350 KB). The latter
holds attacker-written text verbatim — DATA, never executed.

**Finding worth a paper line:** 45,712 `DISC_ENV_PROBE` sessions use **eight**
distinct command sequences. Real attacker traffic is overwhelmingly replay, which
compounds the 29.74% train/test value-overlap problem already recorded.

### IMPORTANT: the dataset on disk is stale

`data/final_v2/` was built 2026-11-15 and predates all four fixes. The fidelity
numbers above describe the GENERATOR, measured on freshly generated sessions
against the raw capture — never on the saved arrays. **A full rebuild
(01 -> 02 -> 05) is required before any number from `final_v2` is quoted
alongside section 9.** That rebuild was in flight when this entry was written.

### Next

- **Finish and validate the rebuild**, then re-run the section 8 integrity table
  and the section 9 fidelity table on the rebuilt arrays.
- **Part 2 of DATA_INTEGRITY section 4** (TabSyn primitives-only) remains NOT
  STARTED. TabSyn is currently excluded from the build (`HS_INCLUDE_TABSYN=1` to
  opt in), which sidesteps it — the generator now supplies the volume instead.
- **Part 0** (extractors return NaN, never fabricate) and **Part 3**
  (`assert_valid` as a training gate) still not done.
- `semantic_pca.pkl` has been refitted on the new corpus, so **live MT3 inference
  is wrong until retrain**. `semantic_pca.pkl.bak-pre-rebuild-20261119` restores
  the old axes if the demo is needed first.

---

## Last updated: 2026-11-15 (Dhanya laptop)

### Session summary (2026-11-15) — REBUILD PART 1 DONE: the generator emits logs, not features

**Read `DATA_INTEGRITY.md` section 8 for the full write-up.** This entry is the
snapshot.

**What was built.** `honeypot_dataset/src/generators/cowrie_simulator.py` — a new
generator that emits synthetic sessions as **Cowrie log events** and runs them
through `cowrie_parser.build_record()` and `pipeline.extract_all()`, the same
path real traffic takes. 32 tests in `tests/test_cowrie_simulator.py`; full suite
84 tests, all passing. This is Part 1 of the three-part fix in
`DATA_INTEGRITY.md` section 4.

**`data/final/` is untouched** — `X_train.npy` still carries its 2026-08-27
timestamp. `kill_chain_simulator.py` is unmodified, so notebooks 01 and 03b still
reproduce the frozen build. Every number in `CLAUDE.md` still describes the OLD
data; do not quote the two side by side without saying which is which.

**Calibrated against the 13-day capture** in `cowrie_logs/` (114,490 sessions,
754,063 events, 0 unparseable lines) — not the 8-day one. Note
`DATA_INTEGRITY.md` section 6 names the older `cowrie_logs_20261109/`; both
captures exist, both are gitignored and irreplaceable, back up both.

**Measured result — finding two is structurally gone:**

```
                           impossible-row checks failed    constant columns
X_train      (frozen)                13 of 97                  50 / 128
X_val        (frozen)                16 of 97                  50 / 128
X_test_synth (frozen)                14 of 97                  50 / 128
generated corpus (18,000 rows)        0 of 97                  39 / 128
```

13 of the 14 FIX features from the section 3c triage are alive. The specific
shape skews that put real sessions 226x outside training are closed:
`login_attempts` max 1 (was 552), `bytes_out` always 0, `bytes_in` 86 for a
one-command session, and duration/long-pause rates matching real within a few
percent in every stratum.

**Four assumptions the real data killed**, all in section 8: commands are the
*fastest* events in a Cowrie session (98.1% sub-100 ms — scripted bots, not
humans typing); the generated label must be the walk's *deepest* state, not its
first; 74% of a deep session's time is the implant-upload gap; and
`attacker_repeat_visitor` is 99.06% constant in the **real** capture too, so
section 3c's FIX verdict for it is wrong.

### Three decisions now waiting on the owner

1. **Label agreement is 24.0%, with 29 of 45 classes at 0.0%.** `cowrie_parser`
   can only emit 18 of the 45 micro-states. Decided this session: keep the
   intended label, record the parser's alongside, report the gap per class
   (`agreement_report()`). The consequence to accept or revisit: those 29 classes
   rest entirely on our own assertion, and MT3 agreeing with the rule labeller is
   not evidence of correctness. See DECISIONS.md.
2. **12 newly UNTRIAGED constant columns** need DROP/ALLOW verdicts in
   `feature_integrity.TRIAGE` — `bytes_out`, `log_bytes_out`, `bytes_ratio`,
   `packets_*`, `dst_port_norm`, `is_ssh_port`, `is_http_port`, `protocol_enc`.
   Most went constant *because* the generator stopped fabricating them. Honest
   count is now **89 informative of 128** for an SSH-only corpus.
3. **Balanced-corpus vs real-marginal mismatch, quantified.** 91% of generated
   sessions issue commands against 46% of real ones — unavoidable when 39 of 45
   classes are post-access states. Only conditional distributions transfer.

### Next

- **Part 2 — TabSyn generates primitives only, derived features recomputed.** NOT
  STARTED, and it is the one that matters most: without it a rebuild reproduces
  the 47% incoherence across the 720k synthetic rows. Part 1 only fixes the
  generator's own output.
- **Part 0** — extractors return NaN or raise instead of fabricating. Not done.
  The new generator never takes the `temporal.py` fallback, but it is still there.
- **Part 3** — wire `feature_integrity.assert_valid()` in as a training gate.
  Still nothing calls it at the entry point.
- Heralding collection continues on the Oracle VM (live since 2026-11-14, planned
  stop on or after 2026-11-29) — wall-clock bound, unaffected by this work.

---
## Last updated: 2026-11-11 (ASUS TUF)

### Session summary (2026-11-09 → 11) — FIRST REAL DATA, AND A DATASET INTEGRITY PROBLEM

**Read `DATA_INTEGRITY.md` before touching the dataset or quoting any number
below.** That is the handoff document for the rebuild.

**Real honeypot data exists for the first time.** A teammate ran Cowrie in Docker
on an Oracle Cloud VM and collected 8 days of internet traffic: **45,648 complete
sessions, 641 unique source IPs, 329,138 events, 0 unparseable lines**, plus 491
file uploads and 31 downloads. All of it parses cleanly and every row satisfies
the session contract. Details in `REAL_DATA_2026-11-09.md`. The capture is
gitignored and **irreplaceable** — back it up.

**The model does not fit it.** 23.3% agreement with the rule labeller on 300
sampled sessions, and 226x outside its own training distribution (real p50 3,491
Mahalanobis against a training p95 of 15.4; held-out `test_real` sits *inside* at
p50 3.5, so the measure is sound).

**Root cause, and it is bigger than the model.** 45 of 128 features are constant
across `X_train` — including **all 14 of `E_threat_intel`** (synthetic sessions
carry no CVE, so every threat-intel lookup returns defaults) and **all 8 of
`F_tls_host`** (Cowrie is SSH; there is no TLS to fingerprint). MT3 reads ~83
informative features, not 128, and two of six architecture branches consume
constants. Separately, **47% of TabSyn rows are arithmetically impossible** in
their temporal block — `iat_mean` greater than `iat_max`, `iat_cv = 0` while
`iat_min != iat_max`. Nothing ever checked, so nothing ever caught it.

**Fixed: the generator's timing model** (`f9fa918`). It emitted no per-event
timestamps at all, so `extract_temporal` took a fallback that fabricated a single
inter-arrival time, collapsing seven features. Now generates per-event timestamps
from a three-component lognormal mixture fitted to 283,432 real gaps, with
duration preserved exactly and duration/event baselines recalibrated per phase
(phase 0 at 2.0 s/5 events vs real shallow 1.9 s/5; phase 8 at 69 s/39 vs real
deep 63.6 s/41). 13 tests including a regression guard.

**Also this session:** finding #1 mitigated by corroboration rather than
abstention (`828ec08`); repo cleaned from 23.8 GB to 9.0 GB; all 22 root markdown
files moved into `docs/`.

**NOT done, deliberately:** the dataset is **not rebuilt**. `data/final/` is
untouched — `X_train.npy` still carries its August timestamp — so every published
number still describes the data it was measured on.

**Next:** the rebuild, in `DATA_INTEGRITY.md`'s order — loud failures, then the
validator (run it on the current data first for the full damage report), then
event-stream generation, then the TabSyn primitive/derived split, then rebuild and
retrain. A second honeypot is explicitly NOT next; collection can continue in
parallel since it is wall-clock bound.

---

## Last updated: 2026-11-04 (ASUS TUF)

### Session summary (2026-11-04) — MULTI-HONEYPOT PHASE 1 + 1b DONE, PHASE 2 PAUSED, MITIGATION MERGED, ALL THREE AUDIT FIXES CLOSED

13 commits, `156c82d` → `838fcc4`, all pushed. **626 tests pass** across
`traffic_gateway`, `response_mitigation` and `deploy/sandbox`; the one failure is
the pre-existing `test_honeypot_round_robin`, which asserts the router cycles
several honeypots while `CONFIG.HONEYPOT_TARGETS` has one entry.

Detail is in `DECISIONS.md` (11 entries today) and `HONEYPOT_AUDIT.md`
(PARTS 5-10, each with the measurements). This is the snapshot.

**MULTI_HONEYPOT.md Phase 1 — the pipeline can handle more than one honeypot.**
`cowrie_parser.build_record()` stamped every record `dst_port=22 protocol="ssh"`,
so `honeypot_target_for()` could only ever answer `SSH_HONEYPOT` and the whole
port→honeypot table was dead code. **Not fixed by reading the log:** the raw
corpus carries `dst_port 2222` on 39,931 events while `build_record` always
flattened it to 22, so every Cowrie session MT3 trained on had
`dst_port_norm = 0.000336`. Reading the real port would move feature 39 ~100x
against a trained constant, silently. They became keyword parameters whose
defaults reproduce the old behaviour byte-for-byte. Also added
`session_contract.py` (22 required + 19 optional fields, enforced by tests, with
negative controls) and `LogSource`, so the watcher takes N sources instead of one
hardcoded glob.

**Phase 1b — Group D settled by measurement.** The worry that
`ACCESS_BRUTE_HTTP`'s perfect score was leakage was wrong: it is **95.9% clean**
(116/121) and MT3 gets **116/116** right, clean macro-F1 0.8183. The real caveat
is representativeness — those rows are CIC-IDS2017 network flows, not honeypot
captures. **Decision: zero-fill Group D for non-SSH sources.** The deciding
number is where a zero-fill lands *after* the frozen scaler: mean 0.368σ, 0 of 30
dims past 2σ, nearer the centre than **94.65%** of real training rows. It is
in-distribution; off-domain text is not (the shell-fitted PCA keeps 90.8% of
shell variance but 73.6% of HTTP's and 64.1% of SQL's). Cost, which belongs in
the paper: non-SSH protocols are classified by **98 of 128 features**.

**Phase 2 — Heralding parser done, DEPLOYMENT PAUSED on a safety finding.** The
parser, rule labeller, `heralding_source()` and 36 tests work. MT3 does not:
**0 of 6** scenarios agree with the labeller and it is *confidently* wrong — a
bare connect with no auth attempt returns `DISC_NETSTAT_SCAN` at confidence
**1.000** (phase 3), which clears `MT3_AUTO_BLACKLIST_CONF`, so deploying as-is
would blacklist users for opening a TCP connection. Cause: Heralding reports no
bytes, packets, TCP flags, TLS or commands, so **only 55 of 128 feature columns
are non-zero** and MT3 is extrapolating.
→ Built the **MT3 trust gate**, keyed on session `source` not protocol (a Cowrie
telnet session is shell-shaped, a Heralding one credential-shaped). The verdict is
still computed and logged for every source, but may only *act* for
`cowrie_real`.
→ Tried a **fine-tune** (separate model, `artifacts/mt3_multi/`, replay against
forgetting). It **fixed the safety problem** (bare connect → `RECON_IP_SCAN`
phase 0) and did not regress `test_real` (0.8272 → 0.8284), Heralding held-out
macro-F1 **0.8924** — but the six hand-built scenarios score only **3/6**, so the
**gate stays closed**. The model learned the generator's distribution, not the
concept. Widening the generator to chase the acceptance set would be tuning
training data to the test and was deliberately not done.

**`feature/mitigation-layer` merged** (`f7810ee`, 9 commits, +8553): the
`response_mitigation` package and **`deploy/sandbox/`**, the hardened
internet-facing kit. One conflict, 6 hunks, in `post_session_pipeline.py` — the
branch called `_mitigate()` *unconditionally*, which merged naively would have
silently undone the trust gate above. Resolved so the engine inherits it.

**All three of HONEYPOT_AUDIT.md PART 3's fixes are now closed:**
1. **API authentication** — bearer token on the four write endpoints, CORS
   narrowed from every origin, and the part that matters: a **start-up refusal**
   when a reachable address is bound with no token. `run_pipeline.py` called
   `app.run()` directly and so bypassed the guard — it is what `live_demo.py`
   runs, so the guard would have been absent from the only path anyone uses. API
   host now defaults to `127.0.0.1`; nothing external ever needed port 5000.
2. **Whitelist bypass** — `skip_reason()` never received the verdict, so
   `is_whitelisted` short-circuited everything at any phase and any confidence.
   A strong verdict (phase ≥ 2, conf ≥ 0.90) may now override a whitelist for
   **DIVERT**, never for **DENY** — a firewall drop of a trusted address can lock
   you out.
3. **Reputation scorer dilution** — every signal was an average over 20 sessions,
   so one serious session was worth 5%. Now the worse of the average and the
   worst session in a 5-session window: the diluted case moves **0.166 → 0.542**
   (crosses SUSPICIOUS, blocks auto-promotion) while the all-clean floor (0.179)
   and sustained-attacker ceiling (0.654) are **unchanged to six decimals**. The
   short window is deliberate — over the full history a spike would be
   permanently sticky and `whitelist_promoter` could never rehabilitate anything.

**Phase 0 readiness.** `deploy/sandbox/`'s own tests pass for the first time
(72 passed, was 3 failing; neither failure was caused by this session's work —
checked at the branch tip). Worst find: **the kit never set `PIPELINE_SOURCE`**,
so every real VPS capture would have been filed `"unspecified"`, unrecoverably
indistinguishable from months of simulated sessions. Now set in the env template,
warned about by `verify_sandbox.sh`, and documented in the runbook. Also:
`active_config.json` is live state living inside a code directory, so the write
recorder copied this machine's honeypot posture and its test passed or failed
depending on what the last demo left behind.

**Demo fix:** `demo/real_server.py` gave a human 20 s from handshake to
authenticating — enough for `attack_client.py` but not for a person clearing the
host-key prompt and typing a password. Raised to 120 s. Hit live during the
two-laptop demo.

**Next:** Phase 0 needs a **VPS** — provisioning is the only thing left and it
needs a cloud account. Then the runbook's Part A (Cowrie on 2222, own IP only) →
Part B (port 22 to the world) → `check_cowrie_ips.py` to confirm real source IPs
rather than `172.x`. After that: Heralding for *collection* with rule labels (the
MT3 gate stays closed), and `ROADMAP.md` M3's A/B study, which needs none of this
work and should not be confounded by multi-honeypot data.

**Still open, deliberately:** MT3 is untrusted for every non-Cowrie source;
`mt3_multi/best.pt` exists but nothing in the live pipeline points at it (opening
the gate and repointing the pipeline are one decision); the frontend does not yet
render the new `sources` / `mt3_trusted` / `group_d_mode` fields; and the
scorer's 0.750 ceiling against a 0.70 blacklist threshold is a pre-existing
calibration question I did not touch.

---

## STATUS.md gap: 2026-09-01 → 2026-11-04

This file jumps from session 3 straight to today, but two sessions' work happened
in between and is recorded elsewhere, not here:

- **2026-09-29** — the live pipeline, gateway, adaptive reconfiguration, dashboard
  and the two-laptop demo were built. See `CHANGES_AFTER_30_SEPT.md` and
  `CLAUDE.md`'s "Live Pipeline / System" section.
- **2026-11-02** — the honeypot reality check: how many honeypots actually exist
  (one), whether any captured traffic is real (none is), and the mitigation-layer
  review. See `HONEYPOT_AUDIT.md` PARTS 1-4.

Recorded so the gap is visible rather than looking like nothing happened.

---

## Last updated: 2026-09-01 (session 3, ASUS TUF)

### Session 3 summary (2026-08-28 → 2026-09-01) — DATASET FROZEN, BOTH MODELS TRAINED

The pipeline is finished and the review comparison is done. Nothing in
`data/final/` may be regenerated — both models are trained on those exact rows.

**Dataset — HoneySynth-960k, frozen 2026-08-27.** TabSyn sampling (720k) completed,
notebook 05 assembled real+TabSyn (GReaT-optional path), splits written to
`honeypot_dataset/data/final/`: 756,000 train / 84,000 val / 60,000 `test_real` /
60,000 `test_synth`; 128 features; 45 classes in train/val/test_synth, **21** in
`test_real`. Train imbalance 28.7x (6,055 → 173,722 per class).

**PROVENANCE CORRECTION (2026-08-28)** — see DECISIONS.md. The 15,000 Cowrie
sessions are **synthetic** (teammate-confirmed), not real. Genuinely real data is
**CIC-IDS2017 + UNSW-NB15 only**, anchoring **13 of 45** classes, all network-flow.
Real class coverage 22 → 13. The 22-class figure in the session-1 table below is
superseded; it is a count of *labelled* classes, not real-anchored ones.

**MT3 pipeline built** (`ml_analytics/mt3_pipeline/`, `0178f58`): data loading with
scaler-provenance checks, class-weighted/focal loss, metrics, train/eval/compare
CLIs, `make_pilot.py`, and a 10-step smoke test. `models/mt3.py` untouched.

**Two dataset traps found and logged in ERRORS.md (top two entries).** Both corrupt
silently, neither crashes: (1) the `data/final/` arrays are ALREADY SCALED —
notebook 05 saved `scaler.transform(X)`, so re-transforming shifts column means
0.002 → 4.8; (2) `feature_scaler.pkl` is a **joblib** dump, `pickle.load` raises.
`data.check_scaling()` now refuses to train if the arrays stop looking pre-scaled.

**Models — all on the identical frozen splits, macro-F1 over the 21 classes present
in `test_real`:**

| model | params | val macro-F1 | test_real | test_real (clean) | test_synth |
|---|---|---|---|---|---|
| linear probe (128→45) | 5,805 | 0.9376 | 0.7681 | **0.7551** | 0.9373 |
| CNN-LSTM baseline | 189,581 | 0.9621 | 0.8093 | **0.7976** | 0.9610 |
| MT3 (d=256, 4 layers) | 3,759,510 | 0.9599 | 0.8276 | **0.8187** | 0.9589 |

MT3 ran on the ASUS (RTX 3050 4GB, bf16 AMP, batch 1024, `--cache-on-device`):
~40 s/epoch, early-stopped at epoch 35, best epoch 29. CNN-LSTM ran on Colab
(~7 s/epoch, early stop epoch 67, best epoch 52).

**Headline result: on `test_real` the two models TIE** — McNemar p = 0.617 (clean),
p = 0.569 (contaminated). MT3's Transformer fusion does not beat concatenation +
MLP at 20x the parameters. The CNN-LSTM wins `test_synth` significantly
(p = 0.00064) and edges MT3 on val macro-F1. Because the baseline deliberately
reuses MT3's branch encoders, this is a clean ablation of the fusion step.
A 5,805-parameter linear probe at 0.7681 is the floor any result must clear.

**TRAIN/TEST CONTAMINATION — quote the clean column.** 17,843 of the 60,000
`test_real` rows (**29.74%**) are byte-identical to rows in `X_train` with the same
label; another 20.11% duplicate `X_val`. Cause: notebook 05's `train_test_split` is
disjoint **by index, not by value**, and real CIC/UNSW flows genuinely repeat. Clean
subset = **41,785** rows, all 21 classes survive; mask at
`test_real_clean_mask.npz` (local, gitignored). `test_synth` unaffected (0.00%).
Worst class: EXEC_SHELL_OPEN, 94.7% duplicated, F1 ~0.99 → ~0.82 once cleaned.
Both models score ~1.0 on the leaked rows, so the *gap* barely moves (+0.0183 →
+0.0210) — but the absolute numbers are inflated and must not be reported as-is.

**Architecture audit — MT3 has no CRF.** No `CRF`/`viterbi`/transition matrix in
`mt3.py`; the "hp_logits" head is a 9-way phase auxiliary, and `KILL_CHAIN_DAG`
never enters training. Measured 2026-09-01: on `test_synth` all three models' errors
are at or **below** chance for DAG legality (0.380 / 0.391 / 0.357 vs 0.412 chance)
— no model has learned kill-chain structure. Adding a real CRF needs per-event
features `data/final/` does not carry. Deferred, not hidden.

**CNN-LSTM branch merged** into `main` (`8087d26`, local — review before pushing).
`SESSION_CONTEXT.md` excluded from the merge and gitignored (stale 2026-08-21
working doc; same rule as ASUS.md / HARDWARE.md / SETUP.md).

**Next:** teammate to confirm the clean 0.7976 independently; report clean numbers
in the paper with the 29.74% disclosed; post-review, rebuild the split
deduplicated-by-value. GReaT (04) still deferred.

---

## Session 2: 2026-08-25 (ASUS TUF)

### Session 2 summary (2026-08-25)
Built the Colab overnight VAE pipeline on the ASUS TUF (code/orchestration only —
no local GPU training). Decision reversed to 45-class TabSyn (see DECISIONS.md).

- **New:** `honeypot_dataset/notebooks/03b_tabsyn_vae_colab.ipynb` — mounts Drive,
  clones repo + TabSyn (pinned `cb5ac0f` + `patches/tabsyn-colab.patch`), merges
  180k balanced simulated sessions with real features, **asserts 45/45 classes**,
  trains VAE only (batch 4096, 500 epochs), checkpoints every 50 epochs + logs
  every epoch to `Drive/.../tabsyn_status.txt`. Does NOT start diffusion.
- **New:** `src/generators/sim_commands.py` — realistic per-micro-state
  `command_text` so simulated rows populate the semantic block (leak fix).
  Validated locally: 45/45 classes, semantic block non-zero for all rows, 0 NaN/Inf.
- **New:** `patches/tabsyn-colab.patch` — the vendored-TabSyn fixes as a git-appliable
  patch (tabsyn/ is git-ignored, so this is how Colab gets them). Now also includes
  the env-var-driven Drive checkpoint/epoch-log hook. Verified applies clean to cb5ac0f.
- Committed + pushed to `main` (`dbafc90`): notebook, sim_commands, patch, the two
  extractor NaN fixes, `.gitattributes` LF rule for *.patch.
- ASUS power locked for overnight: AC sleep/monitor = never, lid-close = do nothing.

**Update (2026-08-25 ~21:52): VAE training is now RUNNING LOCALLY on the ASUS.**
The Colab run crashed at ~5h/epoch 111 (checkpoint saved at epoch 100 only). Because
TabSyn's checkpoints were weights-only (no beta/optimizer state), that run could not
be cleanly resumed — the beta-annealing schedule that drove the loss down was lost.
Decision (user's call): run a FRESH VAE on the ASUS laptop itself (secondary to DGX,
which wasn't reachable). Before launching, added full-state crash-safe checkpoint/
resume to `vae/main.py` (model+optimizer+scheduler+beta+patience+epoch), validated
by a 2→4 epoch resume test, and folded into `patches/tabsyn-colab.patch`.

- Data: prepared the 45-class merged set LOCALLY (same seeds as Colab): 1,387,698
  train / 154,189 test rows at `tabsyn/data/honeypot_sessions/`. `category_embeddings`
  is `[45, 4]` (confirmed 45-class, not the old `[22, 4]`).
- Run: `main.py --method vae --epochs 500 --training_batch_size 512`, detached
  (PID in `tabsyn/vae_run_local/train.pid`), logging to
  `tabsyn/vae_run_local/status.txt`, checkpoints (every 50 + `resume_state.pt` every
  epoch) in `tabsyn/vae_run_local/checkpoints/`.
- Measured: **215.9 s/epoch** at batch 512 (no OOM) → ~30h for 500 epochs. At batch
  512 there are 2711 steps/epoch (vs Colab's 339 at 4096), so it optimizes ~8x faster
  per epoch — epoch 1 val_mse 0.006 already beats Colab's epoch-1 0.036. Likely hits
  the 0.000847 target well before epoch 500.
- If interrupted: just relaunch the same command — it auto-resumes from
  `resume_state.pt`. Does NOT auto-start diffusion.

**Update (2026-08-26 02:47): VAE training COMPLETE — target met, auto-stopped.**
Early-stopped at epoch 79/500 (val_mse 0.000807 <= target 0.000847 for 3
consecutive epochs; best val_mse 0.000722 at epoch 77). beta annealed
0.010 -> 0.007 -> 0.0049 -> 0.00343. ~5h wall on ASUS at batch 512 (vs ~30h for a
full 500). Process exited clean. Final artifacts saved to
`tabsyn/tabsyn/vae/ckpt/honeypot_sessions/`: model.pt, encoder.pt, decoder.pt,
train_z.npy (2.8GB). Periodic/resume checkpoints in `tabsyn/vae_run_local/`
(model_epoch0050.pt, resume_state.pt) + full per-epoch log in
`vae_run_local/status.txt`. Diffusion was NOT started (by design).

---

## (session 1) 2026-08-11

## Pipeline stage

| Notebook | Status | Notes |
|---|---|---|
| 01_process_real_data | ✅ Done | 737,319 real sessions saved to `data/processed/real_sessions_combined.parquet`. 22/45 micro-states covered from real data (see SCHEMA.md for which). |
| 02_feature_extraction | ✅ Done | Ran clean on attempt #4 (3 crash bugs fixed first, see ERRORS.md). `X_real.npy`/`y_real.npy` saved, shape (737319, 128) / (737319,), 0 NaN / 0 Inf. Classes covered: 22/45 (matches SCHEMA.md prediction exactly). Semantic PCA fitted (98.4% variance) and saved to `data/processed/semantic_pca.pkl`. Total wall time ~21 min (much faster than the notebook's own 180k-session benchmark implied). |
| 03_tabsyn_generation (data prep, cell 3.1) | ✅ Done | `tabsyn/data/honeypot_sessions/` prepared: 886,549 train / 98,506 test rows. Only 22/45 classes present (same gap as notebook 01/02 — cell 3's oversampling loop only touches classes present in the data). `info.json` still says `n_classes: 45` but the model's actual `category_embeddings` are sized `[22, 4]`. **Open question, see DECISIONS.md — not yet resolved.** |
| 03_tabsyn_generation (VAE timing test) | ✅ Done | 3-epoch test run on this laptop (RTX 3050, batch 512): **~140 sec/epoch measured**. Hit and fixed 5 real bugs in the vendored `tabsyn/` code along the way (missing deps, ignored CLI args, 3x unbatched-forward-pass OOM, torch version-skew crash) — see ERRORS.md. Extrapolated full-run estimates: 500 epochs ≈ **19.4 hours**, 1000 ≈ 38.9h, 4000 (the old broken hardcoded default) ≈ 155h. |
| 03_tabsyn_generation (real VAE run, 500 epochs) | ⏳ Deferred to college | 22/45-class scope confirmed correct by design (see DECISIONS.md) — no data-prep changes needed. Laptop run would be ~19.4h; user decided to run VAE on the college RTX 4500 Ada instead. All 5 bug fixes from today are in the vendored `tabsyn/` code itself, so they carry over — should NOT need rediscovering at college. |
| 03_tabsyn_generation (VAE, real run) | ✅ DONE (2026-08-26, ASUS) | 45-class VAE early-stopped at epoch 79, val_mse 0.000807 (< 0.000847 target). Artifacts at `tabsyn/tabsyn/vae/ckpt/honeypot_sessions/`. See the 2026-08-26 update below. |
| 03_tabsyn_generation (diffusion) | ✅ DONE (2026-08-27, ASUS) | Completed full 2000/2000 epochs, best_loss 0.042314. Run 1 collapsed at epoch 63 (unclipped lr=1e-3) → added gradient clipping, restarted; run 2 stable start to finish. Survived 3 accidental laptop sleeps via the crash-safe resume. `model.pt` at `tabsyn/tabsyn/ckpt/honeypot_sessions/`. Next: SAMPLING. |
| 03 sampling (720k) | ✅ DONE (2026-08-27, ASUS) | 720,000 synthetic rows sampled; batching (`TABSYN_SAMPLE_BATCH`/`TABSYN_N_SAMPLE`) kept it inside the 4GB card. Fed straight into notebook 05. |
| 04_great_generation | ⏸️ DEFERRED (review-freeze) | Skipped for the 2-day review; add later only if time. Runs on DGX (GB10), ~6-7h. See DECISIONS.md 2026-08-27. |
| 05_assembly_validation | ✅ DONE (2026-08-27) | Made **GReaT-optional** (cells 3/5/7 auto-detect `X_great.npy`; assemble real+TabSyn when absent). Output: HoneySynth-960k in `data/final/`. **Known defect: splits are disjoint by index, not by value → 29.74% of `test_real` duplicates `X_train`.** See session 3. |
| CNN-LSTM baseline | ✅ DONE (2026-08-31, Colab) | 189,581 params, val macro-F1 0.9621, test_real 0.7976 clean. Teammate deliverable, merged `8087d26`. |
| MT3 | ✅ DONE (2026-08-30, ASUS) | d=256/4 layers, 3,759,510 params, val macro-F1 0.9599, test_real 0.8187 clean. Ties the baseline (p=0.617). |

## Environment

- venv at `honeypot_dataset/venv/` has torch `2.13.0+cu126` (CUDA-enabled, verified working — see HARDWARE.md). System Python 3.14 does NOT have the project deps; always use the venv interpreter.
- Raw data present: Cowrie (`data/raw/cowrie_logs/cowrie.json`, 15,000 sessions), CIC-IDS2017 (8/8 CSVs), UNSW-NB15 (both files).

## Review plan (2026-08-27, ~2-day deadline)

Freeze dataset at **real + TabSyn** (skip GReaT); train CNN-LSTM baseline + MT3 on
the **DGX (GB10)** and compare. Steps: diffusion finishes → TabSyn sampling (720k)
→ notebook 05 (real+TabSyn, GReaT-optional) → transfer frozen dataset to DGX →
train both models. Fallback if TabSyn fails: real-only `X_real.npy` (22 classes),
already on disk. GReaT deferred. See DECISIONS.md 2026-08-27. **MT3 is unwritten =
the real critical path** — do not block on GReaT.

## Superseded: immediate next step as of 2026-08-25 (Colab VAE run — done, see session 3)

**To start the overnight Colab VAE run from ASUS TUF:**
1. Upload to a Google Drive folder `MyDrive/capstone/` (the notebook's `DRIVE_PROJECT`):
   `X_real.npy`, `y_real.npy`, `semantic_pca.pkl` (all in `honeypot_dataset/data/processed/`).
   `real_sessions_combined.parquet` is optional (the notebook reuses the extracted
   `X_real.npy` for the real side, so it is not required).
2. Open `honeypot_dataset/notebooks/03b_tabsyn_vae_colab.ipynb` in Colab (GitHub →
   the pushed `main`), set Runtime → GPU, Run all.
3. Watch cell 5 assert 45/45, then cell 7 stream VAE epochs. Paste the keep-alive
   snippet in the browser console; leave the tab open overnight.
4. Morning check: `Drive/capstone/tabsyn_vae_run/tabsyn_status.txt` — epoch 500
   reached, final val MSE < 0.000847, 10 checkpoints in `checkpoints/`, no OOM,
   45-class assert line present.

---

## Prior next step (2026-08-11, superseded by 03b for the VAE stage)

Laptop-side work for today is done. At the college system: run notebook 03
cell 5 (now works correctly — CLI-arg-wiring bug fixed, so `vae_batch=4096`/
`vae_epochs=500` and `diff_batch=4096`/`diff_epochs=2000` will actually take
effect) or invoke `tabsyn/main.py --method vae`/`--method tabsyn --mode train`
directly. Before a real run there: worth a quick check that diffusion
(`tabsyn/tabsyn/main.py`) doesn't have its own unbatched-eval-OOM issue like
VAE did (untested — see STATUS.md pipeline table). The 1.8GB `train_z.npy` /
`model.pt` / `encoder.pt` / `decoder.pt` at
`tabsyn/tabsyn/vae/ckpt/honeypot_sessions/` right now are from the 3-epoch
laptop *test* run only — not a real trained model, will be overwritten by the
actual college run, safe to delete for disk space if wanted.

## Known gaps (not bugs, just not done yet)

- 23/45 micro-states have zero real-data coverage (expected — real traffic doesn't
  naturally produce every APT technique). These need TabSyn/GReaT synthetic coverage.
  Full list in SCHEMA.md.
- `EVENT_MAP` dead code in notebook 01 (cowrie.direct-tcpip.request events silently
  ignored) — not fixed, low priority since LATERAL_SSH_SPREAD is still reachable via
  UNSW's Worms category. See ERRORS.md.
