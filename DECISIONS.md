# DECISIONS

Reference only — not committed. Log *why* a non-obvious choice was made, so we
don't re-debate or accidentally re-break it later. Newest first.

---

## 2026-11-04 — IMPLEMENTED: the MT3 trust gate (gated on source, not protocol)

Decisions 1 and 2 from the "Phase 2 STOP" entry below are now code.

**Gated on `source`, not `protocol`** -- the first cut of this used protocol and
that was wrong. A Cowrie *telnet* session is shell-shaped (commands, byte counts,
durations); a Heralding *telnet* session is credential-shaped. The protocol string
does not determine the feature shape, the producing honeypot does.

- `CONFIG.MT3_TRUSTED_SOURCES = {"cowrie_real"}`, with
  `MT3_TRUST_UNKNOWN_SOURCE = False` so an unrecognised source fails closed.
- `post_session_pipeline.mt3_is_trusted_for()` gates both the auto-blacklist and
  the honeypot reconfiguration. The verdict is still computed and written to
  every result line -- that is the comparison data a retrain needs, and §7.6's
  labelling plan depends on it -- it simply may not ACT.
- `mt3_trusted` is now a field on every result line.

**Also wired Phase 1b's zero-fill, which had been decided but not implemented.**
`feature_bridge.group_d_mode(session)` returns `"live"` or `"zero-filled"` per
source, and `extract_features` honours it. It returns a *mode* rather than a bool
precisely so the result line can tell "DistilBERT missing" from "deliberately off
for this source" -- the gap the Phase 1b entry flagged as owed. `group_d_mode` is
on every result line too.

**Verified end to end** -- the dangerous case from HONEYPOT_AUDIT.md PART 7, and
a Cowrie control, through the real pipeline:

```
Heralding bare connect (no auth attempt at all):
  rule label        RECON_IP_SCAN
  MT3 said          DISC_NETSTAT_SCAN (conf 0.9983, phase 3)
  mt3_trusted       False
  group_d_mode      zero-filled
  auto_blacklisted  False
  config changed    False  (skipped: MT3 not trusted for source 'heralding')
  IP blacklisted    False

Cowrie control (rm -rf /var/log/auth.log):
  MT3 said          EVASION_LOG_WIPE (conf 0.9867, phase 6)
  mt3_trusted       True
  group_d_mode      live
  auto_blacklisted  True
  IP blacklisted    True
```

MT3 is still confidently wrong on the Heralding record (0.9983 for a bare
connect). The gate does not fix that; it stops it mattering. Fixing it is the
retrain.

**Do not add a source to `MT3_TRUSTED_SOURCES` without re-running the PART 7
acceptance scenarios against the retrained model.** A regression test asserts
`heralding` is not in that set, for exactly this reason.

---

## 2026-11-04 — Phase 2 STOP: MT3 cannot classify Heralding sessions, and auto-blacklist must be gated

**Finding, and it blocks the rest of Phase 2.** The Heralding parser works and
emits contract-clean records that route correctly. But pushing those records
through the real feature extraction and the trained MT3 gives **zero agreement
with the rule labeller on 6 of 6 scenarios**, with high confidence on nonsense:

```
scenario            rule label            MT3 (Group D live)      conf  phase
http brute force    ACCESS_BRUTE_HTTP     RECON_OS_DETECT        0.567      0
factory defaults    ACCESS_DEFAULT_CRED   EXEC_WGET_EXEC         0.985      2
cred stuffing       ACCESS_CRED_STUFF     EVASION_HIST_ERASE     0.491      6
user enum           RECON_USER_ENUM       PERSIST_BACKDOOR_ADD   0.742      5
bare connect        RECON_IP_SCAN         ACCESS_BRUTE_SSH       0.888      1
ftp brute force     ACCESS_BRUTE_HTTP     EXEC_SHELL_OPEN        0.834      2
```

**Group D is not the cause.** Applying Phase 1b's zero-fill decision does not
rescue it -- still 0/5, and one case gets *worse*:

```
scenario      rule label            Group D LIVE               Group D ZERO-FILLED
http brute    ACCESS_BRUTE_HTTP     EVASION_HIST_ERASE 0.915   DISC_NETSTAT_SCAN 1.000
defaults      ACCESS_DEFAULT_CRED   EXEC_WGET_EXEC 0.985       EXEC_WGET_EXEC 0.459
stuffing      ACCESS_CRED_STUFF     EVASION_HIST_ERASE 0.491   EXEC_WGET_EXEC 0.559
user enum     RECON_USER_ENUM       PERSIST_BACKDOOR_ADD 0.742 EXEC_WGET_EXEC 0.580
bare          RECON_IP_SCAN         ACCESS_BRUTE_SSH 0.888     DISC_NETSTAT_SCAN 1.000
```

**Why.** A Heralding session has no shell, no bytes counted, no packet sizes, no
TCP flags and no TLS -- Heralding simply does not report them. So Groups B, C, E
and F are mostly *defaults*, Group D is either off-domain or constant, and MT3 is
extrapolating into a region of feature space it never saw in training. The 1b
finding that "98 of 128 features transfer cleanly" was about the *schema*
supporting HTTP. It is not a claim that a Heralding-shaped vector is
in-distribution, and this measurement shows it is not.

**The safety consequence, which is worse than the accuracy one.**
`CONFIG.MT3_AUTO_BLACKLIST` fires at phase >= 1 and confidence >= 0.5. A **bare
connect with no authentication attempt at all** is predicted `DISC_NETSTAT_SCAN`
at confidence **1.000** (phase 3). Deploying Heralding behind the current
pipeline would auto-blacklist users who merely opened a TCP connection, on a
confident wrong answer, and would escalate the honeypot off the same verdict.

**Decisions taken:**

1. **Do not run MT3 on non-SSH sessions until it is retrained for them.** The
   rule labeller carries Heralding for now. This is a per-protocol gate, not a
   confidence threshold -- the verdicts are confidently wrong, so a threshold
   does not help.
2. **`MT3_AUTO_BLACKLIST` must be gated by protocol too**, for the same reason.
   An ungated deployment is a false-positive generator.
3. **Phase 2 deployment is paused** pending (1) and (2). The parser, labeller,
   `heralding_source()` and tests are committed and useful; standing Heralding up
   in front of this pipeline is not safe yet.

**What would unblock it:** generating Heralding-shaped training rows (the
honeyfs/kill-chain simulator already produces synthetic sessions, so this is
tractable) and retraining MT3, then re-running the six scenarios above as the
acceptance test. That is M2-scale work and belongs on the roadmap, not inside
Phase 2.

**Do not quote MT3 numbers for any non-SSH protocol** until this is fixed. The
45-class macro-F1 figures are Cowrie- and netflow-derived and say nothing about
Heralding.

---

## 2026-11-04 — Phase 1b: ZERO-FILL Group D for non-SSH sessions, do not feed it off-domain text

**The question.** `semantic_pca.pkl` (Group D, features 76-105) was fitted on
shell command text. A Heralding/TANNER/Dionaea parser has HTTP request lines, SQL
and credential strings instead. Push them through the shell-fitted projection, or
zero-fill the block? The Heralding parser cannot be written until this is settled,
so it is a design decision, not a post-hoc check.

**Measured, both options.**

What the shell-fitted PCA(30) does to foreign text:

```
text domain                   n   recon err   var kept   z-dist
shell commands (IN-DOMAIN)   60      0.2981     0.9080     0.00
HTTP request lines           64      0.5129     0.7358     1.22
SQL injection payloads       64      0.5946     0.6413     0.92
credential pairs             64      0.5284     0.7135     0.74
```

Reconstruction error roughly doubles; the 30 axes capture 90.8% of in-domain
variance but only 73.6% of HTTP's and 64.1% of SQL's, and the projection sits
~1.2 sigma off the in-domain cloud per dimension.

Where a zero-fill actually lands. This is the part that decided it — the pipeline
zero-fills RAW and then applies the frozen scaler, so raw 0 becomes
`(0 - mean)/scale`, NOT the origin:

```
zero-filled Group D, after the frozen scaler:
  mean |z| over the 30 dims        0.368 sigma
  max  |z|                         1.179 sigma
  dims beyond 2 sigma              0 of 30
  L2 norm of the point             2.400
training Group D (n=20,433, already scaled):
  mean L2 norm of a real row       4.857   (p1 2.201, p99 11.499)
  real rows FARTHER out than it    94.65%
  nearest real training row        1.249 away
  median distance between two real rows  7.725
```

**Decision: zero-fill.** The zero-fill vector is comfortably *inside* the
training distribution — closer to the centre than 94.65% of real rows, with a
genuine training row 1.25 away where typical rows are 7.7 apart. It reads to the
model as unremarkable command text. Off-domain text is the opposite: a shifted
region with a third of its variance destroyed, where the model may latch onto
spurious structure. A known, declared degradation beats a silent distortion, and
the `semantic_available=False` zero-fill path already exists.

**The honest cost.** Zero-filling makes Group D a *constant* for non-SSH
sessions, so it carries no information — those protocols are effectively
classified by 98 of 128 features. That is the price, and it is the right price
until a per-protocol PCA is fitted and MT3 retrained (M2-scale work, not Phase 2).

**Do not read this as "Group D works for HTTP."** It does not. It is switched
off on purpose, and the paper must say so rather than implying 128 live features
on every protocol.

**Implementation note for Phase 2:** the existing flag is global
(`SemanticEncoder.available`), so a protocol-conditional zero-fill needs a new
per-session signal, and `semantic_available` in the result line must be able to
distinguish "DistilBERT missing" from "deliberately off for this protocol".
Reporting both as the same value would hide the decision.

---

## 2026-11-04 — Phase 1 multi-honeypot: parameterise protocol/dst_port, do NOT read them from the log

**Context:** MULTI_HONEYPOT.md Phase 1. `cowrie_parser.build_record()` hardcoded
`dst_port: 22` and `protocol: "ssh"` on every record, which made
`feature_bridge.honeypot_target_for()` return `SSH_HONEYPOT` unconditionally —
the whole `_PROTO_TO_HONEYPOT` / `_PORT_TO_HONEYPOT` table was dead code.

**The obvious fix is wrong.** Reading the real values off the events would shift
MT3's input distribution. Measured today on the training corpus:

```
raw cowrie.json dst_ports:  {2222: 39931, 22: 19, 3306: 21, 443: 17, 80: 13}
what build_record emitted:  22, for every session, always
```

So every Cowrie session MT3 ever trained on carried
`dst_port_norm = 22/65535 = 0.000336` (feature 39). Reading the real port makes
live sessions report 2222 → 0.0339, a ~100x move against a feature the model has
only seen as a constant. It would not raise. It would quietly mispredict. The
parser's own docstring already warned about exactly this ("do not 'improve' it
here, or live inference drifts away from what MT3 was trained on").

**Decision:** `protocol` and `dst_port` are now keyword-only parameters whose
**defaults reproduce the old behaviour byte-for-byte**. Notebook 01 calls
`build_record(events)` with no keywords, so dataset parity holds and live Cowrie
is unchanged. A non-SSH parser passes its own values, which is what finally makes
`honeypot_target_for()` able to answer `WEB_HONEYPOT` / `DB_HONEYPOT`.

Verified: 10/10 real Cowrie sessions still produce `dst_port=22 protocol=ssh`
with the default call; overrides resolve http/8080 → WEB_HONEYPOT, mysql/3306 →
DB_HONEYPOT, postgres/5432 → DB_HONEYPOT.

**Do not "finish the job" by making the defaults read the log.** That is not an
improvement left undone; it is the thing this decision exists to prevent. If the
defaults ever need to change, the model has to be retrained first.

---

## 2026-11-04 — The session contract is executable code, not a document

**Context:** the ~22-key dict every parser must emit was previously implicit in
whatever `build_record()` happened to return. With one parser nothing could
disagree with it. With a second, a missing or misspelled key does **not** raise:
the extractors call `session.get(key, default)` everywhere, so the feature
silently takes a default and one of the 128 features goes quietly wrong.

**Decision:** `honeypot_dataset/src/parsers/session_contract.py` — 22 required
fields and 19 optional ones, with types, a `validate()` that returns a list of
problems, and `assert_valid()` that raises. Prose would have drifted; a test
fails. Enforced by `traffic_gateway/tests/test_session_contract.py`, which
includes negative controls because a check that cannot fail is not a check.

The optional group is the useful half for Phase 2+: `ja3_hash`, `tls_version`,
`sni_hostname`, `cipher_suites` etc. are read by the extractors but never set by
the Cowrie parser, so Group F (features 120-127) is dead for SSH. A TLS-aware web
honeypot can fill them and light those features up for the first time.

---

## 2026-11-04 — N log sources via LogSource, keeping one hardcoded Cowrie path as the default

**Context:** `post_session_pipeline` globbed exactly one directory for
`cowrie.json*` and detected end-of-session by the literal string
`cowrie.session.closed`. Adding a honeypot meant editing the watcher loop.

**Decision:** a frozen `LogSource` dataclass carries `name`, `log_dir`, `glob`,
`session_key`, `is_closed` and `build`. `PostSessionPipeline(sources=[...])`
takes a list; left unset it builds the single Cowrie source from
`cowrie_log_dir`, so every existing caller — `run_pipeline.py`, `main()`, the
demo — behaves exactly as before. Tail state is keyed `f"{source.name}:{path}"`
because two honeypots may write the same filename in different folders.

**Finding worth knowing before Phase 2:** `build_record` is Cowrie-event-specific
well beyond protocol and port. Feeding it Heralding-shaped events
(`auth.attempt`, `session.end`) yields `login_attempts: 0` and
`micro_state: RECON_IP_SCAN`, because it counts only `cowrie.login.failed` /
`cowrie.login.success` and labels from `COMMAND_PATTERNS`. So
`functools.partial(build_record, protocol="http", ...)` is **not** a sufficient
Heralding parser — Heralding needs its own `build` with its own event→micro-state
mapping. The `LogSource.build` hook exists precisely so that is a new function
rather than a change to the Cowrie path.

---

## 2026-11-04 — Ported PIPELINE_SOURCE from 4a6ed19 without its test file

**Context:** commit `4a6ed19` (Anushka, `feature/mitigation-layer`) adds a
`PIPELINE_SOURCE` provenance tag and a `sensor` field to every result line, so
real internet captures, injected demo traffic and lab runs are never pooled into
one statistic. Wanted on `main` for Phase 1.

**Decision:** cherry-pick refused — that commit's
`tests/test_pipeline_mitigation.py` imports `response_mitigation.audit`,
`.config` and `.engine`, none of which exist on `main` (the module there is a
0-byte `__init__.py` plus stale `.pyc` files). The cherry-pick would have added a
test that fails at collection. Ported the `post_session_pipeline.py` half by hand
and wrote the tests in `test_session_contract.py` instead. `sensor` falls back to
the source's own name when the log carries none, and is registered as an optional
contract field so a strict `validate()` accepts it.

## 2026-11-03 — EPSS CORRECTION: every EPSS score the project has produced is a random number

**Finding:** `cve_intelligence/config.py` pointed at
`https://api.first.org/data/1.0/epss`, which FIRST has retired. It now returns
**404 for every CVE**, verified live today against CVE-2021-44228 (Log4Shell):

```
OLD  /data/1.0/epss?cve=CVE-2021-44228  ->  HTTP 404
NEW  /data/v1/epss?cve=CVE-2021-44228   ->  200 OK
     {"cve":"CVE-2021-44228","epss":"0.999990000","percentile":"1.000000000"}
```

That alone would have left EPSS empty. The damage is the fallback —
`analyzers.py:137-141` (pre-fix):

```python
real_epss = fetch_epss_scores(df["cve_id"].tolist())
simulated = simulate_epss(df)
df["epss_score"] = df["cve_id"].map(real_epss)
df["epss_score"] = df["epss_score"].combine_first(simulated).fillna(0.0)
```

`simulate_epss()` draws from **Beta distributions** — Beta(5,2) for KEV entries,
Beta(3,3) for CVSS >= 9.0, Beta(1,8) otherwise. Because the live fetch always
returned nothing, *every* row took the simulated branch, and nothing in the
output marked it as synthetic. Measured on a live run before the fix:
**0 of 517 CVEs had a real EPSS score.** After: **507 scored by FIRST, 10 not
yet scored.**

**Why this matters more than a dead URL:** `ROADMAP.md` 3.4 leads the dataset's
novelty claim with **EPSS drift**. Any EPSS-drift figure computed from this
pipeline is drift in a Beta random walk, not in real exploit-prediction data.
`cve_intelligence/data/trending_profiles.json` (the June 2026 snapshot) has no
`epss_source` field, so its values are most likely simulated too.

**Do not quote any existing EPSS number in the paper.** Recompute from live data
and state the fetch date.

**What this does NOT change:**
- MT3's training data. The Cowrie parser always sets `associated_cve = ""`, so
  the 14 threat-intel features (indices 106-119) are zero for live sessions —
  as they were in training. The model never consumed these scores.
- CVSS, CISA KEV membership, or the NVD CVE records themselves. Only EPSS was
  synthesised.

**Fixed by** Anusha on `frontend-threat-intelligence-anusha` (2026-11-03):
endpoint moved to `/data/v1/epss`; simulation now opt-in behind
`CVE_ALLOW_SIMULATED_EPSS=1` and **off by default**; unscored CVEs get 0.0
rather than a random draw; every profile records `epss_source`
(`first.org` / `unscored` / `simulated`); a failed run logs an ERROR instead of
passing silently. Also found in the same pass: KEV was frozen at 1,675 entries
from `ti_cache.json` (live catalog: 1,766), and `ATTACK_TYPE_PHASES` in
`configurator.py` keyed on labels the classifier never emits
(`"remote code execution"`, `"deserialization"`) while missing brute force, file
inclusion, SSRF and XXE — so no CVE overlay ever matched on live data.

**Still outstanding:** `honeypot_dataset/src/extractors/threat_intel.py` is the
dataset owner's file and still carries the dead URL, a hardcoded 2024-04-15
reference date, and an `epss_7d_delta` that is always 0. The live system routes
around it; the extractor itself needs the same URL fix before any EPSS-drift
claim is recomputed.


## 2026-08-28 — PROVENANCE CORRECTION: the "real Cowrie" data is SYNTHETIC (teammate-confirmed)

**Finding:** The 15,000 Cowrie honeypot sessions previously treated as REAL are
synthetic (generated by a teammate), confirmed by the teammate. Evidence in the
raw `data/raw/cowrie_logs/cowrie.json`: 15,000 unique src_ips for 15,000 sessions
(zero repeat attackers), top IPs all with exactly 83 events, near-uniform username
/password/client-version distributions (real brute-force is heavily power-law
skewed), a clean 2024-03-01→03-30 one-month window, placeholder URLs (evil.com),
and textbook commands mapping 1:1 to the micro-state labels.

**What this changes:**
- **Genuinely real data = CIC-IDS2017 + UNSW-NB15 only** (established real
  network-intrusion datasets). These cover **13 of 45** micro-states, ALL
  network-flow classes.
- The 9 honeypot-command classes that only Cowrie provided now have **no real
  anchor**: PERSIST_SSH_KEY_ADD, EXFIL_STAGING_TAR, DISC_PROC_ENUM,
  EVASION_LOG_WIPE, EVASION_HIST_ERASE, EXEC_WGET_EXEC, EXFIL_SCP_DATA,
  PRIVESC_SUDO_ABUSE, DISC_SUID_HUNT. Real class coverage drops **22 → 13**.
- **There is no real honeypot data in the project.** The honeypot-command
  dimension (Cowrie sessions + their command_text / semantic features) is entirely
  synthetic.
- Explains the quality split: TSTR macro-F1 0.99 on CIC/UNSW (real) vs collapse on
  Cowrie-derived classes (synthetic with tiny sample counts).

**What this does NOT change:**
- The baseline (CNN-LSTM) vs MT3 comparison stays valid — both train on the
  identical frozen dataset; it is a model comparison, not a realism claim.
- CIC/UNSW real data quality and the pipeline/features/schema are unaffected.

**Actions:** relabel Cowrie as synthetic everywhere it is described as real
(dataset_card.json, CLAUDE.md, STATUS.md, ml_analytics/README.md, any paper text).
Honest framing: "real network-intrusion data (CIC-IDS2017, UNSW-NB15) anchoring 13
kill-chain classes, augmented with synthetic honeypot sessions + TabSyn/GReaT to
cover the full 45-class MITRE taxonomy." Future: obtain genuinely real Cowrie logs
(public honeypot datasets or a short live run) to anchor the honeypot classes.


## 2026-08-27 — Freeze the dataset at real + TabSyn for the review; GReaT + all models on DGX

**Decision (user's call):** For the review in ~2 days (CNN-LSTM baseline vs MT3
comparison), FREEZE the training dataset at **real + TabSyn** and skip GReaT for
now. Add GReaT later only if time allows. The three heavy jobs — GReaT fine-tuning,
the CNN-LSTM+DistilBERT baseline, and MT3 — all run on the **college DGX Spark
(GB10)**, not the laptop.

**Why:**
- A baseline-vs-MT3 comparison only needs both models trained/evaluated on the
  SAME frozen dataset. GReaT is +20% additive diversity and (as written) trains on
  real-only data = 22 classes, so it doesn't change the comparison methodology.
- GReaT is ~6-7h on a 24GB GPU and impractical on the 4GB laptop — not worth the
  deadline risk.
- The real critical path is **MT3 (not yet written)**, not GReaT.

**Fallbacks, in order:**
1. Preferred: real + TabSyn, 45 classes (once diffusion + sampling finish + quality
   check passes). Total ~960k (240k real + 720k TabSyn).
2. If TabSyn sampling or quality fails: **real-only** (`X_real.npy`, 22 classes),
   already on disk — a comparison that can start immediately.

**Enabling changes made 2026-08-27:**
- `notebook 05` made **GReaT-optional** (auto-detects `X_great.npy`; assembles
  real+TabSyn with no error when it's absent).
- `tabsyn/tabsyn/sample.py` **batched** (`TABSYN_SAMPLE_BATCH` / `TABSYN_N_SAMPLE`)
  — upstream sampled all 1.39M rows in one ~2.9GB GPU tensor and would OOM the 4GB
  card. Folded into `patches/tabsyn-colab.patch`.

**How to apply:** diffusion finishes -> run TabSyn sampling -> notebook 05 (real+
TabSyn splits) -> transfer the frozen dataset to the DGX -> train CNN-LSTM + MT3
there. GReaT (notebook 04) is deferred; do NOT block the review on it.


## 2026-08-25 — Run the VAE on the ASUS laptop after the Colab crash; add full-state resume first

**Decision (user's call):** After the Colab VAE crashed at ~5h/epoch 111, run a
FRESH 500-epoch VAE on the ASUS laptop itself — explicitly accepting that ASUS is
normally forbidden from local GPU training and is secondary to the DGX (which was
not reachable at the time). Not a resume of the Colab run.

**Why not resume the Colab checkpoint:** the only saved artifact was
`model_epoch0100.pt` = weights only. The beta-annealing schedule (0.01 -> 0.0034 by
epoch 104), the Adam/optimizer state, and the patience counter — all of which drove
val_mse down the staircase — were never saved. Warm-starting from weights alone
resets beta to 0.01 and re-climbs the whole staircase, so it salvages little.

**Why add full-state checkpointing before launching:** a ~30h local run WILL get
interrupted. So `vae/main.py` now saves model+optimizer+scheduler+beta+patience+
best_loss+epoch atomically every epoch to `resume_state.pt`, and resumes from it on
restart (env-var driven; validated 2->4 epoch resume test). Folded into
`patches/tabsyn-colab.patch`. This is exactly what the Colab run lacked.

**How to apply:** the run lives at `tabsyn/vae_run_local/`. To resume after any
interruption, relaunch the same `main.py --method vae --epochs 500
--training_batch_size 512` with the same TABSYN_* env vars — it auto-continues from
`resume_state.pt`. batch=512 is the 4GB-safe size (4096 OOMs); at 512 epoch 1 already
beats Colab's epoch-1 loss because there are 8x more steps/epoch.


## 2026-08-25 — Merge simulated sessions into TabSyn input to cover all 45 classes (reverses the 2026-08-11 "22/45 correct by design" call)

**Decision (user's call, option 3 of 3):** For the Colab overnight VAE run, TabSyn
now trains on **all 45 micro-states**, not 22. `generate_balanced_sessions(180_000)`
produces balanced skeletons for every class; these are merged with the real
extracted features and the pipeline asserts 45 classes before training starts.
**And** the simulated rows get realistic per-micro-state `command_text` (new module
`src/generators/sim_commands.py`) before feature extraction.

**Why the reversal:** The 2026-08-11 entry below ("Data-prep class gap is a scope
question") concluded 22/45 was correct-by-design — TabSyn on the 22 real-anchored
classes, GReaT (notebook 04) on the other 23. Tonight we chose instead to give
TabSyn all 45. The original objection to injecting simulated rows still stands in
part (it dilutes the real-data anchoring), but the user accepted that trade to get
full-class TabSyn coverage now rather than waiting on notebook 04.

**Why the command_text leak fix is mandatory here:** simulated skeletons have no
`command_text`, so without a fix the semantic feature block (group D, indices
76–105 = 30 of 128 features) is all-zeros for every simulated row. TabSyn would
then separate the 23 synthetic-only classes by that all-zero signature — an
artifact, not a learned distribution. `sim_commands.py` fills each row with
realistic MITRE-mapped commands so block D carries genuine per-class signal
(verified: 45/45 classes, all rows non-zero in D, 0 NaN/Inf).

**Known residual caveat:** the 23 synthetic-only classes are still 100% simulator-
derived (no real anchor), and cell 6 oversamples rare classes with replacement to
balance TabSyn's input — so those classes contain duplicated synthetic rows. This
is acceptable for coverage but should be remembered when reading TabSyn quality
metrics for those classes.

**How to apply:** This is the Colab-run policy (notebook `03b_tabsyn_vae_colab.ipynb`).
The local notebook 03 cell 3.1 (22-class prep) was left unchanged; 03b supersedes it
for the 45-class run.


## 2026-08-11 — Patch the vendored TabSyn code directly rather than work around it

**Decision:** Fixed bugs directly inside `tabsyn/tabsyn/vae/main.py` and
`tabsyn/tabsyn/main.py` (the cloned external TabSyn repo) — hardcoded
epoch/batch-size wiring, the 3 unbatched-forward-pass OOM spots, the
`ReduceLROnPlateau(verbose=...)` version-skew crash — rather than writing a
wrapper script around TabSyn that avoided triggering them.

**Why:** All of these are real bugs that would hit *any* run on this hardware,
not just my timing test — the notebook's own design (hardware-aware batch
sizing) only makes sense if the underlying script actually honors the CLI
args it's given, and the OOM bugs would kill epoch 1 of the real run just as
fast as they killed the test. A wrapper/workaround would have meant re-hitting
every one of these the moment the real 500-epoch run started. See ERRORS.md
for the individual writeups.

**How to apply:** If `tabsyn/` is ever re-cloned fresh from upstream, these
fixes will be lost — check ERRORS.md's TabSyn section and re-apply them
before running training again. They're small, targeted diffs, not a fork.

## 2026-08-11 — Data-prep class gap is a scope question, not something to silently patch

**Decision:** Did NOT modify notebook 03's data-prep cell (3.1) to force all 45
classes into the TabSyn training set (e.g. by seeding the 23 zero-coverage
classes with synthetic placeholder rows from `kill_chain_simulator`). Ran it
as-is and flagged the consequence instead.

**Why:** `cell 3`'s oversampling loop only iterates over classes *present* in
`df_input`, so the 23 classes with zero real coverage never enter TabSyn's
training set at all — confirmed via the model's own
`category_embeddings.weight.shape = [22, 4]` (not 45). Whether this is
correct-by-design (TabSyn handles the 22 real-anchored classes; GReaT,
notebook 04, is responsible for the other 23) or a gap that needs fixing now
is a scope decision, not something to guess at silently — especially since
"fixing" it by injecting synthetic placeholder rows into TabSyn's input would
undermine the whole point of using real data to anchor TabSyn's distributions.
**Resolved (2026-08-11, user confirmed):** 22/45 is correct by design. TabSyn
trains on the 22 real-anchored classes only; GReaT (notebook 04) is
responsible for generating the other 23 from scratch. No change to notebook
03's data-prep cell.

## 2026-08-11 — Run the real VAE (and diffusion) training on the college system, not this laptop

**Decision:** Do not kick off the real 500-epoch VAE training on this laptop
despite having a working, bug-fixed pipeline ready to go. Wait until the
college RTX 4500 Ada session.

**Why:** The timing test measured ~140 sec/epoch on this laptop at the correct
batch size (512) → ~19.4 hours for the full 500-epoch VAE run alone, before
diffusion even starts. User's call given that wall-clock cost.

**How to apply:** All the bug fixes made today (see ERRORS.md's TabSyn
section) are in the vendored `tabsyn/` code itself, not laptop-specific
workarounds — they carry over directly to the college run and should NOT need
to be re-discovered there. The one laptop-specific value to swap when moving
to college: batch size. Notebook 03 cell 5's own logic already handles this
(`vae_batch = 4096` when `gpu_mem > 8e9`), and now that the CLI-arg-wiring bug
is fixed, that logic will actually take effect.

## 2026-08-11 — NaN-safety fix goes in the extractors, not just notebook 01

**Decision:** Fixed `src/extractors/temporal.py` and `network.py` to be robust to
`None`/`NaN`/numpy-array inputs, rather than only patching notebook 01's data
construction to make every session dict field-complete.

**Why:** The crash pattern (`session.get(key, default) or default`) fails for two
reasons that are easy to miss: (1) `.get(key, default)` only substitutes `default`
when the key is *absent* — if the key exists with value `None` or `NaN`, `.get()`
returns that value, not the default; (2) the `or` fallback itself breaks down for
`NaN` (which is truthy in Python, unlike `0`/`None`/`""`) and for numpy arrays
(multi-element array truthiness is ambiguous → `ValueError`). Patching only
notebook 01 to always supply every field would work today, but the extractors'
own docstrings claim "all optional — defaults to 0", so any *future* data source
with a different field mix would hit the same crash again. Fixing it at the
extractor level makes that guarantee actually true.

**How to apply:** When adding a new real/synthetic data source, don't assume the
existing extractors will gracefully no-op on missing fields — check ERRORS.md's
list of the 3 fixed crash sites, and if adding new optional session-dict fields,
use the explicit `is None` / NaN-check pattern (see `_safe_int` in `network.py`),
not `.get(key, default) or default`.

## 2026-08-11 — Normalize corrupted CIC-IDS2017 labels rather than hardcode the mangled string

**Decision:** In notebook 01's CIC-IDS2017 loading cell, added a text-normalization
step (`str.replace("�", " ", ...)` + whitespace collapse) before mapping
labels through `CIC_LABEL_MAP`, instead of adding the literal `U+FFFD`-containing
strings as extra keys in the map.

**Why:** The raw CSV's "Web Attack" labels contain a mis-encoded separator
character that reads back as `U+FFFD` (replacement character) — this is a known
CIC-IDS2017 dataset quirk, not something specific to how we're reading it.
Hardcoding the mangled byte sequence as a dict key is fragile (depends on the
exact encoding round-trip) and unreadable in source. Normalizing the text first
means `CIC_LABEL_MAP` stays a clean, human-readable mapping.

**How to apply:** If CIC-IDS2017 is re-downloaded or re-exported and label text
looks different again (e.g. actually has an en-dash instead of the replacement
char), the normalization step already collapses any separator+whitespace
variation, so it should keep working without map changes.

## 2026-08-11 — Fix UNSW `'Backdoors'` → `'Backdoor'` at the map, not the data

**Decision:** Changed the key in `UNSW_LABEL_MAP` from `"Backdoors"` (plural) to
`"Backdoor"` (singular) to match the actual `attack_cat` values in
`UNSW_NB15_training-set.csv` / `testing-set.csv`.

**Why:** This was a straightforward typo in our own map, not a data quirk —
verified the real column has `'Backdoor'` singular. No reason to touch the
source CSVs.

## 2026-08-11 — Reinstall torch as CUDA build, don't try to work around CPU-only

**Decision:** Uninstalled/replaced the venv's `torch==2.13.0+cpu` with
`torch==2.13.0+cu126` rather than trying to run VAE training on CPU "just to get
a number."

**Why:** A CPU-only timing run would be meaningless for planning the real 500-epoch
VAE training — the whole point of the timing test is to estimate GPU wall-clock
time on the RTX 3050. The driver (CUDA UMD 13.3) supports it, and `pip index
versions torch --index-url .../cu126` confirmed a matching wheel exists for this
exact torch version and Python 3.14. See HARDWARE.md for the verified working
versions.

## 2026-08-11 — Do VAE-only today, defer diffusion to a separate session

**Decision (user's call, recorded for continuity):** Run notebooks 01→02→(TabSyn
VAE only) today; do NOT run the diffusion stage (`Stage 2/3` in notebook 03 cell 5)
in this session.

**Why:** VAE + diffusion combined is a long, expensive run (500 + 2000 epochs
per the notebook's own config). Splitting it lets us validate each stage
independently — confirm the VAE converges and produces sane output before
spending the much larger diffusion compute budget on top of it.

**How to apply:** Don't auto-chain into diffusion training after VAE completes,
even though notebook 03 cell 5 is written to run both stages back-to-back
(`run_tabsyn_step("vae", ...)` then `run_tabsyn_step("tabsyn", ...)`). Either run
the VAE step in isolation (call `main.py --method vae` directly) or edit the cell
to stop after Stage 1 until diffusion is explicitly greenlit.

## 2026-08-28 — Adversarial AUC ~0.998 is a benign pipeline fingerprint, not poor fidelity

Full analysis in `FIDELITY_ANALYSIS.md`. Summary: real-vs-real control = 0.50
(metric is calibrated), so the ~0.998 is real signal; it is NOT from the synthetic
Cowrie (CIC/UNSW-only = 0.9979) and is stamped at BOTH the VAE round-trip (AUC 1.0)
and the diffusion latent stage (AUC 1.0), VAE-first. It lives in fine joint
structure — marginals match to ~3 decimals, VAE MSE 0.0008 — so downstream utility
is strong (TSTR macro-F1 0.99 on real CIC/UNSW classes). Report utility (TSTR), not
adversarial AUC alone, as the fidelity metric. Distinguishable != not useful.
