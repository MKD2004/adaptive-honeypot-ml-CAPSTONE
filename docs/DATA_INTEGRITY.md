# Data integrity: what is wrong with the dataset, and the fix

Written 2026-11-11 (ASUS). **This is the handoff document for the rebuild work.**
It is self-contained: the measurements are repeated here rather than
cross-referenced, so a session starting cold can act on it.

The short version: **35% of the 128-feature input carries no information, 47% of
the TabSyn rows are arithmetically impossible, and the 45-class taxonomy is
exercised by 8 classes in real traffic.** None of it was ever detected, because
nothing checked. Every published number was measured on this data.

Three findings, in sections 1, 2 and 3d. The first two are data defects and are
fixable. The third is a scope problem and needs a decision, not a repair.

---

## 1. Finding one — 45 of 128 features are constant

Measured on 18,900 rows sampled from `X_train` (every 40th), un-scaled back to
raw units. A feature with three or fewer distinct values across 18,900 sessions
cannot inform a classifier.

| group | dead / total | what is dead |
|---|---|---|
| A_temporal | **5 / 24** | `burst_count`, `burst_mean_size`, `frac_sub100ms`, + 2 |
| B_network | **13 / 28** | roughly half the flow descriptors |
| C_payload | **5 / 24** | feats 60, 61, 68, 74 + 1 |
| D_semantic | 0 / 30 | nothing — the DistilBERT block is healthy |
| E_threat_intel | **14 / 14** | **the entire group** |
| F_tls_host | **8 / 8** | **the entire group** |
| **total** | **45 / 128 (35%)** | |

Two whole branches of the architecture are dead:

- **`E_threat_intel` (14/14).** These come from live NVD / EPSS / CISA-KEV
  lookups keyed on a CVE. Synthetic sessions carry `associated_cve: ""` — the
  generator never assigns one — so every lookup returns defaults. Thirteen of the
  fourteen are constant 0.
- **`F_tls_host` (8/8).** JA3 fingerprints and TLS version. Cowrie is an SSH
  honeypot; there is no TLS handshake to fingerprint, so the group is structurally
  empty for every row in the dataset.

MT3's 3,759,510 parameters are therefore reading **83 informative features, not
128**, and the paper's "six-group multi-branch architecture" has two branches
consuming constants.

### Why the temporal five were dead specifically

The generator emitted `t_start`, `t_end` and `n_events` but **no per-event
timestamps** — it produced one summary row per session, never an event stream.
There was no aggregation step that lost them; the events never existed.

`extractors/temporal.py` then takes a fallback branch when `event_timestamps` has
fewer than two entries:

```python
iat = np.array([duration / max(n_events - 1, 1)])    # ONE value
```

A single value has no spread, no shape and no runs, so `iat_std`, `iat_cv`,
`iat_skew`, `iat_kurt`, `burst_count`, `burst_mean_size`, `frac_sub100ms` and
`inter_burst_gap_std` all collapse. The signature is unmistakable in the frozen
data: `burst_count` takes exactly the values `{0.0, 1.0}` — 1.0 in the 67 of
18,900 rows where that single synthetic gap happened to fall under 100 ms.

**This is fixed in the generator as of `f9fa918`** (per-event timestamps
calibrated to 283,432 real inter-arrival times). It is *not* fixed in
`data/final/`, which is untouched.

## 2. Finding two — 47% of TabSyn rows are mathematically impossible

`X_test_synth` is TabSyn output only; `X_test_real` is real-derived only. The
contrast is the finding:

```
                 iat_min != iat_max      iat_cv == 0      BOTH (contradiction)
X_test_real              1.9%               98.1%               0.0%
X_test_synth            48.6%               98.4%              47.0%
```

A row cannot have varying gaps (`min != max`) and zero coefficient of variation
at the same time. An actual row from the frozen test set:

```
iat_min 14.9016   iat_mean 17.8319   iat_max 17.4825
iat_std -0.0000   iat_cv  0.0000     burst_count -0.0
```

`iat_mean` (17.83) **exceeds `iat_max`** (17.48). A mean cannot be larger than a
maximum. `iat_std` is negative zero. No session, real or simulated, can produce
this row.

**Cause.** TabSyn models each column's marginal distribution and the joint
structure it can learn from data, but it has no knowledge of the *arithmetic
identities* between columns — that `iat_cv = iat_std / iat_mean`, that
`iat_min <= iat_mean <= iat_max`, that a fraction lies in `[0, 1]`. Handed a
temporal block where most columns were constant zero, it emitted independent
continuous values that violate their own definitions.

**So the two findings compound.** Finding one made the columns degenerate;
finding two means the generative model trained on those degenerate columns
produced 720,000 rows (75% of the dataset) with incoherent temporal blocks.

## 3. Why continuing on this data makes it worse

- Every retrain inherits 45 constant inputs and 47% incoherent synthetic rows,
  so no architecture change can be evaluated fairly. A negative result cannot be
  distinguished from a data defect.
- The headline comparison — MT3 (3.76M params) tying a CNN-LSTM (190k) on
  `test_real` — is **unsafe to interpret**. With 35% of the input constant and
  two branches dead, the finding may be an artefact of starved inputs rather than
  evidence about fusion architectures.
- It is already producing visible failures: on the first real capture MT3 agreed
  with the rule labeller on 23.3% of sessions and sat 226x outside its training
  distribution (`REAL_DATA_2026-11-09.md`).
- Each additional honeypot protocol multiplies the problem before the
  single-protocol case works.

**Nothing here invalidates the work.** It invalidates the *numbers*, which is
recoverable, and the diagnosis is specific enough to fix.

---

## 3b. The validator has been written and run — full damage report

`src/validators/feature_integrity.py` (Part 3 below) exists as of 2026-11-11,
with 25 tests. Run against every frozen split. **It found a defect class the
hand analysis missed.**

```
split          impossible-row checks failed   constant columns
X_train                  13 of 97                  50 / 128
X_val                    16 of 97                  50 / 128
X_test_real               0 of 97                  52 / 128
X_test_synth             14 of 97                  50 / 128
```

**`X_test_real` passes every arithmetic check; `X_test_synth` fails 14.** That
is the cleanest confirmation available that the defect is TabSyn's and not the
extractors': real-derived rows are internally coherent, generated ones are not.
Nothing in the validator was built to make that distinction.

### The new finding: every log1p pair is broken

I had only found the inter-arrival incoherence by hand. The validator shows the
same failure in a second, larger class — **every `log1p` derived feature is
generated independently of the primitive it is supposed to be a function of**:

```
broken log1p pairs, share of TabSyn rows
  log_session_duration == log1p(session_duration_s)    42.7%
  log_bytes_in         == log1p(bytes_in)              30.7%
  log_bytes_out        == log1p(bytes_out)             28.0%
  log_pkts_in          == log1p(packets_in)            22.9%
  log_pkts_out         == log1p(packets_out)            9.8%

incoherent inter-arrival summary
  spread implies cv > 0                                48.2%
  iat_mean <= iat_max                                  23.3%
  iat_min  <= iat_median                               22.9%
  iat_median <= iat_max                                16.2%
  iat_min  <= iat_mean                                 12.5%
  iat_cv   == iat_std / iat_mean                        1.5%

other
  mean_pkt_size_in <= max_pkt_size_in                   6.0%
```

Five of the 128 features are *pure functions of another feature in the same
row*, and TabSyn was asked to generate both sides. It is the clearest possible
case for Part 2's primitive/derived split: those five should never have been
generated at all, only computed.

### A false-positive bug in the validator, and the lesson

The first run reported `commands_per_min >= 0` failing on **99.3%** of
`X_test_real`, plus negative `bytes_in`. Both were wrong. `data/final/*.npy` is
stored as **float32** and un-scaled by a `StandardScaler`, so a value that was
exactly 0.0 returns as `±eps32 × scale_`; for `commands_per_min`, `scale_` is
157.8, giving a residue near 1.9e-5 — a hundred times the 1e-6 epsilon I used.
Every one of those 59,558 "negative rates" was a true zero.

Tolerances are now per-column, derived from the scaler and the storage dtype
(`tolerance_from_scaler`). **A validator that cries wolf is worse than none**,
because a false positive is indistinguishable from a finding until someone
checks. Any new invariant must be tested against a float32 round-trip of
coherent data — `test_a_float32_round_trip_does_not_look_like_breakage` does
exactly that.

### What is still unmeasured

- **`D_semantic` (30 PCA dims) has no invariants**, because a PCA projection has
  none to state. It is also the one group with no constant columns, so it is
  probably the healthiest part of the matrix.
- **The remaining constant columns need triage**, not just counting: 50 of 128 is
  the headline, but some are legitimately constant for an SSH-only corpus
  (`tcp_*` flags without packet captures, every `F_tls_host` feature). The
  allow-list in `EXPECTED_CONSTANT` currently holds exactly one entry. Working
  through the other 49 and deciding *drop / fix / allow* for each is the next
  concrete task, and it decides the real feature count for the paper.

---

## 3c. Triage of the constant columns — done, 0 untriaged

Every constant column now carries a decision, encoded in
`feature_integrity.TRIAGE` so the validator reports progress instead of someone
re-deriving it. `triage_summary()` returns an `UNTRIAGED` bucket and a test
asserts it is empty, so a newly-dead column fails the build until decided.

**The count moved first.** The dead-column check also failed any column with
fewer than four distinct values, which flagged every legitimately **binary**
flag — `is_ssh_port` at a healthy 54/46 split was reported dead three times.
The rule is now modal share alone (>98%). **46 columns, not 51.**

```
UNTRIAGED    0
FIX         14      the input exists; something upstream is not using it
DROP        26      cannot exist here, or would cause a train/serve mismatch
ALLOW        6      constant for one SSH honeypot; informative with a second
```

**The decision rule was availability in the real capture, measured:**

```
key in a real parsed record    rows with a value      feeds
t_first_auth / t_first_cmd     11,328 / 11,328        time_to_first_*
src_ip                         11,328 / 11,328        geo_risk_score, repeat_visitor
src_port                       11,328 / 11,328        src_is_ephemeral
associated_cve                      0 / 11,328        all 14 E_threat_intel
pkt_sizes_in, tcp_flags             absent            std_pkt_size_in, tcp_*
ja3                                 absent            F_tls_host
```

### FIX — 14

| feature(s) | why it is dead |
|---|---|
| `iat_std`, `iat_cv`, `iat_skew`, `iat_kurt`, `frac_sub100ms`, `frac_over30s`, `burst_count`, `burst_mean_size`, `inter_burst_gap_std` | the single-IAT fallback. **Already repaired in `f9fa918`**; populates on rebuild |
| `time_to_first_auth_s`, `time_to_first_cmd_s` | real records carry `t_first_auth`/`t_first_cmd` in every row; **the generator never emits them** |
| `src_is_ephemeral` | **the generator emits no `src_port` at all**, so the flag defaults to 0. Secondary question for the rebuild: the extractor tests `src_port > 49151` (IANA dynamic floor) while 98.3% of real ports are ephemeral by the Linux definition (>= 32768), so real samples like 34958 read as non-ephemeral |
| `geo_risk_score`, `attacker_repeat_visitor` | both computable from `src_ip`, which every real record has — 641 real source addresses, top talker 3,527 connections |
| `rle_compression_ratio` | **an extractor bug.** `min(1.0, n_runs*2/len)` saturates at 1.0 for *any* text — measured 1.0000 on every real command, 0.1 only on the 260-char `AAAA` probe. Drop the factor of 2 |
| `is_business_hours` | derived from a **fabricated shared timestamp**: `session_hour` is 98.1% at hour 22 and `session_day_of_week` 98.3% at day 1 across 60,000 real-derived rows, because the netflow rows were all given one `t_start`. The honeypot capture has genuine timestamps over 8 days |

### DROP — 26

**All 14 of `E_threat_intel`.** `associated_cve` is empty in **100% of real
sessions**. Populating it only in synthetic data would train the model to lean
on a block that is all-zero at inference — a train/serve mismatch, which is
*worse* than a dead feature. Revive only if a CVE can be inferred from observed
behaviour for both real and synthetic sessions.

**Six of `F_tls_host`** (`ja3_hash_bucket`, `ja3_is_known_malicious`,
`tls_version_num`, `cipher_suite_count`, `cipher_suite_entropy`,
`sni_domain_entropy`). SSH has no TLS handshake to fingerprint. Structurally
unavailable until a TLS-speaking honeypot exists. *(The other two —
`geo_risk_score`, `attacker_repeat_visitor` — are FIX, since they key on
`src_ip`, not TLS.)*

**Six packet-level features** (`std_pkt_size_in`, `pkt_size_entropy_in`,
`tcp_syn`, `tcp_ack`, `tcp_fin`, `tcp_rst`). Cowrie is application-layer and
emits no packet sizes or TCP flags. The CIC/UNSW flow rows *do* carry them, so
populating these would make them alive for 13 netflow classes and dead for the
other 32 — the same mismatch as the threat-intel block, reached by a different
route.

### Update 2026-11-14: E_threat_intel had a SECOND cause, now verified

`fix/threat-intel-epss` was merged (`8974273`, Anusha). It does **not** change
the DROP decision, and it explains it better.

The branch records that `src/extractors/threat_intel.py` called FIRST's
**retired** `/data/1.0/epss` path. Verified directly rather than taken on trust:

```
https://api.first.org/data/1.0/epss  ->  HTTP 404   (every CVE)
https://api.first.org/data/v1/epss   ->  HTTP 200   (1 record)
```

So `E_threat_intel` was dead for **two independent reasons**: no producer ever
attaches an `associated_cve` (all three hard-code `""`), *and* even an attached
CVE would have hit a 404. Either alone is sufficient.

Her fix covers the **live** path only (`traffic_gateway/feature_bridge.py`, now
routed through `cve_intelligence`'s CISA and FIRST v1 clients). The **dataset**
extractor was untouched; its endpoint is corrected to `v1` here. She also found
that `get_kev_set()` returns its `ti_cache.json` copy forever once one exists, so
the KEV list was frozen too.

**Two consequences for the rebuild:**

- **The live and dataset paths now fetch threat intel differently** — live via
  `cve_intelligence`, dataset via the extractor. That is a train/serve skew
  waiting to happen if threat intel is ever revived. Converge them first.
- **EPSS scores move daily, so a build that reaches the live API is not
  reproducible.** `ti_cache.json` exists for exactly this; pin and commit a
  snapshot before generating a dataset anyone will cite. `epss_drift.py` already
  assumes a fixed baseline.

The 14 features stay DROPped. Reviving them requires solving CVE *attribution*,
which is the hard half and which nothing currently attempts.

### ALLOW — 6

Constant today, genuinely informative once a second protocol lands. Keep in the
schema, **exclude from training until they vary**:
`is_wellknown_port` (always 1 on port 22), `is_db_port` (no database honeypot),
`unique_dst_ports` (single-port honeypot), `frac_url_encoded` (no web honeypot).

Plus two that are constant because that is simply true of shell text:
`frac_printable` (commands are printable), `frac_null_bytes` (no null bytes).

### What this adds up to

```
informative features today            82 of 128
after the 14 FIXes                    96
schema size if the 26 DROPs go       102
```

**So the honest architecture claim after the rebuild is ~96 informative features
of a 102-feature schema, not 128 of 128** — and `E_threat_intel` and most of
`F_tls_host` disappear as branches. Two of the six feature groups do not survive
contact with an SSH-only corpus. That is a paper-level change to the
contribution, and better to state it than to have a reviewer find it.

---

## 3d. Finding three — the 45-class taxonomy is far wider than anything observable

Asked 2026-11-11: *can a real attack sequence exist that is not one of the 45
classes, and what happens to it?* Yes, in three distinct ways. Measured on all
45,648 real sessions.

### What real traffic actually uses

```
25,256  55.3%  DISC_ENV_PROBE      genuine pattern match (uname / whoami / id)
12,995  28.5%  ACCESS_BRUTE_SSH
 4,354   9.5%  EXEC_SHELL_OPEN     <- THE CATCH-ALL, i.e. matched no rule
 2,914   6.4%  RECON_IP_SCAN
   100   0.2%  EXEC_WGET_EXEC
    23   0.1%  EXFIL_SCP_DATA
     5   0.0%  EVASION_HIST_ERASE
     1   0.0%  DISC_PROC_ENUM

8 of 45 labels ever used.  The top 4 cover 99.7% of all real traffic.
```

A trap worth naming, because it nearly went in this document the wrong way round:
`DISC_ENV_PROBE` at 55.3% is a **real match** on `\b(uname|hostname|id|whoami|cat
/proc)\b`, not a default. The catch-all is `EXEC_SHELL_OPEN`. Check which label a
labeller falls through to before reading anything into its distribution.

### Three ways an attack escapes the taxonomy

**1. The taxonomy has no slot at all.** Of the 45 labels exactly one mentions
web or HTTP (`ACCESS_BRUTE_HTTP`). There is no SQL-injection class, no
database-auth class, no SMB class. A SQLi attack against SNARE has nowhere to go.
This is `MULTI_HONEYPOT.md` section 7.1, and it is why Dionaea and SNARE traffic
can be *collected* but not honestly *labelled* today.

**2. Unrecognised behaviour inside SSH — and this one has a number.** 4,354
sessions, **9.5% of the real capture**, matched none of the 15 command rules and
fell into the catch-all. That is the measured "does not fit" rate.

**3. It is not an attack at all.** The benign problem, `02-11-2026 FINDINGS.md`
finding #1.

### What the model does with them today

MT3's softmax over 45 classes sums to 1. There is no "none of the above" output,
so **every input is forced into one of the 45 and the model cannot signal that it
does not recognise the input.** Measured:

```
bare TCP connect, no login attempt   -> DISC_NETSTAT_SCAN   confidence 1.000
benign `df -h ; free -m`             -> DISC_PROC_ENUM      confidence 0.995
real `uname` fingerprinting          -> EVASION_HIST_ERASE
```

**A confidence threshold cannot catch this, and that is measured, not assumed:**
benign sessions span 0.301-0.995 while real attacks span 0.637-0.828. The wrong
answers are the confident ones. This is the same wall as the Heralding gate
(`HONEYPOT_AUDIT.md` PART 7) and the benign corroboration work -- three separate
problems, one root cause.

### What to do about it, cheapest first

1. **Predict the phase before the micro-state.** MT3 already has an auxiliary
   phase head. Nine phases is a coarser and far more robust target, and a novel
   attack often still has a recognisable phase even when the micro-state is
   wrong. No new data, machinery already present.
2. **Bootstrap an UNKNOWN class from the capture.** The 4,354 catch-all sessions
   are candidate examples. That builds the class from observed traffic rather
   than inventing it, and it only became possible once real data existed.
3. **Distance-based rejection -- but only after the rebuild.** The Mahalanobis
   measurement in this document is computed in INPUT space, which is the weak
   form; the standard approach uses the model's penultimate representation. It
   is unusable today regardless, because training data sits 226x from live data
   so everything looks novel. It becomes meaningful once that gap closes.
4. **Use the disagreement already available.** MT3 against the rule labeller
   disagreeing is a free novelty signal, computable today, and the pipeline
   already logs both.

### 13-day update (2026-11-14): more data, same coverage

A second capture arrived: **114,490 sessions from 1,071 source IPs over 13 days**
(2026-11-01 to 11-13, 754,063 events, 0 unparseable lines), superseding the
45,648-session one. It is 2.5x the data and it produced **zero new micro-states**.

```
                              sessions
ACCESS_BRUTE_SSH   phase 1     52,748     \
DISC_ENV_PROBE     phase 3     45,711      |  the only four above the frozen
RECON_IP_SCAN      phase 0      8,891      |  dataset's own 2,000-per-class floor
EXEC_SHELL_OPEN    phase 2      6,996     /
PRIVESC_SUDO_ABUSE phase 4        532
EXEC_WGET_EXEC     phase 2        137
DISC_NETSTAT_SCAN  phase 3         11
EVASION_HIST_ERASE phase 6          6
EXFIL_SCP_DATA     phase 8          2
DISC_PROC_ENUM     phase 3          1
```

| | 8-day capture | 13-day capture |
|---|---|---|
| sessions | 45,648 | **114,490** |
| source IPs | 641 | 1,071 |
| micro-states obtained | 8 | **8** (9 by deepest-phase) |
| classes above 2,000 sessions | 4 | **4** |

**The mix shifted — brute force overtook environment probing — but the coverage
did not move at all.** That is the finding: *collecting Cowrie for longer does not
broaden the taxonomy.* Only more protocols will. It is now measured rather than
assumed, and it is the strongest argument available for the Heralding / SNARE /
Dionaea work in `MULTI_HONEYPOT.md`.

Supporting counts from the same capture: 31,702 distinct command strings, of
which **38,404 uses (45%) match none of the parser's 15 command rules** and fall
through to `EXEC_SHELL_OPEN`. Of the 16 labels the labeller can emit, 8 never
fired at all — no `crontab` persistence, no `authorized_keys` injection, no
Python or Perl droppers, no log wiping, no SUID hunting. Generous keyword probing
across all 45 classes finds traces of 11; another 25 are not SSH-shell behaviours
in the first place.

### Two labelling defects this exposed

**1. The session label discards the deepest behaviour.** `build_record` assigns
`meaningful[-1]` — the LAST non-recon label in the sequence. Botnet scripts end
with `uname`, so a session that escalates privileges and then fingerprints is
filed as `DISC_ENV_PROBE`. `PRIVESC_SUDO_ABUSE` appears in 532 sessions and
reached the final label in **zero** of them. Labelling by deepest kill-chain
phase instead recovers it and raises coverage from 8 classes to 9. The per-command
detail was never lost — it is in `micro_state_sequence` — only the single label
throws it away. **Switching the rule is a one-line change and should be made
during the rebuild.**

**2. `file_upload` was mapped to exfiltration — FIXED.** Cowrie logs
`cowrie.session.file_upload` when the **attacker pushes a file TO the honeypot**:
a dropper, an implant, a miner. That is MITRE **T1105 Ingress Tool Transfer**, a
tool coming *in*. It was mapped to `EXFIL_SCP_DATA` — **T1048.002, "Exfiltration
Over Asymmetric Encrypted Non-C2 Protocol", phase 8** — which inverts the
direction of the transfer and files routine malware delivery as the deepest stage
of the kill chain.

It also hid finding 1: because phase 8 outranks everything, those 574 sessions
masked the phase-4 `PRIVESC_SUDO_ABUSE` that 532 of them contained. The botnet
uploads its implant *and* sudo-chmods it, and the wrong label won.

Now mapped to `EXEC_WGET_EXEC`, which already carries T1105 and phase 2 and is
where `file_download` goes, so both directions of tool transfer agree. Effect on
the capture:

```
                        before    after
EXFIL_SCP_DATA (label)     574        0
PRIVESC_SUDO_ABUSE           0      532   (deepest-phase)
EXEC_WGET_EXEC             100      137
distinct, deepest-phase      8        9
```

**Consequence worth stating plainly: no real session now maps to any `EXFIL_*`
class.** That is correct rather than a regression — Cowrie's event set carries no
signal for data *leaving* the honeypot, so all five exfiltration micro-states have
no real support and rest entirely on synthetic data. The two sessions that still
label `EXFIL_SCP_DATA` typed an actual `scp` command, which is genuine.

### The part that matters more than the open-set question

Two numbers a reviewer will go straight for:

- **The rule labeller can only ever emit 16 of the 45 labels.** 29 classes are
  unreachable by construction -- they have never been assigned to a real session
  even in principle, and exist only in data we generated ourselves.
- **Real traffic puts ~99.7% of its mass in 4 classes**, and that held across
  both captures: 45,648 sessions and 114,490 sessions gave the same four.
- **Five `EXFIL_*` classes have no real support at all**, now that implant
  uploads are correctly labelled as ingress tool transfer.

So the sharper problem is not "some attacks fall outside the 45". It is that the
taxonomy is far richer than anything we can currently observe or label, and 37 of
its classes rest entirely on synthetic data. A 45-class result measured on data
that exercises 8 classes is a threat to validity on its own.

**Report coverage rather than claiming the taxonomy.** "The taxonomy covers N% of
observed real traffic, with M classes anchored only in synthetic data" is
defensible and checkable. "45-class real-world attack classification" is not, on
this evidence.

Note the asymmetry this creates with the frozen dataset, which is balanced to a
minimum 2,000 sessions per class: the rarest real class here has **one** session.
Balanced synthetic training against 99.7%-in-4-classes reality is itself a
distribution mismatch, separate from the feature-level one in section 1.

---

## 4. The fix — three parts, in dependency order

### Part 0 (first, ~1 hour) — make the silent failure loud

The root cause of all of this is that the extractor **silently substituted a
fabricated value** for missing input. Fix that before anything else, or the next
pipeline will find a new way to do the same thing.

In `extractors/temporal.py`, the `len(ts_list) < 2` fallback must stop inventing
a single gap. Options, in order of preference:

1. Return `np.nan` for the eight features that genuinely cannot be computed, and
   let the validator in Part 3 reject the row.
2. Raise, if the caller is supposed to guarantee timestamps.

What it must **not** do is emit zeros that are indistinguishable from measured
zeros. Apply the same rule to every extractor: *a feature that cannot be computed
is missing, not zero.*

### Part 1 — generate logs, not features

**Principle: synthetic data and real data must travel the same path.** Real
sessions go `events -> cowrie_parser -> extractors -> 128-d vector`. Synthetic
sessions currently skip to the end and write feature-adjacent scalars directly,
which is how they ended up inconsistent.

**There is already a correct precedent in this repo.**
`src/generators/heralding_simulator.py` writes `log_session.json`-format records —
exactly what real Heralding emits — specifically so they pass through the same
`heralding_parser.build_record` as live traffic. Its docstring says so. Follow
that pattern.

So: `kill_chain_simulator.generate_balanced_sessions()` should emit **Cowrie-format
event dicts** (`cowrie.session.connect`, `cowrie.login.*`, `cowrie.command.input`,
`cowrie.session.closed`), then run `cowrie_parser.build_record()` and
`pipeline.extract_all()` over them. Consequences:

- Derived features are **computed, never generated**, so Finding Two cannot occur
  for this source by construction.
- The real capture becomes the calibration target for event *content* as well as
  timing — commands, credentials, byte counts, upload/download events.
- `associated_cve` can be assigned per micro-state, which brings
  `E_threat_intel` to life (14 features). This is the single largest information
  gain available.
- `F_tls_host` stays structurally empty for SSH. **Decide explicitly:** either
  drop the group and document a 120-feature schema, or populate it only when a
  TLS-speaking honeypot exists. Leaving 8 constant features in while calling the
  architecture six-group is the kind of claim a reviewer will check.

The 2026-11-11 timing fix is a down payment on this: timestamps now exist, so the
extractor no longer takes the fallback. `bytes_in`, `n_commands` and the rest are
still written directly.

### Part 2 — make TabSyn generate primitives, not derived features

TabSyn is tabular; Part 1 cannot fix it. Do not ask it to generate values it
cannot keep consistent.

**Split the schema into primitive and derived**, declared once in
`configs/schema.py` so there is a single source of truth:

- **Primitive** — independently meaningful: `n_events`, `session_duration_s`,
  `t_start`, `bytes_in`, `bytes_out`, `n_commands`, port/protocol encodings, the
  30 PCA semantic dims.
- **Derived** — a deterministic function of primitives or of an underlying
  sequence: `iat_*` (all eight), `burst_*`, `frac_sub*`, `inter_burst_gap_*`,
  `log_session_duration`, `events_per_sec`, `commands_per_min`.

Then: TabSyn generates **primitives only**; a post-processing step synthesizes an
inter-arrival sequence consistent with the generated `n_events` and
`session_duration_s` (reuse `generate_event_timestamps`, which is already
calibrated to real data), and **recomputes every derived feature** through the
same extractor real data uses.

Two wins beyond correctness: TabSyn has ~40 fewer columns to model, which usually
improves fidelity, and contradictions become structurally impossible rather than
merely unlikely.

### Part 3 — a validator that fails the build

`src/validators/quality_checks.py` already covers shape, class balance,
Wasserstein distance, adversarial AUC and a TSTR baseline — all *distributional*.
None of it would catch either finding. Add a new module,
`src/validators/feature_integrity.py`, wired into `run_full_validation()`, that
**raises** rather than reports:

1. **Arithmetic invariants.** `iat_min <= iat_mean <= iat_max`; `iat_std >= 0`;
   `iat_cv == iat_std / iat_mean` within tolerance; every `frac_*` in `[0, 1]`;
   counts non-negative and integral; `burst_count <= n_events - 1`;
   `log_session_duration == log1p(session_duration_s)`. Derive the list
   mechanically from the primitive/derived split in Part 2 — every derived
   feature gets a check, by construction.
2. **Dead-column detection.** Fail on any feature with fewer than N distinct
   values, or more than X% identical values, outside an explicit allow-list of
   deliberately-constant features. **This check alone would have caught the
   original bug**, and it is about twenty lines.
3. **NaN / inf**, including the honest NaNs introduced by Part 0 — those must be
   resolved or the row dropped before training, never silently zero-filled.
4. **Drift against a real reference.** Per-feature standardised distance from the
   real capture, failing beyond a threshold. The Mahalanobis measurement in
   `traffic_gateway/feature_bridge.py:TrainingDistribution` is a working starting
   point (real sessions measured 226x the training p95).

Make it a **gate at the training entry point**, not an optional notebook cell. A
report nobody runs is how this survived three months.

---

## 5. The plan (agreed 2026-11-14)

Owner's five-point plan, with the sequencing and gaps worked through. Items 1, 2
and 5 are the owner's wording and are kept as written; item 3 was already done
and item 4 moved.

### Start immediately and in parallel: Heralding collection

**DONE — live since 2026-11-14 19:07 UTC.** Anusha deployed it on the Oracle VM
alongside Cowrie: 8 services, first real attacker 51 minutes in, ~150 sessions in
the first hour, planned stop on or after 2026-11-29. Her report is
`Heralding_deployment_update.md`; it lists seven errors in our runbook that she
had to fix on the VM, including one that would have silently enabled the mysql
and postgres sensors the runbook says must stay off.

Our side is verified ready: the parser produces a contract-valid record from the
exact session she observed, with the naive-UTC timestamp converted correctly.
**Two sessions-worth of data hygiene must survive until the archive arrives** —
exclude `171.76.81.68` between 19:07 and 19:58 UTC on 11-14 (her own tests), and
expect a cluster of `num_auth_attempts: 0` FTP sessions from the Windows client's
`OPTS UTF8 ON`.

**The only wall-clock-bound item.** Real traffic accrues over weeks and no amount
of effort speeds it up, so it must not wait behind laptop work. See
`ANUSHA_HERALDING.md` for the deployment runbook and `MULTI_HONEYPOT.md` section
6 for the Track A / Track B split this follows.

Heralding only. **SNARE/TANNER and Dionaea wait** — see step 5.

### 1. Part 0 — make silent failures loud (about an hour)

Extractors must return `NaN` or raise when an input is missing, never substitute
a fabricated value. This is the root cause of findings one and three and the
cheapest item on the list. Do it first or the next pipeline finds a new way to do
the same thing.

### 2. Session-level aggregation, and the manually reviewed evaluation set

These two unlock measurement, so they come before anything that needs measuring.

**Aggregation.** Keep the full event sequence, the detected states, the primary
label and the phase as **separate fields**. Define how the primary label is
selected and test it against known scenarios. Two mechanical notes:

- Keep `micro_state` as the primary-label field and ADD the others.
  `feature_bridge`, `post_session_pipeline` and the dashboard all read that name;
  renaming it is a live-pipeline change for no benefit.
- Add the new fields to `session_contract.py` **and its tests**, or they become
  silently optional and the next parser omits them.

Measured motivation: the current rule takes `meaningful[-1]`, the last non-recon
label, so `PRIVESC_SUDO_ABUSE` appears in 532 sessions and reaches the final
label in zero. Deepest-phase labelling alone raises coverage from 8 classes to 9.

**The evaluation set** is the highest-value item in the whole plan, because it is
the only thing that turns "23.3% agreement with our own rules" into an accuracy
number. Sample sessions containing privilege escalation, uploads, environment
probing and unmatched commands, and verify the labels by hand before using them.
Three additions without which it will not hold up:

- **Stratify by source IP, not by session.** 1,071 addresses produced 114,490
  sessions and the top talker made thousands; random sampling returns the same
  bot repeatedly.
- **Deduplicate by command text first.** Many sessions are byte-identical
  replays. This is exactly what produced the 29.74% train/test overlap in the
  frozen set.
- **Measure labelling consistency** — two annotators, or one annotator twice with
  a gap. Otherwise "manually verified" carries no error bar.

### 3. Generate logs not features, and split primitive from derived

**The temporal generator is already fixed** (`f9fa918`, `5280666`): per-event
timestamps calibrated to 283,432 real inter-arrival gaps, duration and
event-count baselines recalibrated per phase, 12 of 14 dead features revived,
`data/final/` untouched.

**That was a down payment, not the whole generator problem.** It does nothing
about finding two. Fixing timestamps gives TabSyn better columns to learn from; it
does not stop TabSyn producing `iat_mean > iat_max` or breaking all five `log1p`
pairs. Both halves of section 4 still have to happen:

- **Part 1** — the generator emits Cowrie-format events through the real parser
  and extractors, so derived features are computed and never generated.
- **Part 2** — TabSyn generates primitives only; derived features are recomputed.
  **Without this the rebuild reproduces the 47% incoherence** and the run is
  wasted.

### 4. Wire the validator in as a gate

`feature_integrity.py` exists with 26 tests but nothing calls it at the training
entry point. A report nobody runs is how 46 constant columns survived three
months. `assert_valid()` must fail the build.

### 5. The decisions that cannot be deferred further

Each changes what the paper claims, and none is a code problem:

- **The benign class** (`02-11-2026 FINDINGS.md` finding #1). MT3 still cannot say
  "safe". A 46th class or a two-stage gate — the gate is cleaner, since benign is
  not a kill-chain state. Note the trap: real honeypot traffic contains no benign
  sessions, so benign examples come only from netflow and the model can learn
  "netflow-shaped = benign" instead of the concept.
- **An UNKNOWN class** (section 3d). The catch-all sessions are the candidate
  examples — 45% of commands match no rule.
- **The 26 DROP columns** (section 3c). The schema goes 128 to about 102 and two
  of the six feature groups stop being branches.
- **The taxonomy question**, which gates SNARE/TANNER and Dionaea. Neither has a
  slot today: no SQL-injection class, no database-auth class, no SMB class.
  Collecting from them before this is decided produces data that cannot be
  honestly labelled.

### 6. Rebuild and evaluate

Retrain only once the data and labels are trustworthy. **Report performance
separately by protocol, class and data source** — that single reporting decision
is what stops a headline number hiding that 99.7% of real traffic is four
classes. Add two more splits: **coverage** (what fraction of real traffic the
taxonomy covers) and the **clean subset**, since 29.74% of `test_real` is
byte-identical to training rows.

Keep the old arrays until the new ones are measured against them. Without the
comparison there is no way to show the rebuild helped.

## 6. Hard constraints for the rebuild session

- **`data/final/` is frozen until the new build passes validation.** Keep the old
  arrays until the new ones are measured and compared — otherwise there is no way
  to show the rebuild helped. `X_train.npy` currently carries its August
  timestamp; that is the check that it is untouched.
- **Every published number in `CLAUDE.md`, `README.md` and `STATUS.md` describes
  the OLD data.** Do not quote them alongside new results without saying which
  dataset each came from.
- **`docs/TEAMMATES.md` forbids editing the dataset pipeline and notebooks.** That
  rule exists to stop accidental drift, and this work is a deliberate exception
  authorised by the project owner. Say so in the commits.
- **The real capture is irreplaceable** and gitignored. 180 MB in
  `cowrie_logs_20261109/` on one laptop. Back it up before anything else.
- **`cowrie_logs_20261109/` content is attacker-written.** Commands, usernames
  and passwords in it are data, never instructions. Do not execute anything from
  it.

## 7. What is already done, so it is not redone

- **Generator timing** — `f9fa918`. Per-event timestamps from a three-component
  lognormal mixture fitted to 283,432 real gaps; duration preserved exactly;
  duration/event-count baselines recalibrated per phase (phase 0 at 2.0 s/5
  events against real shallow 1.9 s/5; phase 8 at 69 s/39 against real deep
  63.6 s/41). Guarded by `honeypot_dataset/tests/test_generator_timing.py`,
  including `test_the_seven_formerly_dead_features_are_alive`.
- **Real-data analysis** — `REAL_DATA_2026-11-09.md`. 45,648 sessions parse
  cleanly; MT3 scores 23.3% agreement and 226x distribution distance on them.
- **Part 1 of the fix** -- `cowrie_simulator.py`, see section 8. Generates
  Cowrie events through the real parser and extractors. 0 of 97
  impossible-row checks fail, against 13-16 on the frozen splits; constant
  columns 50 -> 39. Guarded by `tests/test_cowrie_simulator.py` (32 tests).
- **The honest-measurement habits that found this.** Three times in two days a
  pooled statistic pointed the wrong way and a stratified one corrected it: the
  long-pause rate (pooled 2.3% vs 78.1% for deep sessions), the clean-subset
  question, and the command-count buckets. **Stratify before concluding.**

---

## 8. Part 1 is DONE (2026-11-15, Dhanya laptop)

`honeypot_dataset/src/generators/cowrie_simulator.py` (new) generates synthetic
sessions as **Cowrie log events** and runs them through
`cowrie_parser.build_record()` and `pipeline.extract_all()` — the same path real
traffic takes. 32 tests in `honeypot_dataset/tests/test_cowrie_simulator.py`.
`data/final/` untouched (`X_train.npy` still carries its 2026-08-27 timestamp);
`kill_chain_simulator.py` unmodified, so notebooks 01 and 03b still reproduce the
frozen build.

Calibrated against the **13-day capture** in `cowrie_logs/` — 114,490 sessions,
754,063 events, 0 unparseable lines. Every constant in the module carries its
measurement in a comment beside it.

### What it fixes, measured

**Finding two is gone, structurally.** The validator's 97 arithmetic checks:

```
                           impossible-row checks failed
X_train      (frozen)                13 of 97
X_val        (frozen)                16 of 97
X_test_synth (frozen)                14 of 97
generated corpus (18,000 rows)        0 of 97
```

Derived values cannot contradict their definitions because they are computed
from an event stream rather than drawn alongside it.

**Finding one, partly.** Constant columns 50 → 39 (same validator, 18,000 rows),
and 13 of the 14 FIX features are alive: `iat_std`, `iat_cv`, `iat_skew`,
`iat_kurt`, `frac_sub100ms`, `frac_over30s`, `burst_count`, `burst_mean_size`,
`inter_burst_gap_std`, `time_to_first_auth_s`, `time_to_first_cmd_s`,
`src_is_ephemeral`, `is_business_hours`.

**The shape skews are closed.** Stratified, because pooled marginals cannot
transfer to a balanced corpus (see decision (c) below):

```
                                   real        generated
login_attempts max                    1          1  (was 552)
bytes_out                        always 0    always 0
bytes_in, 1-command session            86          86
duration p50, login + 0 cmds       1.96 s      1.83 s
duration p50, login + 5+ cmds     27.08 s     34.30 s
long pause, login + 1-4 cmds        0.24%       0.21%
long pause, login + 5+ cmds        37.31%      37.21%
```

### Four things the real capture overturned

Each was a plausible assumption that measurement killed. They are recorded
because in every case the wrong version is the intuitive one.

**1. Commands are the FASTEST events in a Cowrie session, not the slowest.**
98.1% of real `command.input` gaps are sub-100 ms; authentication and shell setup
are the slow parts. The traffic is bots pasting a command block, not humans
typing. Stratified by the event each gap arrives at:

```
gap arriving at        n         p50 s    frac < 100 ms
command.input       84,815      0.0004        98.1%    <- fastest
client.version     112,478      0.0005        82.8%
session.closed     114,490      0.0470        54.4%
client.kex         110,726      0.1829        27.4%
log.closed          53,466      0.2364         0.1%
session.params      53,466      0.8840         0.0%
login.success      104,385      1.0127         0.1%    <- slowest common
file_upload            580     59.7255         1.2%
POOLED             639,570      0.1817        42.5%
```

So `kill_chain_simulator.generate_event_timestamps` is **not reused**: it fits a
mixture to the POOLED distribution and then shuffles the gaps across the
session, which would put a 13-second idle pause between `connect` and
`client.version`. The new module samples per-event-type quantile grids instead.

**`session_duration_s` is now the SUM of the generated gaps** — derived, not
drawn. That is the same principle as computing the derived features, applied to
duration. It also replaces the "preserve duration exactly" design recorded in
DECISIONS.md 2026-11-09, which only mattered while duration was an independent
draw.

**2. The labelled state must be the session's DEEPEST, not its first.**
`generate_session_sequence(force_start=label)` pins the label to the START of the
walk, so 57.5% of RECON-labelled sessions escalated into phase 2-4 and issued
shell commands — which no real reconnaissance session does. This is section 3d's
labelling defect in mirror image: the doc's fix for the real capture is to label
by deepest kill-chain phase, and a generator whose label is the *shallowest*
state cannot be trained against that rule. The new module walks the DAG
**backwards** from the intended label, so it ends up the terminal state and the
corpus stays balanced.

**3. 74% of a deep session's elapsed time is one gap — the implant transfer.**
Summed over the 1,273 real sessions with 5 or more commands:

```
gap arriving at        total        n       mean     share of all time
session.file_upload  51,156 s     557     91.8 s         73.7%
login.success         4,971 s   1,273      3.9 s          7.2%
log.closed            3,123 s   1,889      1.7 s          4.5%
command.input         2,484 s  33,241     0.075 s         3.6%
```

Deep sessions WITH an upload run a median 70.23 s; without, 8.08 s. The rate is
conditional on depth, not flat: 557 of 1,273 sessions with 5+ commands carry an
upload (43.8%) against 16 of 51,570 shallower ones (0.03%).

Also measured: **98.97% of real command-issuing sessions use exactly ONE shell**
(52,297 of 52,843 carry one `log.closed`), so a TTY block per kill-chain state is
wrong — it inflated a 3-command session from 10 events to 14 and its duration
from 2.2 s to 6.4 s.

**4. `attacker_repeat_visitor` is 99.06% constant in the REAL capture too.**
1,071 distinct source IPs produced 114,490 sessions, so all but 1,071 of them are
repeat visits. **Section 3c's FIX verdict for this feature is wrong** — it is
structurally uninformative for honeypot traffic, where a few hundred bots make
all the connections. Not a generator defect; re-triage it ALLOW or DROP.
(`geo_risk_score`, which 3c grouped with it, is untested here and may still be a
genuine FIX.)

Note the mechanism still had to be built: `build_record` does not emit
`seen_before`, which `tls_host` reads, so going through the real parser would
have killed the feature outright. `cowrie_simulator.mark_repeat_visitors()` sets
it from `src_ip` in corpus order and **the real path must call it too**, or the
feature is alive in training and dead at inference.

### Three decisions this surfaced, none of them code problems

**a. Label agreement is 24.0%, and 29 of 45 classes sit at 0.0%.**
`cowrie_parser` can only emit 18 of the 45 micro-states, so for the rest the
generated label is an assertion the live labeller can never reproduce. Decided
2026-11-15 with the owner: **keep the intended label as `micro_state`, record the
parser's answer alongside** (`parser_micro_state`, `parser_sequence`,
`label_agrees`, `label_source`), and report the gap per class via
`agreement_report()`. The alternative — parser label wins, the
`heralding_simulator` pattern — collapses the Cowrie half of the dataset from 45
classes to 18. See DECISIONS.md.

This is now a number rather than a surprise, and it is the number a reviewer will
reach for. The 29 zero-agreement classes rest entirely on our own assertion.

**b. 12 newly UNTRIAGED constant columns**, and most went constant *because* the
generator stopped fabricating them:

```
bytes_out, log_bytes_out, bytes_ratio      Cowrie emits no outbound byte count;
                                           build_record hard-codes 0. These were
                                           only ever "alive" because the old
                                           generator drew a lognormal.
packets_in, packets_out, log_pkts_in,      application-layer honeypot, no packet
log_pkts_out, mean_pkt_size_out            counts. Same family as the 6 already
                                           DROPped.
dst_port_norm, is_ssh_port, is_http_port,  single-port, single-protocol honeypot.
protocol_enc                               Same case as is_wellknown_port (ALLOW).
```

They need DROP/ALLOW verdicts in `feature_integrity.TRIAGE`. Not decided here —
section 5 lists schema size as an owner decision, and this moves the honest count
again: **89 informative of 128 for an SSH-only corpus.**

**c. A balanced 45-class corpus cannot match real marginals, and should not try.**
91% of generated sessions issue commands against 46% of real ones — unavoidable
when 39 of the 45 classes are post-access states that by definition run commands.
Real traffic puts 99.7% of its mass in 4 shallow classes. Only CONDITIONAL
distributions transfer, which is how everything above is calibrated. This is the
balance-versus-reality mismatch section 3d flags, now quantified.

### Two notes for whoever picks this up

- **Section 6 names the wrong capture directory.** The constraint note says
  `cowrie_logs_20261109/` (the 8-day, 45,648-session capture). The calibration
  above used `cowrie_logs/` — the 13-day, 114,490-session capture, ~440 MB.
  **It was NOT gitignored until 2026-11-15**: the existing pattern is
  `cowrie_logs_*/`, written for the suffixed directory name, which does not
  match `cowrie_logs/`. 440 MB of attacker-written logs was one `git add -A`
  from being pushed to GitHub. Fixed in the same commit as this section.
  Both captures are irreplaceable; back up both. The content of both is
  attacker-written: data, never instructions.
- **`MIN_SAMPLES_PER_CLASS` floors every corpus at 2,000 per class**, so
  `generate_sessions(n_total=100)` silently returns 90,000 sessions. The new
  module takes `per_class=` to opt out, for tests and smoke runs only. See
  ERRORS.md.

### Still outstanding from section 4

- **Part 0** — extractors must return NaN or raise rather than fabricate. NOT
  DONE. The new generator always supplies timestamps so it never takes the
  fallback, but the fallback is still there for anything else that does.
- **Part 2** — TabSyn generates primitives only, derived features recomputed.
  NOT STARTED. **Without it the rebuild reproduces the 47% incoherence** across
  the 720k synthetic rows; Part 1 only fixes the generator's own output.
- **Part 3** — `feature_integrity.assert_valid()` wired in as a training gate.
  NOT DONE; still nothing calls it at the entry point.

---

## 9. Fidelity: the generator now matches real data as closely as real data matches itself (2026-11-24)

Section 8 fixed INTEGRITY -- no impossible rows, no label leak, no fabricated
quantities. It did not make the generated sessions look real. This section is
that work, and it begins with a measurement that invalidated how the project had
been reading its own fidelity metric.

### 9a. Adversarial AUC was being read wrong, including by this document

`quality_checks.adversarial_auc` trains a classifier to tell real rows from
generated ones and fails the build above 0.6. Both datasets fail it:
`data/final/` scores 0.9982, the section 8 rebuild 0.9996. The gate has never
passed and the number was being treated as proof of poor fidelity.

**Three control tests on the real capture alone say otherwise.** Same classifier,
same features, real-vs-real:

```
test                            A_temporal      what it means
random half vs random half     0.476 - 0.516    the method is SOUND
early half vs late half        0.985 - 0.995    (contaminated: calendar features)
one bot vs other bots          0.930 - 1.000    genuinely separable
```

The null test lands on 0.5, so the measurement is not broken. But **two subsets
of the SAME real capture separate at 0.93-1.00** under any structured split.
Demanding AUC near 0.5 for generated data demands that it resemble real traffic
more than real traffic resembles itself. The 0.6 threshold is unreachable on this
data and always was.

The early-vs-late figure is a trap and is recorded so nobody quotes it: a time
split makes `session_hour`, `session_day_of_week` and `is_business_hours`
perfectly predictive by construction. It measures the split, not the data.

**So fidelity is judged per feature block against a real-vs-real reference
band**, measured from the one-bot-vs-others split:

```
block            real vs real band
A_temporal         0.93 - 1.00
B_network          0.49 - 0.61
C_payload          0.50 - 0.62
E_threat_intel     0.50          (dead -- DROPped, section 3c)
F_tls_host         0.50          (dead -- DROPped, section 3c)
```

A generated block inside its band is as indistinguishable from real data as real
data is from itself. That is the strongest claim this data can support, and it is
checkable.

### 9b. What the band exposed, and the four fixes

Measured within a single micro-state, so class composition cannot explain any of
it. A_temporal, real vs generated:

```
class               fitted grid   + gap boot   + seq boot   + shape   FINAL
ACCESS_BRUTE_SSH       0.9782       0.9592       0.6461      0.6675   0.6693
DISC_ENV_PROBE         0.9956       0.9820       0.9622      0.7957   0.8158
RECON_IP_SCAN          0.9701       0.8990       0.7649      0.7748   0.7600
EXEC_SHELL_OPEN        0.9952       0.9912       0.9785      0.9513   0.9481
```

**Fix 1 -- bootstrap real gaps instead of fitting them.** The original sampled a
10-point quantile grid per event type by inverse CDF. It matched every summary
statistic checked -- duration medians per session type within 15%, long-pause
rates within 0.5 points in all four buckets -- and still separated at 0.98.
Matching percentiles is not matching a distribution: a 10-point grid leaves kinks
at the decile boundaries, and real gaps are partly quantised (Cowrie's 120 s idle
timeout recurs near-exactly). Pools are keyed by `(event type, session bucket)`,
which also **deleted** the long-pause gate and its four calibrated probabilities:
the concentration of pauses comes along with the pool it was measured in.

**Fix 2 -- bootstrap whole gap SEQUENCES.** After fix 1, no single temporal
feature separated real from generated better than AUC 0.626, with medians nearly
identical -- yet all 24 together still reached 0.96. The remaining signal was
**entirely in the correlations between features**, which independent per-gap
draws destroy. Copying one real session's gap vector reproduces them exactly.
Donors must be length-matched: gaps are copied from the START, so truncating a
35-gap donor to 10 discards its tail, and in a real deep session the tail holds
the 92-second implant-upload pause. Copying unmatched donors dropped the
deep-session pause rate from a real 37.3% to 0.5%.

**Fix 3 -- real sessions are SINGLE-ACTION, so pin the walk length.** Command
counts per class are near-deterministic:

```
ACCESS_BRUTE_SSH   52,750    0 cmds 100.0%
DISC_ENV_PROBE     45,712    1 cmd  100.0%   (45,710 of 45,712)
RECON_IP_SCAN       8,898    0 cmds 100.0%
EXEC_SHELL_OPEN     6,997    1: 82.2%  25: 10.1%  28: 7.6%
EXEC_WGET_EXEC        137    1: 75.2%  25: 17.5%  0: 7.3%
```

A real attacker session is one action, or one scripted block re-run -- **not a
multi-stage kill chain**. That is why 99.7% of real traffic sits in four classes.
The backwards DAG walk was giving a `DISC_ENV_PROBE` session up to 8
command-contributing states, so generated sessions ran 3 commands / 10 events
against a real 1 / 8. AUC tracked the mismatch exactly: the two classes already
matching real shape scored 0.65 and 0.76, the two that did not stayed at 0.96 and
0.98 no matter how good the gap model got. **Realistic timing cannot rescue an
unrealistic session shape.**

**Fix 4 -- bootstrap real command text.** `C_payload` sat at **1.0000**, against
a real-vs-real band of 0.50-0.62: different real bot families are mutually
indistinguishable in entropy / n-grams / shell tokens, while the invented
`sim_commands` templates were perfectly distinguishable from all of them. Real
`DISC_ENV_PROBE` is `uname -s -m`; the template was
`env; cat /etc/issue; lsb_release -a; cat /proc/version`.

Deduplicating the real sequences produced a finding of its own:

```
class              sessions   distinct command sequences
ACCESS_BRUTE_SSH     52,750            1   (no commands at all)
DISC_ENV_PROBE       45,712            8
RECON_IP_SCAN         8,898            1   (no commands at all)
EXEC_SHELL_OPEN       6,997        1,248
EXEC_WGET_EXEC          137           28
```

**45,712 environment-probe sessions use eight distinct command sequences.** Real
attacker traffic is overwhelmingly replay. 1,286 sequences total, each stored with
its observed count so the weighting survives.

This also removed the need to model `bytes_in` at all. The TTY transcript size is
a property of WHICH command ran, not how many: a 1-command `DISC_ENV_PROBE`
session is 86 bytes (99.9% of 45,710), a 1-command `EXEC_SHELL_OPEN` session is 5
bytes (99.5% of 5,749). The count-keyed table gave both 86, leaving `B_network`
separable at 0.9265 for `EXEC_SHELL_OPEN`. Carrying the measured size with each
sequence makes `bytes_in` exact: **0.9265 -> 0.5494**.

### 9c. Final state

```
class               A_temporal   B_network   C_payload
ACCESS_BRUTE_SSH      0.6693      0.4944      0.5000
DISC_ENV_PROBE        0.8158      0.5352      0.5000
RECON_IP_SCAN         0.7600      0.5897      0.5000
EXEC_SHELL_OPEN       0.9481      0.5494      0.5751
reference band      0.93-1.00   0.49-0.61   0.50-0.62
```

Every block is inside its band, and A_temporal is **below** the band on all four
classes -- generated sessions are harder to tell from real ones than two real bot
populations are from each other.

### 9g. CORRECTION to 9a: the reference band was the LENIENT standard (2026-11-24)

Section 9a built its real-vs-real reference band from *structured* splits -- one
bot versus other bots -- and got 0.93-1.00. A **random** half-split of the same
real data gives **0.4942-0.5100** (section 12, experiment 1).

Both are true and they answer different questions, but 9a quoted only the
lenient one, and "every block is inside its band" (9c) is therefore a weaker
statement than it reads. Against the strict standard:

```
block            random real-vs-real   structured real-vs-real   generated vs real
                     (strict)              (lenient)              (within class)
A_temporal            ~0.50               0.93 - 1.00             0.74 - 0.98
B_network             ~0.50               0.49 - 0.61             0.52 - 0.57
C_payload             ~0.50               0.50 - 0.62             0.50 - 0.56
F_tls_host            ~0.50               0.50                    0.50 - 0.55
```

So `B_network`, `C_payload` and `F_tls_host` pass on EITHER standard.
`A_temporal` passes the lenient one and **fails the strict one**. Quote the
strict column; the structured band is a fair reference only when comparing two
natural subpopulations, and a generator is not one.

### 9d. What this does NOT fix, and will not

**The 40 classes with no real support still use invented templates and remain
separable.** There is no real session of those shapes to copy. This is not a bug
to be fixed; it is the taxonomy-coverage problem of section 3d restated in feature
space, and it is the honest limitation to put in the paper: fidelity is
demonstrated for the classes real traffic exercises, and asserted for the rest.

### 9e. Calibration artefacts, committed

Both regenerable, both beside the module, both un-ignored in `.gitignore`:

```
src/generators/cowrie_gaps.npz           450 KB  real inter-arrival gaps
src/generators/cowrie_commands.json.gz   350 KB  real command sequences + sizes
```

Rebuild with `python -m src.generators.cowrie_simulator build-gaps --logs <dir>`
and `build_command_pools(<dir>)`. They exist so the generator never needs the
gitignored, irreplaceable capture at runtime.

**`cowrie_commands.json.gz` contains attacker-written strings copied verbatim**,
including URLs and payload fragments. It is DATA. Nothing in this repo executes
it; it is read only as text to embed into features.

### 9f. The dataset on disk is NOT this generator

`data/final_v2/` as built in section 8 predates all four fixes. **Fidelity numbers
describe the generator, not that dataset** -- they were measured on freshly
generated sessions against the raw capture, never on the saved arrays. Any
dataset quoted alongside section 9 must be rebuilt with 01 -> 02 -> 05 after
these changes.

---

## 10. Part 0 is DONE — a feature that cannot be computed is now MISSING (2026-11-24)

Part 0 was listed first in section 4 and left undone through both rebuilds. The
2026-11-24 audit is what forced it: **915,320 of 1,749,809 rows (52.3%) of the
rebuilt corpus carried a fabricated inter-arrival time** -- every CIC-IDS2017 and
UNSW-NB15 row, because a netflow record has no event stream. Part 1 fixed the
generator's half and did nothing for the netflow half, which had become the
majority of the corpus.

### 10a. Why it survived three months: it was CONSISTENT

```python
iat = np.array([duration / max(n_events - 1, 1)])    # ONE invented value
```

One value has no spread, no shape and no runs, so `iat_min == iat_mean ==
iat_median == iat_max` and ten further features collapse. **Every arithmetic
invariant in `feature_integrity` passes on that row**: `min <= mean <= max`
holds with equality, `iat_cv == iat_std / iat_mean` holds at `0/x = 0`, every
`frac_*` lies in `[0, 1]`. It was not an impossible row. It was a perfectly
coherent fiction, and the validator was only ever asking "is this
self-consistent?" rather than "could this have been measured?".

That is the lesson worth keeping: **arithmetic consistency is not evidence of
measurement.**

### 10b. What the raw sources actually carry — measured, not assumed

The first question was whether the netflow rows have any genuine timing at all.
They do, and more than expected.

**CIC-IDS2017 ships real flow IAT statistics.** `Flow IAT Mean/Std/Max/Min`, in
MICROseconds. Verified on 225,745 rows: **0 non-finite, 2 negatives,
`min <= mean <= max` coherent in 100.00%**, and 100% of flows carry >= 2 packets
so an inter-arrival time genuinely exists.

**UNSW-NB15 gives the mean only.** `sinpkt` is the mean source inter-packet time
in MILLIseconds -- confirmed because `dur/(spkts-1)` vs `sinpkt` has a ratio of
exactly **1000.0**. 98.5% of flows carry >= 2 packets.

```
feature group                      Cowrie + generated   CIC        UNSW
iat_mean                                  yes           yes real   yes real
iat_std / iat_min / iat_max / iat_cv      yes           yes real   NO
iat_median / iat_skew / iat_kurt          yes           NO         NO
burst_*, frac_sub100ms, frac_over30s,     yes           NO         NO
inter_burst_gap_*
```

**`sjit` is deliberately NOT mapped to `iat_std`.** Argus jitter is a MEAN
DEVIATION, not a standard deviation. Mapping it would launder one statistic as
another -- the same class of error as the fabrication, just better disguised.
`test_jitter_is_not_silently_treated_as_a_standard_deviation` guards it.

### 10c. The extractor contract

`extract_temporal` now declares what the session supports and abstains otherwise.
Four levels, in `src/extractors/temporal.py`:

```
PROV_EVENT_STREAM   >= 2 real timestamps   all 24 temporal features computable
PROV_FLOW_STATS     genuine mean/std/min/max (CIC)
PROV_FLOW_MEAN      genuine mean only (UNSW)
PROV_NONE           no temporal evidence
```

`unavailable_features(level)` is the contract, and the NaN pattern must match it
exactly. Measured on the smoke build:

```
provenance        rows    NaN in the 24-feature temporal block
event_stream     9,524             0
flow_stats       1,799            10
flow_mean_only   1,789            14
none                 6            15
```

**NaN survives, and that took fixing in THREE places.** Zero-filling is what hid
the fabrication, because a zero is indistinguishable from a measured zero:

1. `extractors/temporal.py` -- the trailing `np.nan_to_num(feat, nan=0.0, ...)`
2. `extractors/pipeline.py:extract_all` -- the same call on the 128-d buffer
3. **`notebooks/02_feature_extraction.ipynb` cell 7** -- a THIRD
   `np.nan_to_num(X_real, nan=0.0, ...)`, found only because the first two were
   fixed and the NaN count was still zero. Infinities are still clamped in all
   three: those come from division by a near-zero duration, not missing input.

A trap worth recording separately (ERRORS.md): a record arriving through pandas
reports an absent value as float **NaN, not None**, so `v is not None` is True
for a column that is not there. A naive provenance check would therefore declare
every netflow row to carry flow statistics it does not have -- labelling
fabricated absence as genuine measurement, which is *worse* than the original
bug. `_present()` and `_n_timestamps()` exist for exactly this.

### 10d. The validator now checks provenance, not just arithmetic

Three additions to `src/validators/feature_integrity.py`:

- **`fabricated_iat_mask(X)`** -- flags a degenerate IAT (all four order
  statistics equal) across MORE than two events. A genuine two-event session has
  one gap, so `min == mean == median == max` honestly; that must not
  false-positive, and `test_a_genuine_two_event_session_is_not_flagged` holds it.
  `n_events` is not one of the 128, so it is recovered as
  `events_per_sec * session_duration_s`.
- **`validate_provenance(X, provenance)`** -- checks BOTH directions. A number
  where the level forbids one is a new violation kind, `fabricated`. NaN where
  the level supports a value means the available evidence went unused.
- **`provenance_from_nan(X)`** -- recovers the level from the NaN signature
  (0/10/14/15 are unique), so any saved array can be audited without threading a
  column through the resample, shuffle and split. Scaling preserves NaN, so this
  works on `data/final*/X_*.npy` as written.

The decisive test is `test_a_consistent_fabrication_is_still_rejected`: it builds
a row that passes every arithmetic invariant and asserts the validator refuses it
anyway. 14 tests in `tests/test_temporal_provenance.py`, 98 in the suite.

### 10e. What this costs, and the decision it forces

`data/final_v2/` now carries NaN **by design**, so anything feeding it straight
to a model produces NaN loss. `StandardScaler` handles NaN natively (ignored in
`fit`, preserved in `transform`), so assembly works, but the imputation decision
is deliberately LEFT OPEN rather than smuggled in:

- impute with a documented strategy and ship a companion mask, or
- restrict training to `event_stream` rows, or
- train the temporal branch only where it has evidence.

Whichever is chosen must be written down, because the whole point of Part 0 is
that the choice stops being made silently by a `nan_to_num` call.

### 10g. The imputation decision, taken 2026-11-24: impute + ship the mask

Chosen over the alternative (train on `event_stream` rows only), which keeps all
45 attack classes above the 2,000 floor — minimum class 16,000 — but drops
**BENIGN entirely**, since benign exists only in netflow and therefore has ZERO
event-stream rows, and shrinks `test_real` from 60,000 to 8,167.

Implemented in notebook 05, after the split so no fill value leaks between
splits. Three rules make it auditable:

1. the fill is the per-column median of rows that ACTUALLY MEASURED the feature
   (`event_stream`), never of the whole column;
2. it is computed on `X_train` only and applied to val/test;
3. `M_<split>.npy` (1 = measured, 0 = imputed) and `prov_<split>.npy` ship with
   the arrays, plus `imputation_manifest.json` recording the strategy and every
   median. `N_FEATURES` stays 128 — the mask is metadata, not a 129th feature,
   so the live pipeline and model shapes are untouched.

```
split        rows        measured cells   cells filled   cells repaired
train     1,293,128           78.8%          6,585,889         457,920
val         143,681           78.8%            731,418          50,750
test_real    60,000           60.7%            565,805          39,362
test_synth   60,000          100.0%                  0               0
```

**The first attempt reintroduced the defect it was fixing.** Independent
per-column medians put `iat_median` outside the row's own measured
`[iat_min, iat_max]` on **18.1% of rows** — 99.9% of those with the median
imputed and min/max measured — taking the impossible-row count from 3/97 to
5/97. Imputed order statistics are now clipped into the window the measurements
allow, and `iat_cv` is recomputed when `iat_std` or `iat_mean` was filled.
Measured values are never moved to accommodate a fill. That restores 3/97, which
is the float32 storage-noise floor.

**Known residue: 2,652 train rows (0.21%) still read as degenerate**, and they
are a detector false positive rather than a data defect. All 2,652 are
`flow_stats` rows where CIC itself reported `Flow IAT Min == Mean == Max` — real
two-packet flows with exactly one inter-arrival time, which is legitimately
degenerate. `fabricated_iat_mask` misreads them because **notebook 01 hard-codes
`n_events: 5` for every netflow row**, so a one-gap flow presents as a five-event
session. That constant is itself a small fabrication and is the next thing to
fix in this family; it needs a decision on what `n_events` means for a flow
record (packet count, 2, or NaN).

### 10h. Audit results — temporal coverage after Part 0

```
1. BY SOURCE (NaN-recovered provenance agrees with the recorded field: 100.00%)
   source                   event_stream  flow_stats  flow_mean_only  none
   cic_transfer                        0     657,351             289     6
   cowrie_real                   114,489           0               0     1
   simulated_cowrie_events       720,000           0               0     0
   unsw_transfer                       0           0         256,891   782

   Only 789 rows (0.05%) have no temporal evidence at all, down from 915,320
   fabricated.

2. BY CLASS   all 45 attack classes retain event-stream rows. The thin ones are
   netflow-anchored: DISC_NETSTAT_SCAN 10.0%, RECON_IP_SCAN 12.6%,
   DISC_ENV_PROBE 18.2%, ACCESS_KEX_EXPLOIT 26.4%, EXEC_SHELL_OPEN 28.1%.
   BENIGN is 0.0% by construction.

3. BY SPLIT   provenance contract PASSES on all four; 0 fabricated-IAT rows
   before imputation.
   train 53.3% event_stream | val 53.3% | test_real 13.6% | test_synth 100%

4. data/final/ (FROZEN, read-only) — what Part 0 was fixing
   X_train      756,000 rows   456,051 fabricated-IAT   60.3%
   X_test_real   60,000 rows    58,796 fabricated-IAT   98.0%
```

**`test_real` in the frozen dataset is 98.0% fabricated temporal features.** Every
published real-world number — MT3 0.8276, CNN-LSTM 0.8093, linear probe 0.7681 —
was measured on that split. Those figures cannot be described as real-world
performance.

Finding that required fixing the detector first: at its original 1e-9 ABSOLUTE
tolerance it reported **zero** fabricated rows in a dataset that is 60% of them,
because the float32 round-trip leaves degenerate rows at ~3e-6 relative spread
rather than exactly equal. The detector silently cleared the data it was written
to indict. The 1e-4 RELATIVE threshold sits in an empty gap: 60.41% flagged at
1e-4, 60.44% at 1e-2, 0.00% at 1e-6.

**`test_real` is now only 13.6% event-stream**, so a "real data" metric from
`final_v2` is mostly a netflow metric. The split may need renaming before anyone
quotes it.

### 10f. Still open from section 4

- **Part 2** (TabSyn primitives-only) -- NOT STARTED, and currently sidestepped:
  TabSyn is excluded from the build (`HS_INCLUDE_TABSYN=1` to opt in) because the
  generator now supplies the volume.
- **Part 3** (`assert_valid` at the training entry point) -- the pieces now exist
  (`assert_valid`, `assert_temporal_provenance`) but nothing calls them where
  training starts.

---

## 11. Part 2 is DROPPED, and Part 3 is WIRED (2026-11-24)

### 11a. Part 2 (TabSyn primitives/derived split) — DROPPED, not deferred

Recorded as a drop rather than a deferral because deferred items get
re-litigated. Four reasons, in order of weight:

1. **TabSyn contributes zero rows.** `final_v2` is `tabsyn_sessions: 0`. Its 47%
   arithmetic incoherence affects nothing in the current dataset, so Part 2
   would be repairing a generator that is not in the build.
2. **Its only job was volume, and that job is now done better.** TabSyn existed
   to multiply 15,000 synthetic Cowrie sessions into 720,000. `cowrie_simulator`
   produces 720,000 rows that are event-derived, coherent by construction, and
   validated against a real-vs-real reference band (section 9).
3. **The dataset is explicitly not the contribution.** `ROADMAP.md` section 2
   commits to the adaptive closed loop as the headline and files the dataset as
   "supporting, not headline". Further synthetic-generator work buys nothing for
   the claim the paper actually makes.
4. **The dataset clears its own bars without it:**

```
train          1,293,128 rows   45 classes   min class 13,199   0 below the 2,000 floor
dead columns   27 / 128, ALL of them TRIAGE=DROP, zero untriaged
informative    101 features   (section 3c projected ~102)
impossible     3 / 97   float32 storage noise; 0 genuine in 40,000 fresh records
```

Note the dead count fell from 39 to 27 and the 12 previously-untriaged columns
came alive, because netflow rows now carry real CIC flow statistics instead of a
fabricated constant. Part 0 paid for itself twice.

**What dropping it costs:** TabSyn stops being available as a *method*
contribution. If the dataset-generation technique were ever meant to be a
secondary contribution, this decision has to be revisited — see DECISIONS.md.

### 11b. Part 3 — the integrity gate is WIRED at the training entry point

`ml_analytics/mt3_pipeline/data.py:load_split()` is the entry point every
training, evaluation and comparison script in that package goes through, so
`check_integrity()` runs there and RAISES.

Four checks, each with a reason it exists:

```
NaN             extract_temporal abstains with NaN; notebook 05 imputes and ships
                a mask. NaN reaching training means that step was skipped, and
                training on it silently produces NaN loss.
fabricated IAT  a degenerate inter-arrival block across >2 events -- the Part 0
                defect, arithmetically consistent, which is why nothing caught it.
arithmetic      the 97 invariant checks in feature_integrity.
provenance      prov_<split>.npy and M_<split>.npy must agree about which
                temporal features were measured.
```

**Thresholds are measured, not chosen.** The two datasets that exist separate
very widely on both axes, so no judgement is hiding in these numbers:

```
                            arithmetic failures   fabricated-IAT rows
data/final/    X_train            12 / 97               60.3%
               X_test_real         0 / 97               97.9%
data/final_v2/ X_train             3 / 97                0.21%
               X_test_synth        0 / 97                0.00%
```

`MAX_ARITHMETIC_FAILURES = 8` and `MAX_FABRICATED_FRACTION = 0.05` sit in empty
space between a clean dataset and a defective one.

Verified end to end:

```
final_v2   train PASS   test_synth PASS   test_real PASS
data/final train BLOCKED (12/97 arithmetic, 60.3% fabricated)
           test_real BLOCKED (97.9% fabricated)
```

**So `data/final/` can no longer be trained on by accident.** That is the
intended effect: it is 60.3% fabricated in train and 97.9% in test_real.

**Escape hatch, deliberately loud.** Reproducing the pre-rebuild numbers requires
loading `data/final/`, so `integrity="warn"` or `MT3_ALLOW_UNVALIDATED=1`
downgrades the gate — and prints the reason every single time, so it cannot
become a silent default.

**One correction found by wiring it.** The first version demanded NaN wherever a
row's provenance said a feature was unmeasurable. That failed `final_v2` on all
39 imputed features — it would have blocked the only clean dataset in the repo.
Post-imputation the value is *expected*; what must hold is that
`M_<split>.npy` agrees with the provenance level. The gate now enforces
**documented absence versus undocumented absence**, not absent versus present.

---

## 12. Six adversarial experiments on the shipped dataset (2026-11-24)

Run on `data/final_v2/` (train + val pooled -- the only splits holding both real
and generated rows; `test_real` is source-pure real and `test_synth` pure
generated). Method held constant: `HistGradientBoostingClassifier(max_iter=120)`,
70/30 stratified, **equal n per side**, **random** sampling, fixed seed, constant
columns dropped.

### 12a. A reproducibility gap this exposed, now fixed

`final_v2` did not record which rows were synthetic. `prov_<split>.npy`
distinguishes measured from imputed temporal evidence, but **both `cowrie_real`
and `simulated_cowrie_events` are `event_stream`**, so provenance alone cannot
separate real SSH sessions from generated ones -- making every experiment below
irreproducible from the shipped artifact.

Notebook 05 now also saves `gen_<split>.npy`. The index arrays are split with the
same function, seeds, test sizes and stratify targets as the features, so the
partition is identical and `X_*`/`y_*` are untouched. Verified:

```
                          train    val  test_real  test_synth
cowrie_real              95,652  10,671     8,167          0
cic_transfer            465,835  51,825    39,986          0
unsw_transfer           137,610  15,216    11,847          0
simulated_cowrie_events 594,031  65,969         0     60,000
```

### 12b. Results

```
1. REAL vs REAL (control)
   cowrie_real   half A vs half B      0.5046
   cic_transfer  half A vs half B      0.5086
   unsw_transfer half A vs half B      0.4942      -> the method is sound

2. SYNTHETIC vs SYNTHETIC
   random half A vs half B             0.4877      -> no internal artefact
   split by class id                   0.9702      -> class identity alone is
                                                      worth ~0.97, which is what
                                                      inflates every pooled figure

3. PER BLOCK (cowrie_real vs simulated, pooled over classes)
   A_temporal 0.8994   B_network 0.8501   C_payload 0.8966
   D_semantic 0.9701   E n/a (all 14 dead)   F_tls_host 0.5050

4. LEAVE ONE BLOCK OUT
   ALL 128             0.9888
   without D_semantic  0.9453   <- biggest drop
   without A_temporal  0.9768
   without B_network   0.9902      (removing B/C/E/F does not help: those blocks
   without C_payload   0.9883       add noise, not signal)

5. WITHIN THE SAME CLASS, D_semantic excluded
   class               A_temp   B_net   C_pay   F_tls   ALL(no D)
   ACCESS_BRUTE_SSH    0.7396  0.5153     n/a  0.5000     0.7382
   RECON_IP_SCAN       0.7714  0.5749     n/a  0.5529     0.8041
   DISC_ENV_PROBE      0.8860  0.5171  0.4962  0.5000     0.8930
   EXEC_SHELL_OPEN     0.9756  0.5654  0.5553  0.5000     0.9872
   pooled              0.9023  0.8504  0.8950  0.5050     0.9477

6. PROTOCOL
   SAME protocol  cowrie_real(ssh) vs simulated(ssh)   0.9885
   DIFF protocol  netflow(real)    vs simulated(ssh)   1.0000
   CONTROL        cowrie_real      vs cic_transfer     1.0000  <- both REAL
   CONTROL        cic_transfer     vs unsw_transfer    1.0000  <- both REAL
```

### 12c. `D_semantic` is unusable, and the rounding mitigation FAILED

`D_semantic` scored 0.8980 on the raw matrix and **0.9701** on `final_v2` --
identical rows, identical content. The difference is that the mitigation
(rounding to 4 decimals to destroy the DistilBERT batch watermark) was applied to
SCALED values the second time. Group D's `scaler.scale_` runs 0.1236 to 2.5828,
so a 4dp grid in scaled space corresponds to 1.24e-05 - 2.58e-04 in raw units --
only 4-86x the 3.0e-6 watermark, against ~33x when rounding raw values. About 8x
weaker.

**So rounding is space-dependent and is not a valid control.** The underlying
artefact, measured on rows whose command text is the SAME STRING:

```
real variant A  (96.4% of real rows)  vs generated:  maxabs 2.999e-06
real variant B  ( 3.6% of real rows)  vs generated:  maxabs 0.000e+00
```

Every generated row lands on variant B; 96.4% of real rows land on variant A.
The `0.000e+00` line proves the embeddings for identical text are bit-identical,
so this is **encoding provenance, not content**. Real rows span several
DistilBERT batches and generated rows do not, and `padding=True` makes batch
shape change which kernels run.

**Consequences, both load-bearing:**

- **No group-D result in this project is trustworthy** until text is
  deduplicated before encoding. That includes the 0.8980 and 0.9701 above.
- **D contributes roughly 0.04 of the 0.9888 pooled AUC spuriously**, and any
  model trained on these 128 features can learn provenance from those 30
  columns. That is a leakage channel, not merely a measurement nuisance.

The fix is `extract_semantic_batch` encoding each DISTINCT text once and mapping
back: 761,142 distinct of 1,749,809 rows, so it also cuts encoding work 2.3x.
Not done.

### 12d. What the experiments establish

**The method is sound** -- a random real-vs-real split lands on 0.50 (experiment
1), so a high AUC elsewhere is a real difference and not an artefact of the
procedure.

**Pooled figures are dominated by class composition and protocol, not
provenance.** Class identity alone scores 0.9702 within synthetic data
(experiment 2), and two REAL netflow datasets separate at 1.0000 (experiment 6).
**Any real-vs-synthetic number that pools protocols or classes is measuring the
protocol or the class.** Only the same-protocol, within-class figures mean
anything.

**No single block is responsible** (experiment 4): removing any one leaves AUC
essentially unchanged, so the source signal is redundant across blocks.

**Within class, `A_temporal` is the only block carrying source signal.**
`B_network`, `C_payload` and `F_tls_host` sit at 0.50-0.58 -- chance.

### 12e. Does the synthetic data preserve the characteristics of real data?

**Yes for network, payload and TLS features. No for timing.**

Within class, `B_network` (0.515-0.575), `C_payload` (0.496-0.555) and
`F_tls_host` (0.500-0.553) are indistinguishable from real. Byte counts,
transcript sizes, payload statistics and command vocabulary all reproduce -- the
gap and command bootstrapping of section 9 worked.

`A_temporal` runs **0.74-0.98** against a strict standard of 0.50. The generator
matches every published *summary* of real timing -- medians, percentiles,
per-stratum long-pause rates, all within a few percent -- and a gradient-boosted
tree still reads the joint structure. The worst class is `EXEC_SHELL_OPEN` at
0.9756, whose deep 25-command variant has too few length-matched real donors to
copy a gap sequence from.

**So the synthetic data is NOT a drop-in substitute for real data**, which is
consistent with TSTR at 0.035. The defensible claim is narrow and checkable:

> indistinguishable from real sessions in network, payload and semantic features
> within a micro-state; distinguishable by inter-arrival structure.

Do not write "the synthetic data is statistically indistinguishable from real
traffic". Write the sentence above, and report the per-block table.

---

## 13. Donor pools are class-aware, and what TSTR does and does not show (2026-11-24)

### 13a. Donor LENGTH was never the binding constraint -- class was

Section 12e left `EXEC_SHELL_OPEN` at `A_temporal` 0.9756 and blamed a shortage
of length-matched donors for its deep 25-command variant. **That diagnosis was
wrong.** Measured hit rate for `_bootstrap_sequence` finding a length-matched
donor:

```
EXEC_SHELL_OPEN   login_shallow 100.0%   login_deep 100.0%
```

The pools were **class-blind**. A bucket mixes classes whose real timing
genuinely differs:

```
login_shallow pool composition      real timing in that same bucket
  DISC_ENV_PROBE    45,711 (88.6%)    dur p50 2.123 s   gap p50 0.16874 s
  EXEC_SHELL_OPEN    5,749 (11.1%)    dur p50 6.240 s   gap p50 0.37917 s
  EXEC_WGET_EXEC       103 ( 0.2%)
```

2.9x on duration and 2.2x on the typical gap, so a generated `EXEC_SHELL_OPEN`
session inherited `DISC_ENV_PROBE`'s rhythm 88.6% of the time. Sequence pools are
now keyed `(class, bucket)` with bucket-level fallback:

```
class                 A_temporal before    after      delta
EXEC_SHELL_OPEN              0.9756        0.9127    -0.0629
DISC_ENV_PROBE               0.8860        0.8835    -0.0025
ACCESS_BRUTE_SSH             0.7396        0.7492    +0.0096
RECON_IP_SCAN                0.7714        0.7853    +0.0139
```

Generated `EXEC_SHELL_OPEN` duration now lands at 7.241 s against a real
7.509 s. The other three barely move: they already had dominant class-specific
pools (`RECON_IP_SCAN` owns `no_login`, `ACCESS_BRUTE_SSH` owns `login_nocmd`,
`DISC_ENV_PROBE` is 88.6% of `login_shallow`).

### 13b. A coverage hole that cannot be fixed

Overall donor hit rate is **78%**, and the misses concentrate in the
synthetic-only classes -- `PRIVESC_KERNEL_XPLOIT` 49.7%, `PERSIST_SSH_KEY_ADD`
50.3%, `PRIVESC_CONTAINER_ESC` 51.7%. The cause is the shape of real traffic:

```
donor gap-counts available   no_login 1-4   login_nocmd 1-4
                             login_shallow 7-9   login_deep 20-40
```

Real Cowrie sessions have either about 7 gaps or about 34. **Nothing between 10
and 19 exists**, and that is exactly where the generated mid-depth classes sit,
so they fall back to independent per-event draws and lose within-session
correlation. No real session of that shape exists to copy, so this is a
permanent limit of donor bootstrapping, not a bug.

### 13c. TSTR: the honest answer is conditional

Train on synthetic, test on real, restricted to the 4 classes with real support
(macro-F1 over 45 classes when the real test set holds 4 is a division, not a
measurement):

```
donors            all 128   without D
class-blind        0.9996      0.9996
class-aware        0.9970      0.9970
```

**Saturated, and marginally LOWER with the better generator.** The reason is
structural:

```
                  n_commands  login_attempts  n_events
ACCESS_BRUTE_SSH           0               1         5
RECON_IP_SCAN              0               0         4
DISC_ENV_PROBE             1               1         8
EXEC_SHELL_OPEN            1               1         8
```

Three counts almost fully determine the class, and the generator pins them to
the real distributions by construction (`REAL_COMMAND_COUNTS`). The task is
solved before timing is consulted, so TSTR on the full feature set **cannot
detect temporal fidelity at all.**

Restrict TSTR to timing, and fidelity becomes the whole signal:

```
feature set                        class-blind   class-aware     delta
A_temporal (24)                       0.7755        0.9687      +0.1932
pure timing (15, no counts/calendar)  0.7752        0.9564      +0.1811
structure only (3)                    0.7449        0.8924      +0.1475
```

**So: better temporal fidelity DOES improve real-data predictive performance,
but only where timing is load-bearing.** +0.19 macro-F1 on timing-only features
is large and unambiguous. On the full feature set the gain is invisible because
the structural counts already saturate the 4-class task.

### 13d. Two numbers not to quote carelessly

**0.9996 is not evidence the synthetic data is good.** It is evidence the 4-class
real-supported task is trivial -- `n_commands` and `login_attempts` separate those
classes without any temporal information.

**0.035 (the dataset card) is the 45-class figure against a 16-class real test
set** -- a different and much harder question. Neither number means anything
without saying which task it describes.

---

## 14. Donor provenance, real coverage, and where timing actually pays (2026-11-24)

### 14a. Every generated session records how its timing was obtained

`_bootstrap_sequence` now reports which path it took, and the value rides on each
row as `donor_origin`, through `real_meta.parquet` into `donor_<split>.npy`:

```
donor_exact      copied from a real session of the SAME class and bucket --
                 preserves within-session correlation AND the class's rhythm
donor_bucket     same bucket, DIFFERENT class -- preserves correlation, imports
                 the wrong class's rhythm (the 13a defect)
per_event        no length-matched donor; gaps drawn independently per event
                 type. Marginals right, joint structure wrong.
```

Passed via an out-parameter on `generate_cowrie_events` rather than stamped on
the events, because the events must stay byte-faithful to what real Cowrie
writes. `generate_sessions` now yields 4-tuples.

### 14b. Real coverage is 45.5%, not the 78% section 13b reported

**Section 13b was wrong.** That figure came from asking whether a suitable donor
EXISTED in the pool; it ignored that `_bootstrap_sequence` samples only 24
candidates and rejects any donor more than 50% longer than needed. Measured from
the recorded origin over 18,000 generated sessions:

```
donor_exact    2,098  (11.7%)
donor_bucket   6,094  (33.9%)
per_event      9,808  (54.5%)   <- the majority
any donor      8,192  (45.5%)
```

The split follows real support exactly:

```
exact donor available              reliant on per-event fallback
  EXEC_WGET_EXEC     100.0%          EVASION_LOG_WIPE      88.5%
  EXEC_SHELL_OPEN     99.0%          EXFIL_SCP_DATA        87.8%
  DISC_ENV_PROBE      98.5%          PRIVESC_SUID_EXPLOIT  87.5%
  ACCESS_BRUTE_SSH    97.0%          PERSIST_CRONTAB       87.2%
  RECON_IP_SCAN       85.0%          DISC_SUID_HUNT        87.2%
  EVASION_HIST_ERASE  45.0%          (all 39 synthetic-only ~85-88%)
```

**The cause is a donor-length desert.** Donors exist only at 1-4, 7-9 and 20-40
gaps. Gap counts with NO donor are `[4, 5, 8..22, 41]`, and the synthetic-only
classes sit at a median of 10 gaps -- squarely inside it. Real Cowrie sessions
are either ~7 gaps or ~34; nothing in between exists to copy.

### 14c. Timing-only TSTR, 5 seeds, 95% CI

```
feature set              class-blind          class-aware         delta
A_temporal (24)       0.7759 +/- 0.0126   0.9686 +/- 0.0005     +0.1927
pure timing (15)      0.7784 +/- 0.0133   0.9609 +/- 0.0027     +0.1825
structure only (3)    0.7657 +/- 0.0188   0.8925 +/- 0.0036     +0.1268
```

The intervals are tight and do not overlap, so +0.19 is a real effect rather
than a seed artefact.

### 14d. Novel-behaviour rejection -- the decisive experiment

`DISC_ENV_PROBE` and `EXEC_SHELL_OPEN` have **identical real median structure**:
1 command, 1 login attempt, 8 events. Structural counts cannot separate them, so
anything that does is reading timing.

```
feature set              class-blind          class-aware         delta
A_temporal (24)       0.5457 +/- 0.0189   0.9459 +/- 0.0009     +0.4003
pure timing (15)      0.5584 +/- 0.0198   0.9443 +/- 0.0020     +0.3859
structure only (3)    0.5670 +/- 0.0194   0.8535 +/- 0.0028     +0.2865
                      (0.50 = chance on a balanced 2-class task)
```

**Class-blind donors sit at CHANCE.** The synthetic data was worthless for this
task. Class-aware donors reach 0.946 -- a **+0.40** gain, more than double the
+0.19 on the 4-class problem, precisely because the easy structural signal has
been removed.

### 14e. What this means, and it reframes section 13c

**Temporal fidelity is the difference between a useless model and a working one,
wherever structural counts cannot discriminate.** That is the honest case for the
timing work, and it is measurable.

It also explains the saturated 0.9996 in section 13c: that number was high
because `n_commands` and `login_attempts` solved the task outright. Strip them
and the class-blind generator collapses to chance -- so the full-feature TSTR was
**concealing a generator that could not model behaviour at all, only counts.**
A metric that cannot fail is not a validation.

**And it prices the coverage gap.** 54.5% of generated sessions use `per_event`
sampling, which has the same defect class-blind donors had. Timing-dependent
tasks on the 39 synthetic-only classes should therefore be expected to behave
like the class-blind column -- near chance -- and results must be reported split
by `donor_origin`. That is what `donor_<split>.npy` exists for.

---

## 15. Third capture triaged, NOT incorporated (2026-11-24)

A 23-day capture arrived as `cowrie_logs_20261124/` (687 MB, 24 files, gitignored
by `cowrie_logs_*/`). It landed as `cowrie_logs_24-11-2006` -- a year typo -- and
was renamed 2026-11-24 to match the `cowrie_logs_20261109` convention. It is a
STRICT SUPERSET of `cowrie_logs/`: 100.0% of the old session ids reappear in it.

```
                    OLD (cowrie_logs)    NEW (20261124)
sessions                   114,501            178,738    +56%
distinct src IPs             1,071              2,623   +145%
span                   11-01..11-14       11-01..11-24    13.0 -> 22.9 d
events                     754,063          1,238,268    +64%
distinct cmd texts           1,287              2,842   +121%
micro-states                     7                  7     +0
max login_attempts               1                  2
max n_commands                  28                 28
```

**Third independent confirmation that collecting Cowrie for longer does not
broaden the taxonomy.** 8-day -> 8 classes, 13-day -> 8, 23-day -> 8. Section 3d
said this after two captures; it now holds across three, and 76% more sessions
added zero classes.

The donor-length desert is also unmoved -- sessions with 10-19 gaps go from 4 to
**9** out of 178,738:

```
gaps per session     old       new
1-4               61,641    82,238
7-9               51,564    93,637
10-19 <- desert        4         9
20-40              1,273     2,822
```

**Verdict: worth a rebuild for ONE reason only -- the command pools.** Distinct
command texts more than doubled (1,287 -> 2,842), and command vocabulary is the
thing the generator reproduces well (`C_payload` sits at chance precisely because
it bootstraps real text). `donor_exact` pools also roughly double. It will NOT
fix the 28 synthetic-only classes, the 54.5% per-event fallback rate, or the
desert, because those are properties of what SSH bots do.

**If it is incorporated, use it INSTEAD OF `cowrie_logs/`, never alongside** --
the two overlap completely and pooling would double-count 114,490 sessions.
Every measured constant would need re-deriving: the gap pools, the command
pools, `REAL_COMMAND_COUNTS`, the ttylog table, and the session-shape
percentiles in section 9. Not done; `data/final_v2/` is built from the 13-day
capture.

---

## 16. Group D is deduplicated, and the leak is closed (2026-11-25)

Section 12c's outstanding item. `extract_semantic_batch` now encodes each
DISTINCT command text once and scatters the result back, so identical text
yields a bit-identical embedding by construction. 761,108 distinct of 1,749,809
rows. `data/processed/X_real.npy` and `data/final_v2/` were rebuilt on it
(notebooks 02 then 05).

### 16a. Verified, three ways

**Identical text now gives identical vectors.** 850 command texts appear in both
a `cowrie_real` row and a `simulated_cowrie_events` row. Over 200 of them, the
group-D maxabs difference between the real and the generated row is:

```
before (section 12c)   2.999e-06   for 96.4% of real rows
after                  0.000e+00   for every pair tested
```

The most common text occurs 254,885 times and all sampled rows are byte-equal.

**Within class, group D is now at chance.** Same method as section 12b --
`HistGradientBoostingClassifier(max_iter=120)`, equal n per side, random
sampling, 70/30 stratified, constant columns dropped:

```
class               D_semantic   n/side
ACCESS_BRUTE_SSH       0.5000    14,666
RECON_IP_SCAN          0.5000     8,234
DISC_ENV_PROBE         0.4998    14,667
EXEC_SHELL_OPEN        0.4722     6,504
POOLED                 0.8948    20,000   (was 0.9701)
```

**Pooled stays high and that is expected.** Section 12d: class identity alone is
worth 0.9702 inside the synthetic data, so a pooled figure measures class
composition. 0.8948 says group D still carries class information -- which is its
job -- and the within-class row says it no longer carries provenance. Note
0.8948 lands essentially on the 0.8980 that section 12c measured in RAW space,
which is the number that was never corrupted by the rescaled rounding.

**So group D is usable again, and with it the claim in section 12e** that the
synthetic data is indistinguishable from real in network, payload and semantic
features within a micro-state. Before this, the semantic third of that sentence
was not supported.

### 16b. What was NOT re-measured here

Only group D was re-measured in this section. Section 12b's leave-one-block-out
table was computed with the watermark present, so it was stale rather than
corrected. **Section 17 re-runs the whole suite** and replaces the stale rows
there. The 54.5% `per_event` fallback and every donor figure are unaffected --
dedup touched 30 columns and nothing else.

### 16c. The rebuild reproduces itself

Row counts per split, per generator and per `donor_origin` are identical to the
2026-11-24 build, so the split is a function of the seeds and not of the feature
values. `NaN count: 10,185,865` and `915,320 rows (52.3%)` came back exactly,
confirming dedup touched no temporal feature. The Part 3 gate PASSES train, val,
`test_real` and `test_synth`, all four with 0 NaN after imputation.

Two pooled numbers moved and neither should be read as fidelity (sections 9a,
13d): adversarial AUC 0.9981 -> 0.9921, 45-class TSTR 0.036 -> 0.0278.

### 16d. It also made the pipeline 2.7x faster

Per-cell wall time from the notebooks' own execution metadata:

```
                              before     after
notebook 02, cell 5 (DistilBERT)   54.64 min   17.04 min   <- dedup, 2.3x fewer texts
notebook 02, cell 3 (extractors)   11.40 min    7.37 min   <- chunked to_dict("records")
notebook 02, TOTAL                 66.20 min   24.52 min
notebook 05, TOTAL                  0.50 min    0.52 min
```

`df_real.iterrows()` rebuilt a pandas Series per row across the frame's 17 dtype
blocks. Chunked `to_dict("records")` is value-identical (verified NaN-aware on
6,000 rows spanning all four sources) and saves about 4 minutes.

**A measurement caution worth more than the 4 minutes.** A quick timing taken
*while notebook 02 was running* reported iterrows at 1.000 ms/row -- 2.5x its
true 0.391 ms/row -- and identified cell 3 as a 37-minute bottleneck. It was
never more than 11.4 minutes, and the real cost was always group D at 54.6. Do
not profile this pipeline against a busy machine; read the per-cell
`execution` metadata the notebooks already store instead.

### 16e. Still open after the dedup

- **No model has been trained on `final_v2`.** This was the blocker: group D
  leaked provenance, so any model could learn it. That is now closed, and the
  retrain is an ablation reported per class and per `donor_origin` (11a, 14e).
- **`fit_pca` is unchanged on purpose.** It fits 30 linear axes on a random 50k
  sample; deduplicating there would change the axes and therefore every group-D
  column in both builds, for no measurable gain.
- **The live path still encodes one text per batch**
  (`traffic_gateway.feature_bridge.SemanticEncoder`), so it sits at its own
  ~3e-6 offset from the training embeddings. Pre-existing, now uncorrelated with
  anything, and the reason not to treat group D as high-precision.

### 16f. The quality report was validating arrays that never shipped

`quality_report.json` reported `NaN values: 281635`, failed its shape check, and
gave `A_temporal mean_W=nan` -- for a dataset whose four shipped splits carry
ZERO NaN. One cause for all three: notebook 05 cell 16 passed `X_r_train` and
`X_s_train`, the PRE-pool arrays. `X_pool = np.vstack([X_r_train, X_s_train])`
copies, so cell 10's in-place imputation never reached them.

Fixed by validating the imputed, still-unscaled `X_train`, split into real and
generated with `gen_splits["train"]` (aligned by construction, asserted in cell
9). After the fix:

```
                     before            after
shape_check    FAIL, NaN 281635   PASS, 0 NaN, 45/45 classes
A_temporal W   nan  (nan-poisoned) 618.694  (a real number, and it FAILS)
adversarial    0.9921             0.9929
TSTR           0.0278             0.0323
```

`A_temporal` failing its Wasserstein threshold is a true finding, consistent with
section 12e: timing is the block that does not match. It was previously hidden
behind a NaN.

**Why this mattered more than a cosmetic defect.** A report that fails on a
problem the artifact does not have teaches its readers to ignore it -- and the
two real failures in it (`A_temporal`, adversarial AUC) are the ones a reviewer
should see. The gate still PASSES all four splits through `load_split()`.

The thresholds themselves are NOT recalibrated: `wasserstein` and
`adversarial_auc` compare pooled real against pooled generated, which sections
9a and 12d show measures protocol and class composition. Read the per-block,
within-class table instead.

---

## 17. Source separability re-measured end to end (2026-11-25)

Section 12's experiments were run ad hoc and 12a records what that cost: the
numbers could not be reproduced from the shipped artifact. They are now a
module -- `src/validators/source_separability.py`, run as
`python -m src.validators.source_separability`, results written to
`data/final_v2/source_separability.json`.

It is deliberately NOT `quality_checks.adversarial_auc`, which takes the FIRST n
rows of each side, keeps constant columns and establishes no control. Three
differences matter: equal n per side sampled at RANDOM (the splits are not
source-balanced, so the first n compares different class mixtures), constant
columns dropped (27 of 128 are dead -- they separate nothing but they change
where the tree splits), and a real-vs-real control.

### 17a. The controls hold

```
real vs real,           random half-split    0.5040
synthetic vs synthetic, random half-split    0.4987
```

Both at chance, so every figure below is a real difference rather than an
artefact of the procedure.

### 17b. Group D has gone from the largest leak to inert

```
LEAVE ONE BLOCK OUT         before (12b)        now
ALL 128                        0.9888          0.9522
without D_semantic             0.9453  <-worst 0.9521  <- no effect at all
without A_temporal             0.9768          0.9225  <- now the worst
without B / C / E / F          ~unchanged      ~unchanged

PER BLOCK, POOLED           before (12b)        now
A_temporal                     0.8994          0.9146
B_network                      0.8501          0.8498
C_payload                      0.8966          0.8961
D_semantic                     0.9701          0.8948
E_threat_intel                 n/a (14 dead)   n/a
F_tls_host                     0.5050          0.5047
```

Dropping all 30 group-D columns now moves the pooled AUC by 0.0001. The fall
from 0.9888 to 0.9522 is the leak leaving the dataset, and `A_temporal` is the
only block still carrying source signal.

### 17c. Within class, only timing separates

```
class               A_temp  B_net   C_pay   D_sem   F_tls    ALL   ALL-D
ACCESS_BRUTE_SSH    0.8076  0.5070  0.5000  0.5000  0.4994  0.8037  0.8037
RECON_IP_SCAN       0.8037  0.5738  0.5000  0.5000  0.5534  0.8136  0.8136
DISC_ENV_PROBE      0.9126  0.5025  0.4994  0.4998  0.5000  0.9157  0.9157
EXEC_SHELL_OPEN     0.9201  0.5761  0.5547  0.4722  0.5000  0.9390  0.9380
```

`ALL` and `ALL-D` agree to three decimals in every class -- group D is inert for
provenance, confirmed independently of 16a. So section 12e's claim holds in
full: indistinguishable from real in network, payload AND semantic features
within a micro-state, distinguishable by inter-arrival structure.

### 17d. This AUC is sample-size dependent, and it has been misread already

The `A_temporal` figures above look WORSE than section 13a's post-donor numbers.
They are not. 13a was measured at a smaller n:

```
class               n=2,000   n=5,000   n=max (6.5k-20k)
ACCESS_BRUTE_SSH     0.6939    0.7492    0.8076
RECON_IP_SCAN        0.7951    0.8076    0.8037
DISC_ENV_PROBE       0.8478    0.8862    0.9126
EXEC_SHELL_OPEN      0.8815    0.9222    0.9201
```

`n=5,000` reproduces 13a's `ACCESS_BRUTE_SSH` 0.7492 exactly and its
`DISC_ENV_PROBE` 0.8835 to 0.003. The temporal columns did not change -- the
rebuild reproduced its row counts and its NaN count exactly (16c) -- more rows
simply let the tree find more structure.

**So every adversarial AUC in this project must be quoted with its n**, and two
runs of the same experiment at different n must never be presented as a change.
The module caps at 20,000 per side and logs the n beside every number for
exactly this reason. See ERRORS.md.

A consequence for 17b: section 12b never recorded its n, so its column is
indicative, not exact. The rows measured in a single run under one method --
all of 17a-17c -- are the ones that can be compared with each other.

---

## 18. Which temporal relationships are still missing (2026-11-25)

Section 12e established that timing is the one block that does not reproduce
(`A_temporal` above chance, everything else at it). This localises WHERE, and
prices it. All of it comes out of
`python -m src.validators.source_separability`, which now reports these three
breakdowns, so nothing here is an ad hoc number.

**n is held fixed inside each table.** This AUC climbs with n on unchanged data
(17d), so a breakdown measured at whatever n each cell happens to have is a
table of sample sizes.

### 18a. The marginals are close. The JOINT structure is what is missing

One temporal feature at a time, within class, real vs generated, n=5,000/side:

```
feature                 BRUTE   SCAN   PROBE  SHELL   worst
session_day_of_week     0.592  0.543  0.587  0.756   0.756   <- not timing at all
iat_skew                0.581  0.739  0.541  0.585   0.739
frac_sub100ms           0.555  0.717  0.527  0.627   0.717
iat_cv                  0.535  0.714  0.538  0.536   0.714
iat_std                 0.551  0.709  0.557  0.542   0.709
frac_sub1s              0.523  0.694  0.514  0.614   0.694
inter_burst_gap_std     0.552  0.693  0.565  0.543   0.693
iat_mean                0.554  0.685  0.534  0.515   0.685
events_per_sec          0.566  0.684  0.538  0.510   0.684
iat_median              0.578  0.683  0.564  0.528   0.683
iat_max                 0.545  0.667  0.538  0.539   0.667
log_session_duration    0.562  0.648  0.544  0.514   0.648
inter_burst_gap_mean    0.561  0.648  0.556  0.523   0.648
iat_min                 0.547  0.647  0.538  0.517   0.647
session_duration_s      0.565  0.644  0.546  0.513   0.644
session_hour            0.523  0.531  0.633  0.516   0.633
burst_mean_size         0.512  0.611  0.502  0.583   0.611
burst_count             0.509  0.605  0.523  0.589   0.605
time_to_first_auth_s    0.568  0.583  0.564  0.517   0.583
iat_kurt                0.582  0.572  0.562  0.568   0.582
frac_over30s            0.500  0.576  0.500  0.552   0.576
time_to_first_cmd_s     0.500  0.500  0.557  0.527   0.557
commands_per_min        0.500  0.500  0.545  0.517   0.545
is_business_hours       0.505  0.482  0.537  0.522   0.537   <- best match
```

**No single feature exceeds 0.76, and the 24 together reach 0.75-0.92 at the
same n** (17c, measured at n=5,000 in 17d). So the per-feature distributions are
close to right -- that is what the section 9 calibration bought -- and what is
missing is how the statistics CO-VARY inside one session. A real session with a
high `iat_std` has a particular `iat_skew` and `frac_sub100ms` to go with it;
the generated one does not.

That is a statement about `_bootstrap_sequence`: copying a real gap sequence
preserves the covariance, and drawing each gap independently cannot, however
well each marginal is calibrated.

**One entry is not inter-arrival structure at all.** `session_day_of_week` is
the single most separable temporal feature (0.756 on `EXEC_SHELL_OPEN`), and
`session_hour` reaches 0.633 on `DISC_ENV_PROBE`. The generator's calendar
distribution does not match the capture's. That is a few hours of work and the
cheapest fidelity gain left in the block.

### 18b. There are two timing tiers, and they are far apart

`donor_exact` copies a real session of the same class and bucket;
`donor_bucket` borrows another class's rhythm; `per_event` draws each gap
independently. Compared at MATCHED n, with `donor_exact` re-measured at the
fallback group's own n:

```
class              fallback       n/side   fallback   donor_exact at same n
ACCESS_BRUTE_SSH   per_event        280     0.9667          0.5852
RECON_IP_SCAN      donor_bucket   2,193     1.0000          0.7178
```

Copied timing sits near chance. Independently drawn timing is almost perfectly
identifiable, and borrowed-from-the-wrong-class timing is PERFECTLY
identifiable. (The other six cells hold 6-162 rows -- these four classes almost
never take a fallback -- and are reported as unmeasurable rather than filled
with a number.)

Now the exposure, and this is the part that matters:

```
                            donor_exact  donor_bucket   per_event
the 4 real-supported classes     94.9%        4.0%         1.1%
the other 41 classes              3.4%       36.9%        59.7%
```

**The broken timing is concentrated almost entirely in the classes with no real
data** -- the ones where a model has nothing else to fall back on. The cause is
the donor-length desert (14b): real Cowrie sessions have either ~7 gaps or ~34,
the generated mid-depth classes sit at ~10, and no real session of that shape
exists to copy. Three captures across 8, 13 and 23 days confirm it (15), so this
is a property of SSH bot behaviour, not a bug.

### 18c. For 46.7% of rows the sequence-level relationships do not exist at all

Share of train rows where each temporal feature was MEASURED rather than imputed:

```
100.0%   iat_mean, session_duration_s, log_session_duration, events_per_sec,
         commands_per_min, time_to_first_auth_s, time_to_first_cmd_s,
         session_day_of_week, session_hour, is_business_hours
 89.3%   iat_std, iat_min, iat_max, iat_cv        <- CIC ships real Flow IAT stats
 53.3%   iat_median, iat_skew, iat_kurt, frac_sub100ms, frac_sub1s,
         frac_over30s, burst_count, burst_mean_size, inter_burst_gap_mean,
         inter_burst_gap_std
```

For every netflow row those last ten are the train median -- a constant. A flow
summary cannot report burst structure or a gap distribution's shape. So across
46.7% of the corpus, "temporal relationship" means four summary numbers and
nothing about sequence. This is honest rather than fabricated (that is Part 0's
whole point, and `M_*.npy` records it per row), but it is a ceiling: no
generator work raises it, only a different data source would.

### 18d. And one gap no generator work can close

Everything above is WITHIN a session. The schema carries nothing ACROSS
sessions: no inter-session gap, no per-source-IP campaign ordering, no
return-visit interval. `attacker_repeat_visitor` is 99.06% constant in the real
capture because 1,071 IPs produced 114,490 sessions (section 8).

For a honeypot that reconfigures BETWEEN sessions -- which is what this project
builds -- that is arguably the most consequential missing relationship, and it is
a schema limitation rather than a fidelity one. It is also the most interesting
one: see ROADMAP.

### 18e. How much it matters for real-world detection

**For the four anchored classes: almost not at all.** `n_commands`,
`login_attempts` and `n_events` nearly determine them, which is why full-feature
TSTR saturates at 0.9996 (13c), and 94.9% of their generated rows carry copied
timing anyway. Detection claims for brute-force, scanning, env-probing and
shell-open are defensible.

**For the 28 synthetic-only classes: it matters a great deal, and the news is
bad.** 14d is the proof -- strip the structural counts and class-blind timing
scores at chance while class-aware reaches 0.946. Those classes sit at 59.7%
`per_event`, the regime that measures 0.9667 against real data. So any
timing-dependent detection of persistence, privilege escalation or exfiltration
rests on timing the generator demonstrably cannot model. A model trained here
reads counts and command text for those classes; its temporal branch is
decoration.

**One mitigating fact from how the system is built.** MT3 classifies only at
`cowrie.session.closed` and consumes session SUMMARIES, never a live gap
sequence. The joint-structure gap therefore degrades features the model already
uses coarsely. That caps the damage; it does not remove it.

### 18f. What to do, cheapest first

1. **Fix the calendar distributions** (hour of day, day of week). Biggest single
   marginal in 18a, smallest effort, and it is not even a timing-model problem.
2. **Report every result split by `donor_origin`.** Free -- `donor_*.npy` already
   ships -- and it stops the 18b asymmetry being averaged away.
3. **Restrict timing-dependent claims to `donor_exact` rows**, or state the
   fallback share beside the claim.
4. **Do NOT synthesise 10-19-gap templates.** There is no real session of that
   shape to learn from, so anything generated there is invention. Closing it for
   real needs a higher-interaction honeypot that elicits mid-length sessions, or
   the limit accepted in writing.
5. **Cross-session features** (18d) are a schema change, not a generator fix.

---

## 19. BENIGN is a label now, and the sequences ship (2026-11-25)

Two changes, both asked for after section 18's assessment.

### 19a. BENIGN (label 45) is IN the splits

`data/final_v2/` is now **1,749,809 rows / 46 labels**:

```
split        rows        labels   BENIGN
train     1,466,828        46     163,602
val         162,981        46      18,178
test_real    60,000        17      11,220
test_synth   60,000        45           0
```

`test_synth` has no benign rows and cannot: benign exists only in netflow,
which is measured data, so it lands only in the real splits. The Part 3 gate
PASSES all four, 0 NaN.

**Why this reverses section 5's two-stage-gate preference.** Benign is still not
a kill-chain state -- no MITRE technique, no phase, no DAG edges -- so BENIGN is
a LABEL and is deliberately NOT added to `MICRO_STATES` (`configs/schema.py`:
`BENIGN_IDX = 45`, `N_LABELS = 46`). But shipping it outside the splits left MT3
a closed set over 45 attack classes. 02-11-2026 FINDINGS.md finding #1 measured
the cost on real traffic: four benign sessions all labelled attacks, one
auto-blacklisted, and on Heralding records a bare TCP connect returned
`DISC_NETSTAT_SCAN` at confidence **1.000** -- clearing the 0.5 auto-blacklist
threshold. The wrong answers are confident, so a confidence gate was never the
fix; the model needed somewhere to put "not an attack".

**One line of code is why this stayed broken.** `mt3_pipeline/data.py` validated
`y.max() >= N_CLASSES` with `N_CLASSES = 45`, so the training entry point
REJECTED any dataset carrying label 45. The bound is now `N_LABELS`, which
admits BENIGN and still rejects 46.

**The caveat, which is in the code as well as here.** All 193,000 benign rows are
CIC/UNSW netflow (100,000 + 93,000) and **ZERO are honeypot sessions**, because
real honeypot traffic has none. Netflow and Cowrie rows separate at AUC 1.0000
on source alone (12b), so a model can reach near-perfect BENIGN recall by
learning "netflow-shaped" -- the data source, not the concept. Benign SSH
sessions do not exist in any capture we hold, so this cannot be fixed here, only
stated. `X_benign.npy` is still written for anyone building the two-stage gate
instead.

### 19b. `seq_<split>.npy` ships the micro-state WALK

`y_*` carries one label per session -- the deepest state reached -- so until now
nothing recorded which states a session passed through. `micro_state_sequence`
rides from notebook 01 through `real_meta.parquet` (notebook 02) into
`seq_<split>.npy`, split by the same partition as `gen_*` and `donor_*`.

```
seq_train       471,850 multi-state of 1,466,828
seq_val          52,503
seq_test_real      3,080   <- all cowrie_real
seq_test_synth    43,045
```

### 19c. KCVR had never actually been measured, and the first measurement is a finding

Notebook 05's KCVR cell looked for `tabsyn_meta.parquet` and
`great_meta.parquet` -- files no build has ever produced, one of them behind a
literal `if False` -- so it printed "No sequence metadata found" on every build
and the kill-chain violation rate was never computed. It now reads the shipped
sequences:

```
split        KCVR     over
train       0.0832    471,850 multi-state sessions
val         0.0845     52,503
test_real   0.8851      3,080     <- REAL Cowrie sessions
test_synth  0.0000     43,045     <- generated
```

**Generated walks are 100% DAG-valid. Real multi-state sessions violate the DAG
88.5% of the time.** The generator cannot violate it -- `cowrie_simulator` walks
`KILL_CHAIN_DAG` backwards from the label by construction -- and train/val sit at
8.3% only because a few per cent of their multi-state rows are real.

Why the real ones fail, over the 3,080 multi-state rows in `test_real` (every one
`cowrie_real`):

```
BAD_EDGE,  phase-monotone      2,688  (87.3%)   e.g. ACCESS_BRUTE_SSH -> DISC_ENV_PROBE, phases [1,3]
fully valid                      354  (11.5%)   e.g. ACCESS_BRUTE_SSH -> EXEC_SHELL_OPEN, phases [1,2]
BAD_EDGE, not monotone            38  ( 1.2%)   phases [1,2,...,2,8,4,2]
```

The dominant failure is a **phase skip**: brute-force straight to environment
discovery, skipping Execution. `KILL_CHAIN_DAG` does allow skips -- 15 of its 102
edges jump more than one phase -- just not that one. A handful of real sessions
also run exfiltration and then go back to discovery, which no monotone model
permits and which is ordinary attacker behaviour.

**So `KILL_CHAIN_DAG` is a modelling assumption that real traffic contradicts**,
and the honest reading is not "the real data is invalid" but "the DAG is drawn
tighter than observed behaviour". Two consequences:

1. **It was lucky that the DAG never entered training** (DECISIONS.md records
   this as a known gap, with MT3 having no CRF despite the naming). Enforcing it
   would have taught the model to rule out what real attackers do most.
2. **KCVR cannot be reported as a dataset quality metric without saying which
   half it describes.** 0.0000 on generated data measures the generator obeying
   its own rule. 0.8851 on real data measures the rule being wrong.

### 19d. What this does not change

Row counts per split, per generator and per `donor_origin` are unchanged for the
non-benign rows; `NaN count: 10,185,865` came back exactly again. Pooled figures
moved slightly with the extra 193,000 rows and the regenerated group D:
adversarial AUC 0.9929 -> 0.9935, 45-class TSTR 0.0323 -> 0.0351. Neither is a
fidelity measure (9a, 13d). The `A_temporal` Wasserstein check still FAILS
(568.3), which is the same true finding section 16f uncovered.

### 19e. Open after this

- **The live path still assumes 45 outputs.** `feature_bridge.MT3Inference`, the
  trained checkpoint, `configurator.py` and the dashboard label maps are all
  45-class. A 46-output model needs them updated together; nothing was touched
  here, so the old checkpoint keeps working.
- **A rejection mechanism is still missing.** BENIGN gives the model somewhere to
  put "not an attack"; it does not give it a way to say "none of the above".
  `ood_distance` exists as an honesty signal and cannot gate -- live sessions
  measure 425-642 against a training p95 of 15.4.
- **KCVR on real data wants a decision**: loosen `KILL_CHAIN_DAG` to match
  observed transitions, or keep it tight and state that it is prescriptive. Do
  not quietly report 0.0000.

---

## 20. The DAG is prescriptive, and observed transitions are recorded beside it (2026-11-25)

Section 19c found that real multi-state sessions violate `KILL_CHAIN_DAG`.
This is the decision taken on it, and the artifact that implements it.

**Decided with the owner, 2026-11-25:**

1. **Keep the existing DAG as a prescriptive kill-chain reference.** It is a
   MITRE-derived taxonomy artifact, not a model of behaviour.
2. **Do not reject a real session for violating its edges.** Already true in
   practice -- `kill_chain_simulator.filter_invalid_sequences` exists and is
   called by nothing. It must never be pointed at real data.
3. **Do not claim DAG compliance as realism** for generated sessions.
4. **Record observed transitions separately and measure their agreement with
   the DAG** -- the same pattern section 8a uses for labels: keep the intended
   value, record what was observed, report the gap.

Item 4 is now `src/validators/transition_agreement.py`, run as
`python -m src.validators.transition_agreement`, writing
`data/final_v2/transition_agreement.json`. 9 tests.

### 20a. What real attackers actually do: 16 transitions, 3 of them in the DAG

52,848 of 114,490 real Cowrie sessions (46.2%) carry a multi-state walk. They
contain **16 distinct transitions**, self-loops excluded:

```
transition                                   n      phases  in DAG?
ACCESS_BRUTE_SSH  -> DISC_ENV_PROBE       45,711    1->3    NO (forward_skip)
ACCESS_BRUTE_SSH  -> EXEC_SHELL_OPEN       7,016    1->2    yes
EXEC_SHELL_OPEN   -> EXFIL_SCP_DATA          556    2->8    NO (forward_skip)
EXFIL_SCP_DATA    -> PRIVESC_SUDO_ABUSE      532    8->4    NO (backward)
PRIVESC_SUDO_ABUSE-> EXEC_SHELL_OPEN         532    4->2    NO (backward)
ACCESS_BRUTE_SSH  -> EXEC_WGET_EXEC          100    1->2    NO (forward_adjacent)
ACCESS_BRUTE_SSH  -> EXFIL_SCP_DATA           16    1->8    NO (forward_skip)
EXEC_SHELL_OPEN   -> DISC_NETSTAT_SCAN        11    2->3    yes
DISC_NETSTAT_SCAN -> DISC_ENV_PROBE           11    3->3    NO (same_phase)
DISC_ENV_PROBE    -> DISC_PROC_ENUM           11    3->3    yes
DISC_PROC_ENUM    -> EXEC_SHELL_OPEN          10    3->2    NO (backward)
EXFIL_SCP_DATA    -> EXEC_SHELL_OPEN           5    8->2    NO (backward)
ACCESS_BRUTE_SSH  -> EVASION_HIST_ERASE        5    1->6    NO (forward_skip)
DISC_ENV_PROBE    -> EXEC_WGET_EXEC            1    3->2    NO (backward)
(+2 more edge types)
```

```
agreement           12.9% of instances;  3 of 16 edge types
instances by kind   forward_skip 46,290   permitted 7,038   backward 1,080
                    forward_adjacent 100   same_phase 11
```

**One transition is 83.8% of all real transitions and the DAG forbids it:**
`ACCESS_BRUTE_SSH -> DISC_ENV_PROBE`, brute force straight into environment
discovery with Execution skipped.

Three kinds of disagreement, and they are not the same defect:

- **forward skips** (46,290 instances) -- a gap in the DAG's adjacency list.
- **backward steps** (1,080) -- exfiltration back to privilege escalation, then
  to execution, 532 instances each. This contradicts phase MONOTONICITY, not
  just an edge, and it is ordinary attacker behaviour.
- **same-phase and forward-adjacent edges that are simply absent** (111). Note
  `ACCESS_BRUTE_SSH -> EXEC_WGET_EXEC` is phase 1->2, intuitively sensible, and
  still not in the DAG -- so the gaps are not only about skipping.

### 20b. The mirror statistic, which is the stronger one

```
                              DAG edge types exercised
real honeypot traffic              3 of 102   ( 2.9%)
generated sessions               101 of 102   (99.0%)
```

**The DAG is 97% hypothetical.** 99 of its 102 edges have never been observed in
13 days and 114,490 real sessions, and the only thing that exercises them is our
own generator. That is the 28-synthetic-only-classes problem restated as
transitions, and it is a cleaner way to say it than any class count.

### 20c. Agreement on GENERATED sequences is a tautology, not a result

```
generated   100.0% of instances, 101 of 101 edge types in the DAG
```

`cowrie_simulator` walks `KILL_CHAIN_DAG` backwards from the intended label, so
it **cannot** emit a forbidden edge. The 100% measures the generator obeying a
rule it was built from. Report it only as a build check, never as fidelity --
same reading as KCVR 0.0000 in section 19c.

### 20d. Why the DAG is NOT simply loosened to fit

Tempting, and wrong for two reasons.

**The DAG is load-bearing for label coherence, not for realism.** The generator
walks it backwards from the intended label so the labelled state is the
session's DEEPEST state. Section 8's finding 2 is what happens otherwise:
pinning the label to the START of the walk made 57.5% of RECON-labelled sessions
escalate into phases 2-4 and issue shell commands, which no real reconnaissance
session does. Removing the constraint does not buy realism, it buys
unconstrained invention.

**There is nothing to replace it with for most of the taxonomy.** 16 observed
transitions exist, across 8 classes. For the 28 synthetic-only classes there are
zero observed transitions, so a DAG-free generator would be inventing structure
with no evidence at all -- strictly worse than a documented, citable assumption.

**The upgrade path, if the generator is revisited:** stamp each generated
session with `transition_source = observed | dag`, the `donor_origin` pattern
(14a). Sample the 16 observed transitions where the class supports it, fall back
to the DAG where it does not, and let realism claims attach only to the
`observed` rows. Not done.

### 20e. How to write this up

Say: the taxonomy's transition model is prescriptive, derived from MITRE
ATT&CK's kill-chain ordering; measured against 13 days of real SSH honeypot
traffic it accounts for 12.9% of observed transition instances and 3 of 16
observed edge types, while 99 of its 102 edges are never observed. Real
attackers skip phases (84.9% of transitions) and occasionally move backwards
through them (2.0%).

Do not say the real data is invalid, and do not quote the generated 100%.

---

## 21. The split leaked by VALUE, and three different things caused it (2026-11-25)

Found while answering "is the data still linearly separable". `test_real` was
**33.42% byte-identical to a row in `X_train`** -- worse than the 29.74%
recorded for `data/final/` and retired with it. It survived the entire rebuild
because the figure was never re-measured after `final_v2` was built.

Notebook 05 split disjointly by INDEX. Three independent mechanisms then made
distinct sessions identical, and each had to be fixed separately:

```
pass     mechanism                                        test_real leak
start    index-based split                                    33.42%
cell 9   group by post-imputation identity                     0.36%
cell 10  median fill coinciding with a measured value          0.36%
cell 14  float32 scaling collapsing distinct rows               0.00%
```

### 21a. Imputation manufactures the duplicates

The RAW feature matrix is **99.8% distinct**. After filling 10-11 temporal
columns with a per-column constant, only **82.5%** is -- 306,017 rows (17.5%)
become a byte-copy of another row:

```
rows that become a copy of another row, by source
  unsw_transfer   53.6%     supplies only iat_mean; 23 of 24 columns filled
  cic_transfer    33.0%
  simulated        0.8%
  cowrie_real      0.2%
```

So this is a second-order cost of the Part 0 imputation decision (10g), and it
lands hardest exactly where `test_real` draws most of its rows. Cell 9 now
groups rows by the identity they will have AFTER imputation -- same NaN mask and
same measured values, which is precisely the equivalence class a per-column fill
produces -- and gives each group exactly one split.

**One global pass, not one per subset.** Splitting the real and synthetic halves
separately let a group holding both a real and a generated row be claimed twice:
29 groups, 27 leaked rows. A group spanning that boundary now goes to TRAIN,
since the test splits must be source-pure anyway.

**`np.unique(X, axis=0)` is the obvious grouping and it OOM-killed the kernel** --
it copies the full 1.75M x 128 matrix and sorts it. Replaced with a chunked
64-bit row hash: 2 seconds, negligible memory. A hash collision only MERGES two
groups, which makes the split more conservative rather than leaky.

### 21b. An imputed median is a real number

A row whose NaN cell is filled with the column median can become identical to a
different row that MEASURED that same value. Different pre-imputation groups,
identical outcome. This cannot be grouped away -- the medians depend on the train
split, which would then depend on the medians -- so cell 10 measures it after
imputation and drops the offenders from the held-out splits.

### 21c. Scaling collapses rows too, and this was the stubborn one

Cells 9 and 10 both honestly reported zero while the shipped arrays still leaked
216 `test_real` rows. `scaler.scale_` reaches **879,385**, so dividing by it
crushes values that differ by ~1 onto the same float32. Distinct sessions,
indistinguishable features.

Not leaked information in the usual sense -- nothing could tell those rows apart
at that precision -- but a memorised train row still scores the test row, which
is what the 33.42% did at scale. Cell 14 drops them, because the scaled arrays
are the last point where it can be settled.

**Each pass now asserts its own guarantee**, so none of this can regress in
silence. Cost: 404 of ~283,000 held-out rows (0.1%), and split sizes are
approximate because a group is indivisible.

```
train 1,466,849   val 162,767   test_real 59,784   test_synth 60,005
duplication with train: 0 / 0 / 0   (verified on the shipped arrays)
```

`test_real` holds **16** labels, down from 17: grouping constrains which rows can
be held out and a class that previously had a support of 1 there no longer
appears. No earlier `test_real` figure is comparable row-for-row.

### 21d. Three-way comparison on the clean split

All three trained under one protocol -- same splits, frozen scaler,
`weighted_ce` + `balanced`, same metrics, same seed -- so the only difference is
the model. `train_baseline.py --model linear|cnn_lstm` exists so the two
baselines cannot drift apart from each other.

```
model          params   | test_real  exclB  BENIGN    acc | test_synth    acc
linear probe    5,934   |   0.3835  0.3853  0.7114  0.7463 |    0.6007  0.6177
CNN-LSTM      189,710   |   0.4413  0.4416  0.8625  0.8186 |    0.6576  0.6869
MT3         3,759,767   |   0.5507  0.5636  0.9149  0.8908 |    0.7186  0.7285
```

MT3: best val macro-F1 0.7566 @ epoch 34/40; `test_real` phase F1 0.6692;
`macro_f1_all45` 0.1916 over 46 labels.

**The architecture gap is real now, which it was not on `data/final/`:**

```
floor-to-ceiling spread on test_real
data/final/ (clean col)   0.7551 -> 0.8187    0.064    MT3 vs CNN-LSTM p=0.617, a tie
final_v2 (clean split)    0.3835 -> 0.5507    0.167    2.6x wider
final_v2, excl BENIGN     0.3853 -> 0.5636    0.178
```

Three separated tiers: CNN-LSTM beats the probe by **+0.058** and MT3 beats
CNN-LSTM by **+0.109** (excl BENIGN: +0.056 and +0.122). On the old build a
5,805-parameter linear layer reached macro-F1 0.7681 at **0.9930 accuracy** and
MT3 beat it by 0.06 -- the benchmark could not tell architectures apart because
the task was close to linearly separable. Removing the fabricated temporal block
and the group-D watermark removed that shortcut.

**BENIGN behaves exactly as section 19a warned.** It is every model's easiest
class (0.711 / 0.863 / 0.915) and all 193,000 benign rows are netflow, which
separates from Cowrie at AUC 1.0000 on source alone. Quote the `exclB` column
for any claim about the attack taxonomy.

### 21e. What the leak was actually worth, and a wrong prediction of mine

```
test_real macro-F1    leaking split -> clean split
linear probe             0.3515    ->   0.3835    +0.032
CNN-LSTM                 0.4202    ->   0.4413    +0.021
MT3                      0.5704    ->   0.5507    -0.020
```

**Small, and not in one direction.** The two weak models improved and MT3 fell
slightly. So the 33.42% was not inflating the headline -- it was adding easy but
oddly-distributed rows that helped a weak model and marginally hurt a strong one.
Every qualitative conclusion above survives it.

**A prediction I got wrong, recorded because the reasoning was the error.** From
the leaking run I filtered the duplicate rows out of `test_real` post hoc and
estimated MT3 would retrain to 0.6175. It came back 0.5507 -- below even its
leaking-split score. Filtering the TEST set cannot estimate a retrain, because
the fix also changes the TRAINING distribution: duplicate groups are now
concentrated in train, which makes train more redundant and the held-out rows
genuinely harder. A post-hoc subset answers "how would this model score on
cleaner rows", not "what happens if the split is fixed".

---

## 22. Results per `donor_origin`, which 11a required and nothing did (2026-11-25)

`python -m ml_analytics.mt3_pipeline.report_donor`, writing
`data/final_v2/donor_origin_report.json`. 4 tests.

Only `test_synth` carries donor origins -- `test_real` rows were measured, not
generated, so its column is `measured` throughout and the tool says so rather
than inventing a breakdown.

### 22a. The pooled table is confounded, and inverted

```
pooled on test_synth        exact    bucket   per_event
linear probe               0.6965    0.6881     0.5520
CNN-LSTM                   0.6562    0.6916     0.6328
MT3                        0.7402    0.7176     0.6924

rows / classes             6,907/6  20,412/43  32,686/44
MT3 accuracy               0.6990    0.4353     0.9179   <- inverted vs macro-F1
```

Whether an exact donor exists is a property of the CLASS (14b), so the three
groups hold different classes by construction -- 6 against 43 against 44. A
pooled score therefore measures class composition, the same trap section 12d
documents for adversarial AUC. The inversion makes it obvious: `per_event` has
MT3's best accuracy (0.9179) and its worst macro-F1 (0.6924), because the
`per_event` classes are the balanced synthetic-only ones with ~1,100 rows each.

**Do not quote the pooled row.** It is printed only with its composition beside
it, so the confound is visible rather than hidden.

### 22b. Paired within class: `per_event` timing is measurably worse

For each class holding at least 100 rows under both origins, the model's RECALL
on that class under each. The class is held fixed, so the difference is about
how the timing was produced and nothing else. Recall rather than F1 because it
is defined per row and does not shift when the subset changes the negative set.
28 of 45 classes qualify.

```
model          mean delta  median  bucket wins  per_event wins  wilcoxon p
linear probe      +0.1969  +0.1876      27            1          ~0
CNN-LSTM          +0.0933  +0.0621      23            5          3e-06
MT3               +0.0355  +0.0207      23            5          3.7e-05
```

**`donor_bucket` beats `per_event` for every model, significantly.** This is
section 14e's prediction confirmed on a trained model rather than on an
adversarial classifier: `per_event` draws each gap independently, so the
marginals are right and the within-session joint structure is gone, and that
costs real classification accuracy.

Worst affected classes are the deep ones, consistently across models:

```
MT3, largest paired gaps      bucket   per_event    delta
EXFIL_CURL_C2                 0.9536     0.8079    +0.1457
EXFIL_TUNNEL_NGROK            0.9124     0.8035    +0.1089
EVASION_CHMOD_HIDE            0.9769     0.8775    +0.0994
EXFIL_DNS_TUNNEL              0.9403     0.8455    +0.0948
LATERAL_SSH_SPREAD            0.9670     0.8743    +0.0926
```

### 22c. The gap shrinks as the model gets stronger, and that is the real finding

```
linear probe   +0.1969
CNN-LSTM       +0.0933      47% of the probe's gap
MT3            +0.0355      18% of the probe's gap
```

A stronger model recovers most of what the broken timing costs. Two things
follow, and they pull in opposite directions:

- **The 54.5% `per_event` fallback is a real defect with a measurable price**,
  and it is not hypothetical: it costs the probe ~0.20 recall on the affected
  classes.
- **It is not the binding constraint on MT3.** 0.036 mean recall is small next to
  the 0.24 that separates MT3 from the probe. Fixing the donor desert -- which
  14b says is impossible anyway, since no real session of that shape exists --
  would buy MT3 very little.

So the honest framing for the paper: temporal fidelity measurably affects
classification, the effect is strongest for weak models, and `donor_origin` must
ship with the dataset so anyone can check it. It does.

### 22d. What this does NOT show

The comparison is `donor_bucket` against `per_event`. **`donor_exact` cannot be
paired broadly** -- it exists for only 6 classes, and only `RECON_IP_SCAN` holds
enough rows under both exact and bucket to compare. So the question "does a
same-class donor beat a wrong-class donor on a trained model" is still open; 13a
answered it for adversarial AUC (0.9756 -> 0.9127) but not for classification.

Nothing here touches `test_real`. The donor column is a property of generated
sessions, so the real-data headline cannot be split this way, and the 28
synthetic-only classes remain unevaluable against real traffic.

---

## 23. Which classes a per-class metric may average over (2026-11-25)

MT3's headline on `test_real` is **macro-F1 0.5507**, and it is not a statement
about the model. Macro-F1 weights every class equally regardless of size, and
our classes are not remotely equal:

```
                      classes    rows    share of the macro average
support >= 500            7     59,132              44%
support <  500            9        652              56%
```

**652 real sessions -- 1.1% of the test set -- decide more than half the
headline.** `EXFIL_SCP_DATA` has **2 rows**, scores F1 0.0, and counts for 6% of
the average on its own.

### 23a. The rule, and why it is a confidence interval and not a round number

A per-class recall measured on *n* rows has a 95% CI half-width of about
`1.96 * sqrt(0.25/n)`. Accepting +/-0.10 requires **n >= 97**, so that is the
threshold: `metrics.MIN_SUPPORT_CI10`. Every `classification_metrics` call now
emits a `sufficient_support` block beside the unrestricted numbers.

```
CI accepted    min n    classes    macro-F1 (MT3)    coverage
+/- 0.20          25       13          0.6340         100.0%
+/- 0.10          97       10          0.7387          99.6%     <- chosen
+/- 0.05         385        7          0.8825          98.9%
```

**The threshold had to be fixed BEFORE any per-class F1 was looked at**, and the
reason is measurable: on `test_real`, support and per-class F1 correlate at
**spearman 0.856**. Any frequency-based cut therefore selects, as a side effect,
the classes the model happens to win -- so a threshold picked afterwards is
indistinguishable from cherry-picking even when the intent was honest. The CI
derivation is the defence: it is a claim about measurement precision that makes
no reference to our results.

+/-0.10 was taken over +/-0.05 deliberately. 0.8825 over 7 classes is the better
number and the worse argument: it keeps under half the observed classes and
invites "you dropped the hard ones". 10 of 16, covering 99.6% of real sessions,
is defensible on its face.

### 23b. All three models, both ways

```
model          params     all 16 classes    n >= 97 (10 classes)    coverage
linear probe    5,934         0.3835              0.5339              99.6%
CNN-LSTM      189,710         0.4413              0.6118              99.6%
MT3         3,759,767         0.5507              0.7387              99.6%
```

The subset does not flatter one architecture: floor-to-ceiling spread is 0.205
on the subset against 0.167 on all 16, so the ablation conclusion of section 21d
is unchanged.

### 23c. Exactly what is excluded

```
EXFIL_SCP_DATA         2 rows      F1 0.0000
EXEC_WGET_EXEC         6           0.2791
LATERAL_SSH_SPREAD    12           0.2917
EXEC_CURL_BASH        40           0.1194
EXEC_MEMFD_EXEC       95           0.3434
ACCESS_BRUTE_HTTP     96           0.3933
                     ---
                     251 rows of 59,784  (0.4%)
```

Two of the six -- `EXFIL_SCP_DATA` (36 real sessions corpus-wide) and
`EXEC_WGET_EXEC` (100) -- are already listed as **trace honeypot only** in
CLAUDE.md's class-anchoring table, written long before any of these model
results existed. The rule is therefore making an existing documented
distinction operational, not inventing a convenient one.

### 23d. How to report it

1. **Name it "classes with sufficient real support", never "the important
   classes".** The first is a checkable claim about the data; the second is a
   claim about the world that would have to be defended separately.
2. **Always print the unrestricted number beside it.** The block is additive --
   `macro_f1` never goes away, and `format_metrics_line` shows both.
3. **Name every excluded class with its support** (23c). Nothing hidden means
   nothing to accuse.
4. **Quote the coverage.** 99.6% is the legitimacy argument in one number.

### 23e. The question this invites, and the answer

*"If only 10 of 46 classes can be evaluated, what are the other 36 for?"*

It is a scope question, not a metrics question, and the answer is already in 3d
and 15: the 46 labels are the MITRE-mapped space the honeypot can act on; 18
have some real evidence, 10 have enough to measure, 28 rest on synthetic data
alone. Three captures over 8, 13 and 23 days produced the same 8 micro-states,
so this is a property of what SSH bots do rather than a collection failure.
Broadening it needs the other honeypots in MULTI_HONEYPOT.md -- a web or auth
honeypot would give `ACCESS_BRUTE_HTTP` (96 rows today) real support.

**The recommended headline set**, in this order:

```
phase accuracy                       0.9366     what the system acts on
weighted F1, all 16 classes          0.9082
macro-F1, 10 classes with n >= 97    0.7387     covers 99.6% of real sessions
macro-F1, all 16 observed classes    0.5507     the strict number
```

Do not reach back for the retired 0.8276. It was measured on a build with a
fabricated temporal block in 60.3% of train rows, a group-D provenance
watermark readable at AUC 0.97, and 29.74% train/test duplication.

---

## 24. Heralding anchors two classes that had no real evidence at all (2026-11-26)

`heralding_logs_20261126/` arrived: 11 days of the credential honeypot Anusha
deployed on 2026-11-14, running alongside Cowrie on the same Oracle VM. **Read
and measured, NOT incorporated** -- the same status section 15 gave the 23-day
Cowrie capture, and for a related reason.

**It was not gitignored.** 32 MB of attacker-written logs, plus `https.pem`
-- a private key. The `cowrie_logs/` near-miss (section 8) repeating: that
pattern was written `cowrie_logs_*/` and missed the unsuffixed name, leaving
440 MB one `git add -A` from GitHub. Fixed in `f5c0cb0` with all three forms.

### 24a. The capture

```
40,565 attacker sessions    3,078 source IPs    11 days, still running
71.9% attempted a login     38,965 auth attempts    672 distinct credential pairs
4 own test sessions excluded per CAPTURE_NOTES (source 171.76.81.68)

telnet 30,340   vnc 3,195   http 2,600   https 2,503
pop3 577   smtp 543   imap 438   ftp 369
```

The credentials are an IoT botnet dictionary, not human guessing:
`enable/linuxshell` 4,302, `system/shell` 2,700, `admin/admin` 1,036,
`root/xc3511` 822 -- the last straight off the Mirai list.

`duration` is 30.00 s at the median AND the maximum. That is Heralding's
timeout, not attacker behaviour, and nothing temporal should be read from it.

### 24b. What the rule labeller assigns

`src/parsers/heralding_parser.label_session`, which already existed
(MULTI_HONEYPOT 7.6). It is a HEURISTIC -- agreement with it is agreement with
our own rules, never accuracy.

```
ACCESS_BRUTE_SSH      24,083  (59.4%)    all telnet and vnc, see 24d
RECON_IP_SCAN         11,394  (28.1%)    bare connects, no credentials
ACCESS_DEFAULT_CRED    4,800  (11.8%)
ACCESS_CRED_STUFF        234   (0.6%)
ACCESS_BRUTE_HTTP         54   (0.1%)
```

### 24c. The real gain: two classes go from ZERO real evidence

Measured against `final_v2` (train + val + test_real, by `gen_*`):

```
class                 real rows BEFORE   Heralding adds
ACCESS_DEFAULT_CRED            0              4,800
ACCESS_CRED_STUFF              0                234
ACCESS_BRUTE_HTTP          1,507 (cic)           54
ACCESS_AUTH_BYPASS             0                  0
```

**`ACCESS_DEFAULT_CRED` and `ACCESS_CRED_STUFF` had no real evidence of any
kind** -- 14,661 and 14,675 rows each, all `simulated_cowrie_events`. They now
have 4,800 and 234 real sessions, both above the n>=97 measurability bar of
section 23.

**And they are exactly where the model fails.** MT3 loses 1,657 of 3,872
`ACCESS_BRUTE_SSH` sessions (recall 0.5721), and 1,328 of those misses go to
these two classes plus `ACCESS_AUTH_BYPASS`:

```
ACCESS_CRED_STUFF      887
ACCESS_DEFAULT_CRED    441
ACCESS_AUTH_BYPASS     242
```

The model was being asked to separate credential-access variants it had never
seen a real example of. This capture is the first real evidence for two of the
three.

**Class anchoring therefore moves from 18 of 46 to 20 of 46**, and
synthetic-only from 28 to 26. That is a scope claim that costs no pipeline work
and should go in the paper.

### 24d. Two things it does NOT fix, one of them a prediction of mine

**`ACCESS_BRUTE_HTTP` is not rescued, and it never needed rescuing.** I expected
http+https (5,103 sessions) to anchor it with thousands of rows. It yields
**54**: 5,072 of those 5,103 are bare connects with no credentials submitted, so
they label `RECON_IP_SCAN`. Scanners knock and leave. Separately, the class was
never starved in the dataset -- it holds 1,507 real CIC rows. The 96 I quoted
earlier was its support in `test_real` alone, which is a property of the split,
not of the corpus.

**`ACCESS_AUTH_BYPASS` gains nothing.** It is not in the labeller's output at
all, so the third confusion target stays synthetic-only.

### 24e. Why it is not merged: 43 of 128 features

200 credential-bearing sessions through `build_record` -> `extract_all`:

```
group             cols   constant   usable
A_temporal          24          5       19
B_network           28         23        5
C_payload           24          6       18
D_semantic          30         30        0
E_threat_intel      14         14        0
F_tls_host           8          7        1
TOTAL              128         85       43
```

No shell, no commands, no byte counts, a fixed 30 s duration. **So a Heralding
row is identifiable from its constant signature alone**, and any class anchored
only by Heralding becomes learnable from "is this a Heralding row" rather than
from behaviour.

That is section 19a's trap exactly: all 193,000 BENIGN rows are netflow,
netflow separates from Cowrie at AUC 1.0000 on source alone, and BENIGN scores
F1 0.9149 without the model understanding anything about benign traffic.
Merging 4,800 Heralding-only `ACCESS_DEFAULT_CRED` rows would reproduce it on a
class the paper would then claim as real-anchored.

### 24f. Two decisions this forces, neither taken here

**1. 24,083 telnet and VNC sessions would be labelled `ACCESS_BRUTE_SSH.`** The
parser comments this as "nearest available". MITRE T1110.001 (Password
Guessing) genuinely covers both protocols, but the class NAME says SSH and the
traffic is telnet. Three options: rename the class protocol-neutral, add
`ACCESS_BRUTE_TELNET` (a 47th label, with everything that follows), or conflate
and state it in the paper. Doing nothing silently inflates the biggest
real-anchored class by 24k rows of a different protocol.

**2. How Heralding joins the feature matrix, if it does.** Keep it as a separate
credential-access evaluation set; restrict it to the two classes it uniquely
anchors; or merge it with the mask and report by provenance -- which is what
Part 0 built, but which does not stop the source being learnable (24e).

`MT3_TRUSTED_SOURCES` remains `{"cowrie_real"}`. Nothing here changes that:
HONEYPOT_AUDIT PART 7 measured MT3 agreeing with the rule labeller on 0 of 6
Heralding scenarios and being confidently wrong -- a bare connect returning
`DISC_NETSTAT_SCAN` at confidence 1.000.

### 24g. The capture is still running

Last session 2026-11-26 10:39 UTC. `Heralding_deployment_update.md` planned a
stop on or after 2026-11-29. `ACCESS_DEFAULT_CRED` is the one thing accruing
that the dataset genuinely lacks, so there is a reason to let it run past that
date -- decide before it is stopped, because restarting loses continuity.

---

## 25. No more sources to anchor classes — the shape test (2026-11-26)

**Decision.** We do NOT add further public datasets to give the 26
synthetic-only classes a real anchor. The question was reasonable -- CIC-IDS2017
and UNSW-NB15 are already in the build, so why not CSE-CIC-IDS2018, CTU-13,
ToN-IoT, NSL-KDD? The answer is that the binding constraint is not availability.
It is **feature shape**, and adding sources makes the dataset look better while
being less defensible.

### 25a. Every source arrives with a measurement fingerprint

Of the 24 temporal features, how many each source actually MEASURED (from
`M_train.npy`, which ships for exactly this purpose):

```
source                      rows      measured   provenance
cowrie_real               95,710        24/24     event_stream 100%
simulated_cowrie_events  592,615        24/24     event_stream 100%
cic_transfer             557,232        14/24     flow_stats 100%
unsw_transfer            221,292        10/24     flow_mean_only 100%
heralding (not merged)      ~40k      43 of 128   no shell, commands or bytes
```

A source is identifiable from that pattern alone, so **a class anchored by
exactly one source is learnable from its source rather than from behaviour.**

### 25b. This is measured three times over, not a worry

```
12b control   cic_transfer vs unsw_transfer   AUC 1.0000   BOTH REAL netflow
19a           BENIGN is 100% netflow          F1  0.9149   understands nothing
24e           heralding fills 43 of 128       identifiable by its constants
```

The first is decisive on its own. **Two real netflow datasets separate from each
other perfectly**, because one fills 14 temporal features and the other 10. A
third flow dataset would be just as separable from both, and `gen_<split>.npy`
ships with the dataset, so any reviewer can run that classifier in an afternoon
-- we would be handing them the tool.

A gap that is admitted is more defensible than an anchor that is not real.

### 25c. The test for any dataset anyone proposes

> Can it produce a COMMAND SEQUENCE WITH TIMESTAMPS -- the same shape
> `cowrie_parser` produces?

If no, it can only anchor a class by its own fingerprint.

```
flow / packet datasets          FAIL   same shape as what we have; 12b applies
more SSH honeypot captures      pass shape, FAIL class: section 15 showed three
                                       captures over 8, 13 and 23 days produce
                                       the same 8 micro-states
host / process telemetry        partial: covers privesc, persistence and lateral
(DARPA OpTC, Sysmon corpora)    movement, but process-event-shaped -- a new
                                       extractor and contract, still fingerprinted
```

### 25d. Why the 26 classes are empty, which is the real point

Not missing datasets. **A low-interaction honeypot never lets an attacker reach
those phases.** Cowrie emulates a shell; nobody runs a real privilege
escalation in it. So no quantity of Cowrie-shaped public data contains
`PRIVESC_*`, `PERSIST_*`, `EVASION_*`, `LATERAL_*` or `EXFIL_*` behaviour,
because that behaviour was never produced.

This is section 3d's conclusion restated with a mechanism: the taxonomy is wider
than anything observable from the sensor we have.

### 25e. What IS permitted, in order of value for effort

**1. Execute the techniques ourselves through our own extractor.** Atomic Red
Team provides MITRE-mapped command sequences for most of the missing techniques.
Run them in a lab, capture through `cowrie_parser` -> `extract_all`, and the
rows have the RIGHT SHAPE (24/24 temporal measured, real command text for group
D), correct labels by construction, and a provenance tier of their own. Describe
them as **"real execution traces of scripted attack techniques"** -- never as
captured attacker behaviour. Cheapest defensible route to coverage, and a better
anchor than another netflow source precisely because it fills the same features
Cowrie fills.

**2. A higher-interaction honeypot.** Cowrie in proxy mode to a sandboxed
backend, so attackers get a real shell and the post-access phases appear in
genuine attacker data. The only route to REAL attacker evidence for those
classes. Weeks of work and a real safety problem -- a live shell on the
internet. See MULTI_HONEYPOT.md.

**3. Nothing.** State the gap. 20 of 46 classes with real evidence, 10
measurable (section 23), and the reason in one sentence.

### 25f. What to write

> The taxonomy covers 46 MITRE-mapped labels. 20 have some real evidence and 10
> have enough real sessions to measure; the remainder rest on calibrated
> synthetic sessions. We deliberately did not anchor the remaining classes with
> additional public datasets: each source in this build is separable from the
> others by its measurement fingerprint -- two real netflow datasets already
> separate at AUC 1.0000 -- so a class anchored by a single source is
> identifiable from that source rather than from attacker behaviour. The gap is
> a property of a low-interaction sensor, not of data availability.

Do not write "we combine N public datasets for broad coverage". With `gen_*`
shipped, that claim is checkable and it does not hold.

---

## 26. Error bars: three seeds, and MT3 is the seed-sensitive one (2026-11-26)

Every model number before today came from a single run. Three seeds (42, 43,
44) per model, identical protocol, ~3.5 hours unattended.

**These are TRAINING-variance bars** -- model initialisation and batch
shuffling. The split is fixed in `final_v2`, so all three seeds see identical
rows. Data-resampling bars would need the whole pipeline re-run per seed and are
NOT what is reported here.

### 26a. test_real, 3 seeds

```
model          params      macro-F1            accuracy
linear probe    5,934   0.3852 +/- 0.0015   0.7459 +/- 0.0003
CNN-LSTM      189,710   0.4363 +/- 0.0141   0.8179 +/- 0.0083
MT3         3,759,767   0.5628 +/- 0.0442   0.8872 +/- 0.0147

per seed (42 / 43 / 44)
linear probe   0.3835  0.3863  0.3858
CNN-LSTM       0.4413  0.4472  0.4204
MT3            0.5507  0.5259  0.6119
```

### 26b. Both gaps clear the noise

```
MT3 - CNN-LSTM   = +0.1266   pooled sd 0.0328   ~3.9x
CNN-LSTM - probe = +0.0511   pooled sd 0.0100   ~5.1x
```

So the three-tier ordering of 21d is a real effect, not a seed artefact. On
`data/final/` all three models sat inside 0.064 of each other and MT3 vs
CNN-LSTM was a tie at p=0.617, so that comparison could not have survived this
test.

### 26c. MT3's headline numbers, with bars

```
phase accuracy        0.9422 +/- 0.0011     <- 40x tighter than macro-F1
weighted F1           0.9047 +/- 0.0124
macro-F1 @n>=97       0.7332 +/- 0.0206
macro-F1 (16 classes) 0.5628 +/- 0.0442
macro-F1 over 46      0.1958 +/- 0.0154
accuracy              0.8872 +/- 0.0147
```

**Report the mean, not seed 42.** `0.5507` is the MIDDLE seed, not the best
(0.6119) nor the worst (0.5259), so quoting it was neither cherry-picking nor
representative -- but a single run cannot be either.

### 26d. The seed sensitivity is itself a finding

```
linear probe   +/- 0.0015       5,934 parameters
CNN-LSTM       +/- 0.0141     189,710
MT3            +/- 0.0442   3,759,767
```

MT3 varies **29x more than the probe** across seeds, spanning 0.5259 to 0.6119.
That is section 23's problem showing up as variance: macro-F1 over 16 classes is
unweighted, 9 of those classes hold 652 of 59,784 rows, so a few hundred rows
changing hands between seeds moves the average a long way. The same model's
ACCURACY varies only +/- 0.0147 and its PHASE accuracy +/- 0.0011.

**Phase accuracy at 0.9422 +/- 0.0011 is the most reproducible number in the
project**, and it is also the one the honeypot acts on. Another reason to lead
with it (23's headline order).

### 26e. What this does not settle

Three seeds is the minimum for a standard deviation to mean anything. With MT3
at +/- 0.0442 a reviewer could reasonably ask for 5-10, which at ~55 minutes a
run is an overnight job. `n>=97` for seed 42 (0.7387) was computed post hoc from
its saved predictions because the metric did not exist when it ran; seeds 43 and
44 emit it directly. The three agree, but they come from two code paths.
