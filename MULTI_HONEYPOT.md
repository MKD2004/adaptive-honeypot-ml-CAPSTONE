# MULTI_HONEYPOT — adding auth-portal, web-app and database honeypots

Last updated: 2026-11-03 (created; then execution-order review — added the
scheduling tracks in §6, Phase 1b, the labelling plan in §7.6, and the measured
Group D numbers in §7.2)

Shared reference — **committed**, identical on every machine (ASUS / Dell / DGX).
Change it once and push; do not fork it locally.

This file is the expansion of `ROADMAP.md` **M4 ("Broaden")**. It says how the
single-protocol system grows to four honeypots, in what order, and what breaks
on the way. Read `ROADMAP.md` §4 (deployment topology) and `HONEYPOT_AUDIT.md`
(what is actually running) alongside it.

**Decision taken 2026-11-03:** use **real third-party honeypots in Docker**, not
hand-written emulators, and target the **internet VPS** rather than the laptop
demo. Rationale in §4.

---

## 1. Where we actually are (no spin)

**There is one honeypot.** Cowrie 3.0.13 in Docker (`cowrie-honeypot`,
`127.0.0.1:8081 -> 2222`). Not four.

The "four honeypots" is a **commented-out list** at `traffic_gateway/config.py:45-49`:

```python
#HONEYPOT_TARGETS: List[Target] = field(default_factory=lambda: [
#    Target("127.0.0.1", 2222, "ssh"),    # Cowrie SSH honeypot
#    Target("127.0.0.1", 8081, "web"),    # fake web-app emulator
#    Target("127.0.0.1", 8082, "auth"),   # fake auth-portal emulator
#    Target("127.0.0.1", 8083, "db"),     # fake database emulator
#])
```

The live list immediately below has exactly one entry. `adaptive_honeypot/emulators/`
is an **empty folder** — nothing implements a web, auth or database emulator.
`HONEYPOT_AUDIT.md` (2026-11-02) establishes this independently, along with the fact
that every captured session on every machine so far is simulated.

Uncommenting that list does **not** give you four honeypots. It gives you a gateway
round-robining connections at three closed ports.

---

## 2. What is already built (more than expected)

A surprising amount of multi-protocol plumbing exists and is simply unreachable.
None of this needs to be written from scratch:

| Already there | Where |
|---|---|
| `WEB_HONEYPOT` / `DB_HONEYPOT` resolution by protocol and port | `traffic_gateway/feature_bridge.py:42-57`, used at `:259-265` |
| `is_ssh_port`, `is_http_port`, `is_db_port`, `protocol_enc` as **real trained features** | `src/extractors/network.py` — group-local 18-21, global **42-45** |
| Per-target fake banners for web and db | `adaptive_honeypot/configurator.py:137-141` |
| Web-aware trending-CVE matching (refuses to dress SSH as a REST API) | `adaptive_honeypot/configurator.py:183-193` |
| 28 attack-type honeypot templates — service, ports, endpoints, detection regexes | `cve_intelligence/config.py:205` (`HONEYPOT_TEMPLATES`) |
| 28 matching emulator config strings (`db_emulator`, `reflect_xss`, `ssrf_emulator`, …) | `cve_intelligence/config.py:461` (`CONFIG_STRING_TEMPLATES`) |
| Hardened internet-facing deployment kit (egress block, systemd, verify script) | `deploy/sandbox/` on `origin/feature/mitigation-layer` — **unmerged** |
| Pipeline field recording which honeypot saw a session | commit `4a6ed19` on `origin/feature/mitigation-layer` — **unmerged** |

Web- and auth-relevant micro-states already exist in the frozen 45-class taxonomy:

| id | label | which honeypot produces it |
|---|---|---|
| 2 | `RECON_VERSION_PROBE` | web, auth |
| 4 | `RECON_VULN_SCAN` | web |
| 5 | `RECON_USER_ENUM` | auth |
| 7 | `ACCESS_BRUTE_HTTP` | auth, web |
| 8 | `ACCESS_CRED_STUFF` | auth |
| 9 | `ACCESS_DEFAULT_CRED` | auth, db |
| 11 | `ACCESS_AUTH_BYPASS` | auth, web |
| 22 | `DISC_CVE_SEARCH` | web |

**98 of 128 features transfer cleanly.** Group B already encodes HTTP and DB ports.
Group C (payload) is protocol-agnostic entropy/n-gram work and already carries
`frac_url_encoded` and `base64_likelihood` — genuinely well-suited to web payloads.
Only Group D is a problem (§7.2).

---

## 3. The blockers

### 3.1 `build_record()` hardcodes SSH

`honeypot_dataset/src/parsers/cowrie_parser.py:134-135`:

```python
"dst_port":             22,
"protocol":             "ssh",
```

Every session the pipeline has ever seen claims to be SSH on port 22. So
`honeypot_target_for()` returns `SSH_HONEYPOT` **unconditionally** — the entire
`_PORT_TO_HONEYPOT` table in `feature_bridge.py` is dead code today. Fix this
first; nothing else is testable until it is fixed.

### 3.2 The pipeline is single-source

`post_session_pipeline` globs one directory for `cowrie.json*`
(`COWRIE_LOG_GLOB`) and only understands `cowrie.*` eventids. Three new honeypots
mean three new log formats.

### 3.3 No session-dict contract is written down

The contract is implicit in whatever `build_record()` happens to return (30 keys).
Three new parsers must match it exactly, including keys the extractors silently
default when missing. Write it down before writing a second parser.

**A written contract is not enough.** Prose drifts, and the thing that actually
prevents a second round of pipeline surgery is an **executable conformance test**
every parser must pass: required keys present, types right, `protocol` and
`dst_port` actually set (not defaulted), no NaN or None reaching the extractors.
Without it, parser #2 breaks the contract anyway and you have written a document
about the problem instead of a guard against it.

### 3.4 No adaptive surface outside Cowrie

`apply_honeyfs()` (`configurator.py:442`) only writes `etc/motd`, a fake
`/etc/shadow` and a fake SSH host key into Cowrie's honeyfs. There is no
equivalent for a web, auth or database honeypot. Without siblings, the new
honeypots are *monitored* but not *adaptive* — which is the project's entire
contribution.

### 3.5 The gateway is protocol-blind — but this is now moot

`traffic_router.py:52,170` picks honeypots with `itertools.cycle`, so an SSH
client could be round-robined into a web honeypot. **Not being fixed:** per
`ROADMAP.md` §4.1 the gateway is dropped for data collection, and each honeypot
binds its own public port. The gateway stays single-honeypot for the LAN demo.
If a future topology ever puts the gateway in front of four honeypots, this
becomes a listener-per-port job.

---

## 4. Approach: real honeypots, not emulators

**Chosen: real third-party honeypots in Docker.**

`ROADMAP.md` M4 already asks for "a real honeypot, not the demo prop", and §7
forbids calling props honeypots. The project's novelty is the **adaptive loop**,
not the emulator. Writing a Flask app with fake SQLi sinks adds no novelty and
hands a reviewer the "is that actually a honeypot?" objection for free — the same
objection `HONEYPOT_AUDIT.md` already had to answer about `demo/ssh_honeypot.py`.

Cost of this choice, accepted knowingly: none of these speak Cowrie JSON, so each
needs a parser (§3.3), and none is adaptively reconfigurable out of the box, so
each needs a config-rewrite applier (§3.4).

### Selection

| Role | Honeypot | Why this one |
|---|---|---|
| **Auth portal** | **Heralding** | One container, YAML config, logs every credential pair across HTTP/HTTPS/FTP/SSH/Telnet/POP3/IMAP/SMTP/MySQL/Postgres/VNC/SOCKS5. Maps onto four micro-states we already have. Adaptive surface = rewrite YAML, restart. |
| **Web app** | **SNARE + TANNER** | TANNER has genuine SQLi / XSS / LFI / RFI / command-exec emulators; SNARE clones a real site. Four containers (snare, tanner, tanner-redis, tanner-phpox). |
| **Database** | **Dionaea** | MySQL + MSSQL + SMB + FTP in one container. |

All three are packaged by **T-Pot** (Telekom Security), which `ROADMAP.md` M4
already names as a candidate substrate. If maintaining four separate compose
stacks becomes the bottleneck, switching to T-Pot is the fallback — but T-Pot
owns its own log layout and would mean rewriting the parsers again, so do not
start there.

### Why VPS, not the laptop demo

- `ROADMAP.md` §4.1: on a public honeypot box ~100% of traffic is hostile and
  there is no real service to protect, so the gateway has nothing to do. Dropping
  it removes `peer_attribution`, rate limiting and routing from the picture.
- `src_ip` is genuine, not a Docker bridge address.
- It is the only path that produces **real attacker data**, which is M1 and gates
  the paper.

---

## 5. Target architecture

```
internet
   |   :22 ssh        :80/:443 web      :8080 auth     :3306/:445 db
   v
[cloud firewall]  ->  [host firewall: honeypot_guard]  ->  [Docker: honeypot_net / br-honeypot]
  (manual, provider)       drops IPs on the block list        |        |          |         |
                                     ^                     Cowrie  SNARE+    Heralding  Dionaea
                                     |                             TANNER
                                     |                              |        |          |         |
                                     |                              +--------+----------+---------+
                                     |                                            |
                                     |                            per-honeypot logs (4 formats)
                                     |                                            |
                                     |                    [pipeline: parse -> 128 feats -> MT3 -> config]
                                     |                                            |
                                     +---- blocklist.json <--- [mitigation] <------+
                                                                                   |
                                                              adaptive config written back per honeypot
```

**The single most useful thing in `deploy/sandbox/`:** `egress.nft` matches on the
**bridge interface name**, not on a container —

```
iifname "br-honeypot" ct state new counter drop
```

So **any honeypot joined to `honeypot_net` inherits outbound containment for
free.** No per-honeypot firewall work. (With one caveat — see §7.3.)

---

## 6. Phases

### How to schedule these — three independent tracks

The phases below are a **dependency** order, not a schedule. Read strictly in
sequence they waste weeks, because Phase 0 is **wall-clock bound**: real attacker
data accrues over 2-4 weeks and no amount of effort speeds it up. Phase 1 is
laptop work with no dependency on it.

Three tracks run **concurrently**:

| Track | What | Blocked by |
|---|---|---|
| **A — collect** | Phase 0 on the VPS. Start it, let it run, check on it. | nothing |
| **B — build** | Phases 1 -> 1b -> 2 on the laptop. | nothing |
| **C — the paper's headline** | `ROADMAP.md` M3 A/B study, Cowrie-only | Track A being live |

Track C is worth stating explicitly: **Cowrie is already adaptive today** (the
configurator + `apply_honeyfs` loop works), so the A/B study needs nothing from
this document. It can run on the Phase 0 box in parallel. Do not let
multi-honeypot work delay the one experiment the paper depends on (§7.4).

### Phase 0 — prove the single-honeypot VPS deploy first
`deploy/sandbox/README.md` says plainly: *"Not yet run on a real server"* — not
with the real Cowrie image, not with the trained MT3, not in the cloud. **Do not
add three honeypots to an unproven deployment.** This phase is also `ROADMAP.md` M1.

- [ ] Merge or cherry-pick `origin/feature/mitigation-layer` to `main` (it is
      unmerged; `HONEYPOT_AUDIT.md` notes nothing from it was committed)
- [ ] Run sandbox Part A — Cowrie on 2222, own IP only in the cloud firewall
- [ ] Run sandbox Part B — port 22 open to the world, own admin SSH moved first
- [ ] `check_cowrie_ips.py` confirms real attacker IPs, not `172.x`
      (`ROADMAP.md` §4.4 — if bridge addresses appear, switch to `network_mode: host`)
- [ ] **Then leave it running.** Do not wait on it — Track B proceeds in parallel.
      Several weeks of accrual is the point, and it is also M1 and M3's input.

### Phase 1 — session contract + multi-source pipeline
Laptop work, **concurrent with Phase 0** (Track B). Nothing honeypot-specific; this
is the socket everything else plugs into.

- [ ] Fix `cowrie_parser.py:134-135` to carry the real `dst_port` / `protocol` (§3.1)
- [ ] Write the flat session-dict contract down explicitly — all 30 keys, their
      types, and which the extractors silently default (§3.3)
- [ ] **Executable conformance test** every parser must pass (§3.3) — this, not the
      written contract, is what stops the next integration needing pipeline surgery
- [ ] Parser registry: `post_session_pipeline` takes N `(log_dir, parser, source_name)`
      sources instead of one hardcoded `cowrie.json*` glob
- [ ] Add `honeypot_source` to `pipeline_results.jsonl` — cherry-pick `4a6ed19`
- [ ] Test: synthetic HTTP session in, assert `honeypot_target == WEB_HONEYPOT`
      (this is the first test that can ever pass, given §3.1)

### Phase 1b — baseline the feature pipeline BEFORE Heralding

Validating multi-protocol support is usually put *after* the second honeypot. Half
of it can be done **now**, with zero new infrastructure, and the answer changes what
Phase 2 should build — so it belongs here.

**What is already measurable.** `ACCESS_BRUTE_HTTP` (id 7) is **already present in
`test_real`** — 121 rows. A measured per-class number for an HTTP class exists in the
frozen eval today.

- [ ] Pull per-class precision / recall / F1 for ids **7** (`ACCESS_BRUTE_HTTP`, 121
      rows) and **4** (`RECON_VULN_SCAN`, 213 rows) out of the existing MT3 eval.
      Quote the **clean** subset, as everywhere else (`CLAUDE.md`).
- [ ] Report them with confidence intervals. **121 of 60,000 rows is a weak anchor,
      not proof** — a per-class F1 on 121 rows has a wide interval and must not be
      quoted as "MT3 handles HTTP".
- [ ] Characterise Group D's domain gap offline: push synthetic HTTP request lines,
      SQL, and credential strings through `semantic_pca.pkl` and compare their
      projection distribution against the shell-command training distribution
      (distance to training-embedding mean, or distance-to-nearest-neighbour).

**Measured already — Group D on the existing real HTTP rows is not what Heralding
will produce:**

| class | n | Group D distinct rows | mean per-dim std |
|---|---|---|---|
| `ACCESS_BRUTE_HTTP` (7) | 121 | 119 | **0.150** |
| `RECON_VULN_SCAN` (4) | 213 | 157 | 0.335 |
| `ACCESS_BRUTE_SSH` (6) | 1807 | 812 | 0.414 |
| `DISC_ENV_PROBE` (18) | 22608 | 17774 | 0.289 |

Group D is populated for the HTTP class, but at roughly **a third the variance** of
the SSH classes. Whatever text produced those features is not representative of live
HTTP request text. The variance alone does not say what that text was — but the gap
is real.

**The decision this forces** (a Phase 2 *design* decision, not a post-hoc check):

- [ ] Choose: does the Heralding parser feed real HTTP / credential text through the
      shell-fitted PCA, or **deliberately zero-fill Group D for non-SSH sessions**?
      Zero-filling is plausibly the more honest option, and the pipeline already has
      the `semantic_available=False` path for it (§7.2). Decide before writing the
      parser — it changes what the parser emits.

### Phase 2 — Heralding (auth portal)
Start here, not with web. Lowest risk, cleanest taxonomy fit, fastest proof the
pipeline is genuinely multi-protocol.

- [ ] Add to `deploy/sandbox/docker-compose.yml` on `honeypot_net`, same
      `cap_drop` / `no-new-privileges` / `pids_limit` / `mem_limit` posture as Cowrie
- [ ] **Enable HTTP / HTTPS / FTP / Telnet auth only. Leave Heralding's MySQL and
      Postgres listeners OFF.** Heralding ships them, and switching them on walks
      straight into the missing-SQLi-class problem (§7.1) in *this* phase — which is
      exactly what deferring Dionaea was meant to avoid. Turn them on only after the
      §7.1 decision is made.
- [ ] `heralding_parser.py` -> the Phase 1 contract, `protocol`/`dst_port` set
      correctly, Group D handled per the Phase 1b decision
- [ ] **A rule-based `micro_state` labeller in the parser**, as `build_record` has.
      Without it there is nothing to compare MT3 against on unlabelled real
      traffic — see §7.6, and decide the labelling plan *before* collecting.
- [ ] Confirm MT3 lands sessions on ids 5, 7, 8, 9, 11 rather than collapsing to SSH classes
- [ ] `verify_sandbox.sh` extended to cover the new port and container

### Phase 3 — Dionaea (database)
- [ ] **Resolve the taxonomy gap first (§7.1) — this is a decision, not a task**
- [ ] Add to compose on `honeypot_net`
- [ ] `dionaea_parser.py` (SQLite/JSON logs) -> the contract

### Phase 4 — SNARE + TANNER (web app)
Last, deliberately. Heaviest and by far the riskiest.

- [ ] Containment review **before** exposure: `phpox` **executes attacker-supplied
      PHP**. On an internet-facing box with real adversaries this needs its own
      review, not just the shared bridge rule
- [ ] Verify intra-network traffic survives `egress.nft` (§7.3) — snare -> tanner
      -> redis -> phpox all cross the bridge
- [ ] Choose and clone the site SNARE serves
- [ ] `tanner_parser.py` -> the contract

### Phase 5 — adaptive surfaces
The loop is only "adaptive" if MT3's verdict changes each honeypot. Siblings to
`apply_honeyfs()`:

- [ ] `apply_auth_surface` — Heralding YAML: enabled protocols, banner, auth-success rate
- [ ] `apply_web_surface` — TANNER: which vuln emulators on, which cloned page set
- [ ] `apply_db_surface` — fake table rows, server version banner
- [ ] Each is write-files-then-restart-container; log what changed, as `apply_honeyfs` does
- [ ] Wire `HONEYPOT_TEMPLATES` / `CONFIG_STRING_TEMPLATES` (`cve_intelligence/config.py`)
      in as the content source — 28 templates exist with nothing consuming them

### Phase 6 — dashboard / frontend
- [ ] Honeypot inventory panel (what is up, on which port, which version)
- [ ] `honeypot_source` filter on sessions and MT3 results
- [ ] Per-honeypot breakdowns in `/api/stats`

**Phases 1 -> 1b -> 2 carry most of the value.** After them the dead
`_PORT_TO_HONEYPOT` table comes alive, a second real protocol runs end to end, and
the multi-protocol claim rests on something measured rather than assumed. Phases
3-4 are scope; Phase 5 is the contribution.

---

## 7. Six things that will bite

### 7.1 There is no SQL-injection micro-state

A database honeypot's single most characteristic attack has nowhere to land in the
45-class taxonomy. Nearest existing labels are `ACCESS_DEFAULT_CRED` (9) and
`ACCESS_AUTH_BYPASS` (11), neither of which means SQLi.

The dataset is **frozen** (`HoneySynth-960k`) and every trained model depends on
those exact rows, so adding a class means retraining everything — M2-scale work.
Two honest options:

1. **Map to the nearest class and disclose it** in the paper's threats-to-validity.
   Cheap, and defensible if stated plainly.
2. **Extend the taxonomy and retrain.** Correct, expensive, and couples this work
   to M2.

Decide **before** Phase 3, not during it.

**This arrives earlier than Phase 3 if you are not careful.** Heralding has MySQL and
Postgres listeners. Enabling them in Phase 2 hits this gap immediately — the thing
that dropping Dionaea was supposed to defer. Keep them off (see Phase 2).

### 7.2 Group D goes out-of-distribution

`semantic_pca.pkl` (30 of 128 features, global 76-105) was fitted on **shell
command text**. HTTP request lines, SQL queries and credential strings pushed
through that DistilBERT -> PCA projection are out-of-distribution: the numbers
come back, they just mean less. This does **not** raise an error — it quietly
mispredicts.

The pipeline already surfaces `semantic_available` for the "DistilBERT missing"
case. A second, distinct signal is needed for "available but off-domain", so the
dashboard and the paper can tell the two apart. Do not let an OOD projection be
reported as a clean one.

**Partly measured already** (Phase 1b, full table there). On the real HTTP rows that
exist in `test_real`, Group D is populated but runs at roughly a third the variance
of the SSH classes — `ACCESS_BRUTE_HTTP` 0.150 mean per-dim std against
`ACCESS_BRUTE_SSH` 0.414. So the Group D distribution MT3 was trained on for the
HTTP class is **already** unlike what live HTTP request text will produce. Feeding
Heralding's text through the shell-fitted PCA is therefore not "reusing a trained
capability" — it is a third distribution the model has never seen.

Hence the Phase 1b decision: **deliberately zero-filling Group D for non-SSH
sessions may be more honest than feeding it off-domain text.** Zero-filling is a
known, declared degradation with an existing code path; off-domain text is a silent
one. Make the choice explicitly and record it in `DECISIONS.md`.

### 7.3 `egress.nft` will probably break TANNER

`forward_guard` drops `ct state new` on `iifname "br-honeypot"`. With
`br_netfilter` loaded (Docker loads it), that likely catches **container-to-container**
traffic on the same bridge too — so snare -> tanner -> redis -> phpox dies.

Needs an `iifname "br-honeypot" oifname "br-honeypot" accept` rule **ahead of**
the drop. Verify on the VM before Phase 4 and extend
`deploy/sandbox/tests/test_sandbox_egress_linux.py`. Note the trade-off: that rule
also lets a compromised honeypot reach its neighbours, so scope it as narrowly as
the TANNER stack actually needs.

### 7.4 Do not let this confound the A/B study

`ROADMAP.md` M3 — the paper's **headline figure** — is a Cowrie-only
control-vs-adaptive comparison needing >=4 weeks. Adding honeypots mid-run changes
the attacker population and wrecks it.

**Run M1 -> M3 on Cowrie alone. Bring the new honeypots up on a second VPS.**
Multi-honeypot is M4 "broaden" — a separate "generalises beyond SSH" section, not
part of the headline experiment.

### 7.5 Four honeypots is four times the attack surface

One Cowrie container was one audited thing. Four stacks (seven containers with
TANNER) on an internet-facing box, one of which executes attacker PHP, is a
materially different risk posture. Every sandbox rule in
`deploy/sandbox/README.md` §"The rules this setup keeps" applies per honeypot, and
`verify_sandbox.sh` must grow to check all of them. Re-read the provider's
acceptable-use policy before exposing non-SSH ports.

### 7.6 Real captures have no ground truth — "validate" is not yet an operation

The most easily-skipped item on this list. Real Heralding sessions are
**unlabelled**: nobody tells you which micro-state an actual attacker was in. There
is no F1 to compute. So "validate the feature pipeline before claiming MT3 supports
multiple protocols" has no defined meaning until a labelling plan exists, and
without one it quietly degrades into *"the predictions looked plausible"*.

Pick one, in Phase 2, before collecting:

1. **Rule-label agreement.** Write a rule-based labeller into the Heralding parser,
   as `build_record` already has for Cowrie, and report MT3-vs-rule agreement.
   `pipeline_results.jsonl` already logs `rule_label` beside `mt3_prediction` for
   exactly this. Cheap and immediate — but it measures agreement with *your own
   heuristic*, not correctness, and must be reported in those words.
2. **Manual review of a stratified sample.** Expensive, and the only option that
   supports an actual accuracy claim. Budget the hours; decide the sample size up
   front.

The two are complementary: (1) for continuous monitoring across all sessions, (2)
on a sample, to calibrate how much (1) is worth.

---

## 8. What NOT to claim

- Do **not** say the system has four honeypots until four are running and logging.
  Today it is one. `traffic_gateway/config.py:45-49` is a comment.
- Do **not** call anything in `adaptive_honeypot/emulators/` a honeypot. The folder
  is empty; if it is ever filled with hand-written emulators, they are props
  (`ROADMAP.md` §7).
- Do **not** claim the adaptive loop generalises across protocols until Phase 5
  exists. Monitoring four honeypots is not adapting four honeypots.
- Do **not** report a DB-honeypot session's micro-state without the §7.1 caveat.
- Do **not** mix multi-honeypot data into the M3 A/B result (§7.4).
- Do **not** report MT3-vs-rule **agreement** as accuracy (§7.6). Agreement with our
  own heuristic is not ground truth, and the distinction has to survive into the
  paper's wording.
- Do **not** cite the existing `ACCESS_BRUTE_HTTP` result as evidence MT3 handles
  HTTP. It is **121 rows** of `test_real` (Phase 1b) — a weak anchor with a wide
  confidence interval, quotable only with that stated.
