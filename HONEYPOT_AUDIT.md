# Honeypot Reality Check

**Audit + verification runs · ASUS TUF laptop**

What is actually running on this machine, whether the captured attacks are real, how this working
copy has drifted from GitHub, a review of the mitigation layer on `feature/mitigation-layer`, and
the results of running that layer against the real MT3 model here — on hostile traffic and
on benign traffic.

`2026-11-02` · `repo back on main @ ae1761b` · `nothing committed or merged` · see the Colophon for
exactly what the test runs changed

---

## Headline answers

| Question | Answer | Note |
|---|---|---|
| **How many honeypots?** | **One** | Not four. One Cowrie SSH container. The "four" is a commented-out list in the gateway config. |
| **Are the attacks real?** | **All simulated** | Every log on this laptop was generated locally. Zero real attacker traffic, in any file. |
| **Cloud deployment?** | **Not deployed** | No provider, no server, no public listener. Nothing to name. |

---
---

# PART 1 — Honeypots on this machine

## What Docker is holding

One note first: `docker ps -a` fails with the shell's default settings, because Docker Desktop's
`desktop-linux` context points at a named pipe that is not currently answering. The `default`
context works, and that is what every result below came from. The daemon was never restarted and
no container was started or stopped.

Eight containers exist. Seven belong to unrelated projects (`demo-env-*` Grafana / Loki /
Prometheus / Redis, and `backend-postgres-1`) and are all exited. **One is a honeypot.**

### Compose files

- `honeypot_dataset/cowrie/docker-compose.yml` — the one in use. Docker confirms this exact file
  path as the running container's compose source.
- `deploy/sandbox/docker-compose.yml` — the internet-facing kit. It exists **only on the
  `feature/mitigation-layer` branch**, not in this working copy, and has never been run here.

## The honeypot, in full

| Field | Value |
|---|---|
| Container | `cowrie-honeypot` — running, started 2026-11-02 07:45 UTC |
| Software | Cowrie — SSH / Telnet honeypot |
| Image | `cowrie/cowrie:latest` |
| Exact version | **v3.0.13** (image label `org.opencontainers.image.version`) |
| Image digest | `sha256:42e01e0e5fe705a0a63dacc0f1992b2d230740ac149af7675f48197abf740d44` |
| Image built | 2026-08-24 · base `gcr.io/distroless/python3-debian13` |
| Pretends to be | An SSH server on an old Debian box. Hostname `svr04`, banner `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2`. **SSH only** — Telnet is disabled in `cowrie.cfg`, and there is no web, database, or login-page honeypot. |
| Ports | container `2222/tcp` → host `127.0.0.1:8081` |
| Reachable from outside? | **No.** The publish is bound to loopback only, and `netstat` shows `127.0.0.1:8081` as the sole listener — nothing on 22, 2222, 8082 or 8083, and nothing on a public interface. |
| Logs (host) | `honeypot_dataset/cowrie/logs/cowrie.json` plus rotations `.2026-09-08` and `.2026-09-28` |
| Logs (container only) | TTY recordings and fake downloads live in Docker named volumes under `/cowrie/cowrie-git/var/lib/cowrie` — not on the host filesystem |
| Downstream logs | `traffic_gateway/logs/gateway.log` (routing), `logs/pipeline_results.jsonl` (MT3 verdicts), `traffic_gateway/data/sessions.jsonl` (gateway events) |

## So: are there four honeypots?

**No. There is one.** Here is where the number four comes from and why each of the other three
does not exist:

- `traffic_gateway/config.py` lines 45–49 hold a **commented-out** four-entry list: SSH 2222,
  web 8081, auth 8082, db 8083. The live list immediately below it has exactly one entry,
  `127.0.0.1:8081`.
- The gateway says so itself. Its own startup line in `sessions.jsonl` reads
  `"honeypot_count": 1, "honeypots": ["web://127.0.0.1:8081"]`.
- `adaptive_honeypot/emulators/` is an **empty folder**. Nothing implements a web, auth or
  database emulator.
- `configurator.py` can emit `WEB_HONEYPOT` and `DB_HONEYPOT` as target names, and
  `cve_intelligence/config.py` has a template library for SQL-injection / XSS / SSRF honeypots —
  but these are *plans and labels*. No process listens for them.

Excluded on purpose, as asked: `demo/ssh_honeypot.py` (a Paramiko prop on 127.0.0.1:8081) and
`demo/real_server.py` (a fake business server on 127.0.0.1:8000). These are demo stage props, not
honeypots.

## Sample log lines

Passwords and credential strings are replaced with `[REDACTED]`. Long cryptographic fields are
trimmed with `…` for readability; nothing else is altered.

### Log 1 — written by the real Cowrie container

`honeypot_dataset/cowrie/logs/cowrie.json*` · 8 sessions · 68 events

*Compact JSON, full Cowrie field set, sensor = container id.*

```json
{"session":"2e31e230c07d","protocol":"ssh","src_ip":"172.18.0.1","src_port":44236,"dst_ip":"172.18.0.2",
 "dst_port":2222,"eventid":"cowrie.session.connect","sensor":"4aa60f9593a3","timestamp":"2026-09-29T05:45:46.466638Z",
 "message":"New connection: 172.18.0.1:44236 (172.18.0.2:2222) [session: 2e31e230c07d]"}

{"session":"2e31e230c07d","src_ip":"172.18.0.1","version":"SSH-2.0-paramiko_5.0.0","eventid":"cowrie.client.version",
 "sensor":"4aa60f9593a3","timestamp":"2026-09-29T05:45:46.474891Z","message":"Remote SSH version: SSH-2.0-paramiko_5.0.0"}

{"session":"2e31e230c07d","src_ip":"172.18.0.1","hassh":"6372ee6957562199b2fb773b0be1bf34","kexAlgs":["curve25519-sha256@libssh.org",…],
 "eventid":"cowrie.client.kex","sensor":"4aa60f9593a3","timestamp":"2026-09-29T05:45:46.479518Z"}

{"session":"7b208cc4c57e","src_ip":"172.18.0.1","src_port":48086,"username":"root","password":"[REDACTED]",
 "eventid":"cowrie.login.success","sensor":"4aa60f9593a3","timestamp":"2026-09-29T05:46:27.980056Z",
 "message":"login attempt [root/[REDACTED]] succeeded"}

{"session":"7b208cc4c57e","src_ip":"172.18.0.1","input":"cat /etc/shadow","eventid":"cowrie.command.input",
 "sensor":"4aa60f9593a3","timestamp":"2026-09-29T05:46:30.535212Z","message":"CMD: cat /etc/shadow"}
```

### Log 2 — injected into the same file by the demo prop

Same files, but **not written by Cowrie** · 46 sessions · 140 events

*Spaced JSON, thin field set, sensor = "svr04", dst_port 8081, no uuid / hassh.*

```json
{"eventid": "cowrie.session.connect", "session": "86e78c3d667b", "src_ip": "127.0.0.1",
 "timestamp": "2026-09-28T06:41:20.535500Z", "sensor": "svr04", "src_port": 61131, "dst_port": 8081, "protocol": "ssh"}

{"eventid": "cowrie.session.closed", "session": "86e78c3d667b", "src_ip": "127.0.0.1",
 "timestamp": "2026-09-28T06:41:20.541Z", "sensor": "svr04"}

{"eventid": "cowrie.session.connect", "session": "1830aa34920d", "src_ip": "127.0.0.1",
 "timestamp": "2026-09-30T11:05:55.871913Z", "sensor": "svr04", "src_port": 59214, "dst_port": 8081, "protocol": "ssh"}

{"eventid": "cowrie.session.closed", "session": "1830aa34920d", "src_ip": "127.0.0.1",
 "timestamp": "2026-09-30T11:05:55.873794Z", "sensor": "svr04"}
```

These come from `demo/ssh_honeypot.py`, which sets `HOSTNAME = "svr04"` and writes to
`Path(log_dir) / "cowrie.json"` — the very same file the container writes. **46 of the 54 sessions
in that log are prop-injected, not honeypot captures.**

### Log 3 — the 15,000-session dataset corpus

`honeypot_dataset/data/raw/cowrie_logs/cowrie.json` · 80 MB · 336,764 events · 15,000 sessions

*No sensor field anywhere; dst_ip is one of ten fake 10.0.0.x boxes.*

```json
{"eventid": "cowrie.session.connect", "session": "e276ab7878c9", "src_ip": "63.58.36.189", "src_port": 7741,
 "dst_ip": "10.0.0.9", "dst_port": 2222, "timestamp": "2024-03-21T02:05:11.515139Z", "protocol": "ssh"}

{"eventid": "cowrie.client.version", "session": "e276ab7878c9", "src_ip": "63.58.36.189",
 "timestamp": "2024-03-21T02:05:11.643743Z", "version": "SSH-2.0-Go"}

{"eventid": "cowrie.login.failed", "session": "e276ab7878c9", "src_ip": "63.58.36.189", "dst_ip": "10.0.0.9",
 "timestamp": "2024-03-21T02:05:12.263155Z", "username": "pi", "password": "[REDACTED]"}

{"eventid": "cowrie.login.failed", "session": "a3f1c46a600f", "src_ip": "195.207.41.179", "dst_ip": "10.0.0.6",
 "timestamp": "2024-03-19T06:40:14.471852Z", "username": "www", "password": "[REDACTED]"}

{"eventid": "cowrie.command.input", "session": "5a7777cfd76d", "src_ip": "238.193.218.61", "dst_ip": "10.0.0.7",
 "timestamp": "2024-03-18T11:39:31.009266Z", "input": "arch", "message": "CMD: arch"}
```

## Real, simulated, or unknown?

Every verdict below is **confirmed on this machine** from the files themselves and the generator
source — not taken on trust from `DECISIONS.md`.

### Log 1 — Cowrie container capture · SIMULATED

| | |
|---|---|
| **Source addresses** | Every one of the 68 Cowrie-written events has `src_ip 172.18.0.1` — the host side of the Docker bridge. That is this laptop's own NAT address, so the traffic started on this laptop. Only **two** distinct source addresses appear in the whole file, both local. |
| **Client tool** | **100% of 29 client-version events say `SSH-2.0-paramiko_5.0.0`.** Paramiko is the Python library used by `demo/attack_client.py` and `demo/brute_force.py`. No real scanner tool (libssh, zgrab, Go, OpenSSH) appears even once. |
| **Date range** | Three days only: 2026-09-08, 09-26 and 09-29 — each matching a recorded demo session, with nothing in between. |
| **Repeat IPs** | Not applicable in a useful way: there is only one source address, reused across all 8 sessions. |
| **Reachability** | The port is bound to loopback, so a real attacker could not have reached it even if one had tried. |

### Log 2 — prop-injected lines · SIMULATED

| | |
|---|---|
| **Writer identified** | `demo/ssh_honeypot.py` — matched on the literal `HOSTNAME = "svr04"` and its write path `Path(log_dir) / "cowrie.json"`. |
| **Shape mismatch** | Different JSON spacing and key order, and missing `uuid`, `hassh` and `dst_ip`, which real Cowrie writes on every event. `dst_port` is 8081 (the host port), not 2222 (the real listener). |
| **Source addresses** | All 140 events are `127.0.0.1` — loopback. |
| **Date range** | Two days: 2026-09-28 and 09-30. |

### Log 3 — the 15,000-session corpus · SIMULATED

| | |
|---|---|
| **Generator match** | `honeypot_dataset/cowrie/attack_simulator.py` documents its own usage as `--sessions 15000 --output ../data/raw/cowrie_logs/cowrie.json` — this exact file, this exact count. |
| **Impossible addresses** | The generator's `_random_ip()` is four calls to `rng.randint(1, 254)`, so it emits reserved space. `238.193.218.61` appears as a source address; 238/8 is multicast and can never be a source. That alone rules out real capture. |
| **Fake targets** | `dst_ip` is uniformly spread over `10.0.0.1`–`10.0.0.10` (~33k events each) — ten private, randomly chosen fake sensors. Matches the generator's `dst_ip = f"10.0.0.{rng.randint(1, 10)}"` line for line. |
| **Repeat IPs** | **15,000 sessions, 15,000 unique source addresses** — each used exactly once, zero repeat offenders. Real honeypot traffic is dominated by the same scanners returning again and again. |
| **Missing field** | No `sensor` key appears anywhere in 336,764 events. Real Cowrie writes one on every single event. |
| **Date range** | 2024-03-01 to 2024-03-30 — one clean calendar month, which is the generator's `--days` window, not an observation period. |

### Log 4 — gateway and pipeline logs · SIMULATED

| | |
|---|---|
| **Files** | `traffic_gateway/logs/gateway.log`, `traffic_gateway/data/sessions.jsonl`, `logs/pipeline_results.jsonl` |
| **Source addresses** | 162 of 163 session lines are `127.0.0.1`; the 163rd is the literal string `"system"`. The only IP record on file is `127.0.0.1`, which was MT3-blacklisted as `ACCESS_BRUTE_SSH` and later promoted back to whitelisted. |
| **Date range** | 2026-09-30, 10:55 to 17:46 — a single afternoon. |

## Cloud provider and operating system

**Not deployed.** Nothing on this machine indicates a cloud server exists, so there is no provider
or OS to name. What was checked:

- No `deploy/` folder in this working copy at all.
- No Terraform, no cloud-init, no provider SDK or CLI config in any tracked file.
- The only cloud strings in the codebase are honeypot bait: `demo/ssh_honeypot.py` serves the
  public AWS documentation example key (`AKIAIOSFODNN7EXAMPLE`), and `cve_intelligence/config.py`
  describes fake `169.254.169.254` metadata as something a honeypot *should* show.
- No public listener: the Cowrie port is loopback-bound, and the gateway's `0.0.0.0:8080` is not
  running.

The `deploy/sandbox/` kit on the `feature/mitigation-layer` branch does mention Oracle Cloud and
ARM in its notes, but it is a plan, not a deployment — it is not in this working copy, and its own
documentation says it has never been run on a real cloud server. **Not confirmed:** whether a
server exists somewhere outside this laptop; nothing here would show it.

> ### Worth flagging for the mitigation work
>
> The real Cowrie container and the demo prop **write to the same `cowrie.json`**, and the sandbox
> compose file mounts that same folder. In the existing log, 46 of 54 sessions are prop-injected.
> If the sandbox ever goes public with the demo still in use, real internet sessions and fake
> loopback sessions land in one file with no way to separate them after the fact. The `sensor` and
> `source` fields added in commit `4a6ed19` are exactly the right fix — this is a live problem
> today, not a hypothetical one.

---
---

# PART 2 — How this laptop differs from GitHub

## Git position

| Item | State |
|---|---|
| Current branch | `main` @ `ae1761b` |
| Upstream tracking | **none configured** — `main@{upstream}` does not resolve, so git cannot report ahead/behind on its own |
| vs origin/main | measured directly: **0 ahead, 0 behind** — identical |
| Stashes | none |
| Uncommitted | 7 modified tracked files, 1 untracked file |
| Local-only commits | **3**, none on `main`: `f0ada86` and `655e0c7` (on `feature/ml-analytics`, "MT3 architecture with DAG-constrained CRF decoding") and `4374414` (on `revert-2-feature/ml-analytics`) |
| New on the remote | Two branches this laptop had never seen before the fetch: `origin/feature/mitigation-layer` (`4a6ed19`) and `origin/frontend` (`3cec27c`) |

The mitigation branch is now fetched locally, as requested. It was **not** merged, pulled into
`main`, or checked out — everything inspected from it was read via `git show`.

## Where each changed file should go

### A — Should go to GitHub

*Code and shared docs.*

- `.gitignore` — adds three lines so `DEMORUN.md` stays local. A shared rule; every machine should
  have it.
- `CHANGES_AFTER_30_SEPT.md` *(untracked)* — your teammate's written record of the mitigation
  branch. Useful to every machine; her own note says it is deliberately uncommitted, so this is
  your call, but it belongs in A.

### B — Should stay on this laptop only

*Logs, runtime state, machine notes.*

- `traffic_gateway/data/ip_records.json` — one record for `127.0.0.1` from a demo run. Pure
  runtime state.
- `traffic_gateway/data/sessions.jsonl` — a single afternoon of local demo events (632 lines
  removed, a reset).
- Already ignored and correctly local: `honeypot_dataset/cowrie/logs/`, `traffic_gateway/logs/`,
  `logs/`, `adaptive_honeypot/active_config.json`, `demo/*_host_key`, `ASUS.md`, `HARDWARE.md`,
  `SETUP.md`, `DEMORUN.md`, `.claude/settings.local.json`.

Worth fixing separately: those two `traffic_gateway/data/*` files are **tracked** while their
siblings `blacklist.json` and `whitelist.json` are ignored. Tracking live runtime state guarantees
a conflict every time two machines run the demo.

### C — Large data, copy another way

*All already gitignored. Listed so you know what a fresh clone will **not** have.*

- `tabsyn/` — **8.7 GB**
- `honeypot_dataset/data/synthetic/` — 993 MB
- `honeypot_dataset/data/raw/` — 966 MB (includes the 80 MB 15k-session corpus)
- `honeypot_dataset/data/final/` — 477 MB (the frozen HoneySynth-960k splits)
- `honeypot_dataset/data/processed/` — 396 MB (includes `semantic_pca.pkl`)
- `ml_analytics/data/` — 245 MB · `ml_analytics/artifacts/` — 194 MB (includes
  `mt3_full_d256/best.pt`, 45 MB)
- `test_real_clean_mask.npz` — small but local-only

### D — Your decision

*The four modified notebooks — 5,000+ changed lines between them.*

- `01_process_real_data.ipynb` — output text only.
- `02_feature_extraction.ipynb` — **3,674 added lines of ipywidgets progress-bar state**
  (`model_name` / `_view_name` / `state`, 99 blocks). Junk from tqdm.
- `03_tabsyn_generation.ipynb` and `05_assembly_validation.ipynb` — the diff looks like source
  edits, but it is Jupyter re-serialising each cell's `source` from one long string into a list of
  lines, plus `execution` timing metadata and outputs.

I checked the actual text: **no code or logic changed in any of the four**. My recommendation is to
discard these, since committing them adds thousands of lines of noise and no information. They are
your files under `TEAMMATES.md`, so it is your call — hence group D rather than B.

## Are the two unpushed fixes here?

**No. Neither fix is on this laptop.** Both exist only on `origin/feature/mitigation-layer`, now
fetched.

| Fix | On this laptop | On the branch |
|---|---|---|
| 172.1 / 172.2 prefix check | **Still buggy** — `peer_attribution.py:37` `ip.startswith("172.1") or ip.startswith("172.2")`; `post_session_pipeline.py:234` `not peer_ip.startswith(("172.1", "172.2"))` | **Fixed** — `ipaddress.ip_network("172.16.0.0/12")` behind a new `is_docker_bridge_addr()`; the pipeline now routes the decision through `response_mitigation/safelist.py`, which uses the same real range. |
| Startup validation of gateway settings | **Absent** — `config.py` has no `ValueError` and no validation anywhere. Its `__post_init__` only creates directories; `CLASSIFIER_ROUTING` and `DEBUG` use a bare `bool(os.getenv(...))`. | **Present** — `_env_bool` / `_env_int` / `_env_float` / `_env_path` helpers that raise `ValueError` naming the offending variable and its allowed range. |

Also worth knowing: `response_mitigation/` in this working copy is **empty** — an empty
`__init__.py` and an empty `network_controls/` folder. All 35 files of the mitigation package live
on the branch only. The branch adds 60 files and +8,509 lines across `response_mitigation/` (35),
`deploy/` (18), `traffic_gateway/` (6) and `CLAUDE.md` (1).

## Is this repo inside OneDrive?

**Yes.** The repo sits at `C:\Users\mahit\OneDrive\Desktop\adaptive-honeypot-ml-CAPSTONE`, and
`$OneDrive` resolves to `C:\Users\mahit\OneDrive` — so the whole tree, including the `.git` folder,
is being synced.

That is worth knowing because OneDrive syncs git's internal object and index files while git is
using them, which can corrupt a repository or silently revert work, and because the two large
ignored trees here (`tabsyn/` at 8.7 GB and ~3 GB of datasets) are being uploaded to your OneDrive
quota. Moving the repo outside OneDrive, or excluding the folder from sync, would remove both
risks.

## Any secrets tracked by git?

**No.** Clean on both `main` and the mitigation branch.

- The only secret-shaped tracked files are templates: `honeypot_dataset/.env.example` (contents:
  `NVD_API_KEY=YOUR_NVD_API_KEY_HERE`) and, on the branch, three `deploy/sandbox/*.env.example`
  files.
- `.env` is ignored at `.gitignore:3`, and **no real `.env` exists on disk** anywhere in the repo.
- No API-key-shaped literals in any tracked `.py`, `.cfg`, `.json` or `.yml`. The one key-looking
  string, `AKIAIOSFODNN7EXAMPLE`, is the public AWS documentation placeholder used as honeypot
  bait.
- `demo/honeypot_host_key` and `demo/real_server_host_key` exist locally but are correctly ignored.
  They are throwaway demo SSH keys.

> ### One correction to the handover doc
>
> Known gap #1 in `CHANGES_AFTER_30_SEPT.md` says the model files are on the DGX and not on this
> laptop. **They are both here**, at exactly the paths `traffic_gateway/feature_bridge.py` lines
> 29–30 look for: `ml_analytics/artifacts/mt3_full_d256/best.pt` (45 MB) and
> `honeypot_dataset/data/processed/semantic_pca.pkl` (96 KB). The mitigation engine can be run end
> to end against the real MT3 model on this machine, not just a stand-in.

---
---

# PART 3 — Review of the mitigation layer

Read from `origin/feature/mitigation-layer` via `git show`. Nothing was merged or checked out.

## Context for the notes below

The layer has one public call, `engine.handle(verdict)`, and a clean three-way split:
`policy.py` decides what we *want* (a pure function — no files, no network, no clock),
`engine.py` decides what we are *allowed* to do (safety list, mode, caps, kill switch), and
`executors/` carry it out. Every decision is written to the audit log, including the ones that
did not happen.

With the default thresholds, one attacker is routed like this:

| MT3 says | Planned | What happens in `observe` mode |
|---|---|---|
| confidence < 0.5 (any phase) | OBSERVE | recorded, nothing else |
| phase 0 — Reconnaissance | OBSERVE | recorded, nothing else |
| phase 1–3 — Initial Access, Execution, Discovery | DIVERT | pinned to the honeypot |
| phase 4–6 — PrivEsc, Persistence, Defense Evasion, under 3 sessions | DIVERT | pinned to the honeypot |
| phase 4–6, **3+ sessions from that IP** | DIVERT + DENY | pinned; the firewall drop is logged as *would-apply* only |
| phase 7–8 — Lateral Movement, Exfiltration, under 3 sessions | DIVERT + ALERT | pinned; alert logged as *would-apply* |
| phase 7–8, 3+ sessions | DIVERT + ALERT + DENY | pinned; the other two logged, not done |

`DIVERT` is **not** a block: `traffic_router.py:13` sends a blacklisted IP to the honeypot
("keep observing; useful intel"). `DENY` is the only action that drops traffic, and the pipeline
never touches the firewall itself — it writes `blocklist.json`, and a root script on the Linux
host (`host/apply_blocklist.py`, systemd timer every 15 s) re-validates every address as untrusted
input and calls `nft` with an argument list, never through a shell.

**Practical note for testing on this laptop:** `127.0.0.1` is currently in `whitelist.json`, and
the whitelist check runs *before* the DIVERT/DENY split — so a demo run today records OBSERVE and
does nothing. Clear the whitelist first.

## Does it align with the project?

**Mostly yes, and in two places it is a direct fit.** `CLAUDE.md` describes `response_mitigation/`
as "scaffolding; auto-blacklist currently lives in post_session_pipeline" — this fills exactly that
gap and moves the inline block out. The `deploy/sandbox/` kit serves ROADMAP **M1** (get Cowrie on
a VPS) directly. The 2,916-combination test proving default behaviour is byte-identical to the old
inline condition is the right way to land a refactor like this.

**One real tension.** ROADMAP §5 makes the paper's headline figure an A/B **intelligence-yield**
study: commands captured per session, session depth, *kill-chain depth reached*, *fraction of
sessions that advance past Initial Access*.

The `repeat_offender` rule fires at phase ≥ 4 with 3+ sessions — precisely the attackers who
generate the most valuable data. Firewall-dropping them truncates the exact metric the paper is
built on, and if enforce mode runs on both arms it confounds the comparison outright.

Her defaults are already correct (`observe` + `MITIGATION_FIREWALL=0`), so nothing is broken. But
it should be written down explicitly: **enforce mode stays off for all of M1 and M3.** The
`replay.py` tool is the right instrument instead — it runs recorded sessions through the policy on
a simulated clock and reports TP / FP / FN / TN without touching anyone.

Note that the two main actions pull opposite ways on the paper's goal: DIVERT *increases* yield
(the honeypot is the measuring instrument), DENY *destroys* it. Worth stating in the design doc.

## How an IP actually moves through the system

Needed to follow the findings below. Verified from `traffic_router.py`, `inspection_gateway.py`,
`whitelist_promoter.py` and `reputation_scorer.py`.

**There are two separate classifiers, and they are easy to confuse.**

| | Heuristic scorer | MT3 |
|---|---|---|
| Runs | At connection time, and again after each session closes | After each session closes |
| What it is | 5 hand-weighted behavioural signals | 128 features, 45 micro-states, trained model |
| Controls | Routing and IP status | Honeypot adaptation and mitigation |

**MT3 never touches routing directly.** It influences it only through the blacklist the mitigation
layer writes — and the heuristic scorer can undo that blacklist 70 minutes later. The trained model
is subordinate to a hand-weighted formula.

**Naming problem for the paper.** The function is `ml_risk_assessment()` and the field is
`last_ml_score`, but `reputation_scorer.py` describes itself as *"a heuristic risk score"* —
hand-written step functions with fixed weights, nothing learned. `ip_records.json` prints the
formula in plain text: `entropy=0.10 volume=0.15 honeypot=0.10 duration=0.20 freq=0.18 ->
weighted=0.136`. **Do not call this ML in the paper.** Same class of problem as "MT3 has no CRF
despite the naming" — add it to `DECISIONS.md`.

**Routing is decided by IP status, not by traffic content.** `CLASSIFIER_ROUTING` defaults to off,
so `traffic_classifier`'s verdict is telemetry only (`gateway_score` / `gateway_verdict` /
`gateway_signals`). The router's own comment says so: *"telemetry always; routing when enabled."*

| Status | Goes to |
|---|---|
| `WHITELISTED` | **real server** |
| `BLACKLISTED` / `PROBATION` / `SUSPICIOUS` / `UNKNOWN` | honeypot |

**The lifecycle, with measured timings:**

| Transition | Condition | Time |
|---|---|---|
| `UNKNOWN` → `SUSPICIOUS` | heuristic score ≥ 0.45 | after a session |
| `UNKNOWN` / `SUSPICIOUS` → `BLACKLISTED` | heuristic score ≥ 0.70, **or** MT3 via DIVERT | after a session |
| `BLACKLISTED` → review eligible | `MIN_BLACKLIST_SEC` | 600 s |
| `BLACKLISTED` → `PROBATION` | score < `SCORE_PROMOTE` (0.25) | 60 s review loop |
| `PROBATION` → `WHITELISTED` | `PROBATION_SEC` clean, < 3 strikes | 3600 s |
| `WHITELISTED` → `BLACKLISTED` | heuristic score ≥ 0.70 (continuous monitoring) | after a session |

**Two consequences that are almost certainly unintended:**

1. **A well-behaved IP never reaches the real server.** The promoter only reviews `BLACKLISTED` and
   `PROBATION` records. An `UNKNOWN` IP is never reviewed, so it stays in the honeypot forever.
   **Getting flagged as an attacker is the only automatic route to trusted access.** Minimum path:
   600 s + 3600 s = **70 minutes**. Measured on this laptop: `127.0.0.1` took 70 min 48 s.
2. **MT3 cannot whitelist anything.** It only ever contributes a blacklist. The only two ways to
   become whitelisted are the promoter loop and `POST /api/whitelist`, which has no authentication.

## Improvements

### The most serious finding — the whitelist bypass — ✅ PARTLY FIXED 2026-11-04

**Status.** Fix #2 below (let MT3 override the whitelist) is implemented and
tested. Fixes #1 (dashboard authentication) and #3 (recent-window maximum rather
than a lifetime average) are **still open**, and #1 is still the one that matters
most before anything faces a network.

What changed: `safelist.skip_reason()` now receives the verdict's phase and
confidence, so it can weigh evidence instead of short-circuiting on
`is_whitelisted`. A DIVERT may override a whitelist above
`whitelist_override_min_phase` (2) and `whitelist_override_min_confidence`
(0.90) — stricter than the ordinary blacklist floors (1 / 0.50), because
overriding explicit trust should need more evidence than blocking a stranger.
A DENY never overrides a whitelist, because a firewall drop of a trusted address
can lock you out.

Measured after the change:

```
                                                DIVERT                 DENY
untrusted IP, strong verdict (ph6/0.98)         applied                applied (nft rule)
WHITELISTED, strong verdict  (ph6/0.98)         applied   <-- fixed    skipped: whitelisted
WHITELISTED, phase ok low conf (ph6/0.60)       skipped: whitelisted
WHITELISTED, conf ok low phase (ph1/0.98)       skipped: whitelisted
WHITELISTED, weak verdict    (ph1/0.60)         skipped: whitelisted
```

`never_block` and `own_addresses` stay DENY-only, as originally designed
("must never be DENIED") and as `test_never_block_list_does_not_stop_a_divert`
asserts. An earlier draft extended them to DIVERT; that was scope creep past what
this finding recommended and was reverted. **Residual question for the team, not
settled here:** an admin address is usually whitelisted too, so a strong verdict
can now divert it to the decoy. If that is unacceptable, extend `never_block` to
DIVERT deliberately and update that test.

The original finding follows, unchanged, for the record.

#### Original finding

This outranks everything else on the list, including the A/B tension. It is a chain, and every link
is confirmed in code:

```
POST /api/whitelist   →  no authentication, CORS(app) wide open
      ↓
you are WHITELISTED
      ↓
traffic_router sends you to the REAL SERVER, not the honeypot
      ↓
safelist.py checks is_whitelisted BEFORE the DIVERT/DENY split,
so every MT3 verdict returns "skipped: whitelisted" at any phase or confidence
      ↓
only the heuristic scorer can re-blacklist you — and it averages
over up to 50 sessions (session_tracker.MAX_HISTORY_PER_IP)
```

**Anyone who can reach port 5000 gets past the gateway, the honeypot and MT3 in one HTTP request.**

Even without that endpoint, a legitimately earned whitelist is nearly as good. An attack from a
whitelisted IP is fully classified by MT3 and written to the results file, but the mitigation layer
records `divert / skipped: whitelisted` and does nothing. The only backstop is the heuristic score,
and every one of its signals is an **average** — `avg_entropy`, `avg_bytes_in`, `avg_duration`,
honeypot ratio. One attack among 49 clean sessions barely moves it. A whitelisted IP by definition
has a long clean history, because it spent 70+ minutes earning one. **The longer an attacker
behaves, the harder it becomes to catch them.** `ip_records.json` already shows `sample=20
sessions` diluting a score to 0.136.

Note also that the gateway's only identity check is the source address. SSH needs a full TCP
handshake so blind spoofing fails, but ARP-spoofing onto a whitelisted LAN address would work.

**Three fixes, in priority order** — #1 and #2 are now DONE (2026-11-04), #3 is open:

1. ✅ **DONE.** `traffic_gateway/api_auth.py`: a bearer token on all four
   state-changing endpoints, CORS narrowed from every origin to
   `GATEWAY_API_ORIGINS`, and — the part that actually protects anyone — a
   start-up guard that **refuses to bind a reachable address with no token**,
   because the realistic mistake is deploying to a VPS having never set one. The
   API host also now defaults to `127.0.0.1` rather than `0.0.0.0`: the React
   dashboard calls `127.0.0.1:5000` and two-laptop peers connect to the gateway
   on 8080, so the API never needed to be network-reachable at all.

   `run_pipeline.py` calls `app.run()` directly and so bypassed `serve()`'s
   guard; it now calls the guard itself, before the ~90 s of model loading rather
   than after. Refusal takes 0.4 s.

   Leaving `GATEWAY_API_TOKEN` unset on loopback keeps today's behaviour exactly,
   so the demo is unaffected. 37 tests in `tests/test_api_auth.py`.

   Still no TLS: a bearer token over plain HTTP is readable in transit, so on a
   public host this belongs behind an SSH tunnel or a TLS proxy. The guard stops
   the no-token mistake, not every transport mistake.

2. ✅ **DONE.** MT3 can now override the whitelist — see the status note at the
   top of this finding.

3. ⬜ **OPEN. Make the heuristic use a recent-window maximum, not a lifetime
   average**, so one serious session cannot be diluted away by history.

**The original text of the three fixes follows.**

1. **Get the dashboard authentication committed before anything faces the internet.** Her
   uncommitted work already does this; right now `api.py` on `main` has open CORS and no login on
   four state-changing endpoints (`POST`/`DELETE` on `/api/blacklist` and `/api/whitelist`). This
   is more urgent than any of the thirteen numbered items.
2. **Let MT3 override the whitelist above some phase.** Invert the order in
   `safelist.skip_reason()` so a high-phase, high-confidence verdict wins over `is_whitelisted`.
3. **Make the heuristic use a recent-window maximum, not a lifetime average**, so one serious
   session cannot be diluted away by history.

### Must discuss

**1. Enforce mode vs. the A/B study.** As above. Document that enforce mode stays off for M1 and
M3; consider a loud startup warning when `MITIGATION_FIREWALL=1` and `PIPELINE_SOURCE=internet`.

**2. The policy throws away the 45 micro-states.** `plan()` reads only `phase` and `confidence`;
`micro_state` is used purely for the reason text. So the response layer collapses MT3's output to a
9-way bucket that a far simpler classifier could produce — and the project's whole claimed
contribution is micro-state resolution. A per-micro-state override table is what would make this
layer a *paper contribution* rather than a sysadmin script: `EXFIL_*` → DENY on first sighting
regardless of repeat count; `DEFENSE_EVASION_*` → ALERT because the session is about to go dark;
`RECON_*` stay OBSERVE even at high confidence. Headline: *response granularity follows
micro-state, not phase.*

**3. Nothing is audited when the layer is off.** `handle()` returns `[]` with no log line when the
kill switch is on or mode is `off`. If the kill switch gets left on during an incident, the log is
silent — you cannot later prove whether the layer saw the verdict and chose nothing, or never ran.
Write one `OBSERVE / skipped / "mode is off"` record per verdict, rate-limited per IP if needed.

### Should fix

**4. `sessions_seen` never decays, and the audit log is loaded whole into RAM.** Three sessions six
months apart score the same as three in five minutes. And `session_ids_by_ip()` reads the entire
file and holds `{ip: set(session_ids)}` for the process's life, with `engine._sessions` growing
forever — on an internet honeypot (M1 targets thousands of sessions) that is unbounded memory and a
slow startup. Make it a sliding window (`MITIGATION_DENY_WINDOW_HOURS`, default 24): it fixes the
semantics and lets the log be pruned. Also rotate the audit log.

**5. The gateway can silently undo a DIVERT, and that buys permanent DENY immunity.**
`whitelist_promoter.py` walks BLACKLISTED → review_eligible → PROBATION → WHITELISTED on its own
schedule. The mitigation log says "DIVERT applied" and nothing ever records the reversal. Worse,
once whitelisted, `safelist.skip_reason` returns `"whitelisted"` *before* the DIVERT/DENY split —
so the IP becomes immune to the firewall too. This is not hypothetical: in the local
`ip_records.json`, `127.0.0.1` went MT3-blacklisted → probation → fully whitelisted in 70 min 48 s
(the configured minimum is 600 s + 3600 s). Either have the promoter refuse to rehabilitate IPs
blacklisted by `mt3_pipeline` above some phase, or have it call `engine.record_manual(...)` so
reversals land in the audit log.

**See "The most serious finding — the whitelist bypass" above**, which is the full version of this
problem: once rehabilitated, the IP is routed to the real server *and* becomes permanently immune
to MT3, and the only remaining backstop averages a single attack away across 50 sessions.

**6. The confidence floor ignores feature degradation.** The pipeline already warns when
`semantic_available` is False — 30 of 128 features (Group D, DistilBERT command semantics) are
zero-filled, and `CLAUDE.md` says that degrades confidence on exactly the command-driven classes.
The policy still uses a flat 0.5. Pass that flag into the engine and raise the floor, or cap the
worst action at ALERT, when Group D is dead.

**7. A flat 0.5 floor is weak for the classes that trigger DENY.** Phases 4–8 are the
honeypot-command classes, and per `DECISIONS.md` only 13 network-flow classes have a real anchor at
all — so DENY will be driven by the least-validated part of the model, whose honest `test_real`
macro-F1 is 0.8187 over just 21 of 45 classes. Set per-class floors from
`ml_analytics/artifacts/mt3_full_d256/metrics_test_real.json`, and require a higher floor for any
class with no real anchor.

### Worth knowing

**8. DIVERT is nearly a no-op in the default config.** `traffic_router` already sends UNKNOWN →
honeypot (zero-trust), so blacklisting only changes routing for an IP that would otherwise reach
the real backend. Not a bug — just worth saying out loud so nobody over-claims it. Its real value
is durable state and, per #5, blocking promotion.

**9. There is an hourly cap on DENY but none on DIVERT.** Thousands of distinct IPs per day will
grow `blacklist.json` and `ip_records.json` without bound, and the gateway loads both in full at
startup. Cap or expire them too.

**10. Three small ones.**
- The hourly DENY cap is in-memory, so a restart loop multiplies the effective cap. It could be
  rebuilt from the audit log's tail, which the engine already reads at startup.
- `MITIGATION_MAX_NEW_BLOCKS_PER_HOUR=0` is a second, undocumented off switch that reports
  differently from `MITIGATION_FIREWALL=0` (SKIPPED "hourly cap" vs WOULD_APPLY "firewall switched
  off"). Worth one line in the settings table.
- `handle()` holds its lock across the whole decision, including a cross-process file lock with a
  10 s timeout and an fsync. Harmless while the watcher is single-threaded; worth a comment for
  when it is not.

### What is already right, and worth keeping

- `policy.py` as a pure function — no I/O, no clock — so every row is trivially testable.
- Fail-safe everywhere: an unreadable kill-switch file counts as ON; a non-writable audit log
  refuses the block; an executor that raises becomes a FAILED decision and never reaches the
  pipeline.
- The root script treats `blocklist.json` as untrusted and re-validates every address; `nft` is
  called without a shell; the pipeline needs no privilege at all.
- Atomic writes plus a cross-process lock file, so the pipeline, the CLI and the dashboard cannot
  overwrite each other.
- The webhook never follows a redirect and never writes its URL to a log.

### Process note

Commits 5 and 9 touch `post_session_pipeline.py`, commit 2 touches `traffic_gateway/config.py`, and
commit 3 touches shared `CLAUDE.md` — all owned by Mahith under `TEAMMATES.md`. She flagged all
three herself; just settle who merges them.

---
---

# PART 4 — Verification runs on this laptop

Two runs on 2026-11-02, both on branch `mitigation-test` (a local branch off
`origin/feature/mitigation-layer`). Nothing was merged or committed. The pre-test state was backed
up before each run and restored afterwards, so Parts 1 and 2 above are still accurate.

1. **Attack run** — hostile sessions through the honeypot, to exercise the mitigation layer against
   real MT3 verdicts. Findings 11-13.
2. **Benign run** — genuinely harmless sessions through the gateway, to test whether MT3 can
   recognise safe traffic. Finding 14, and the subject of `02-11-2026 FINDINGS.md`.

## Test suite

**387 passed · 16 skipped · 1 failed · 3728 subtests passed** (12.6 s).

The one failure is the pre-existing `test_honeypot_round_robin`:
`AssertionError: 1 not greater than 1`, because `CONFIG.HONEYPOT_TARGETS` holds a single entry.
It is not related to her work. The 3,728 subtests include her 2,916-combination
same-as-today equivalence test.

**Her reported figures were 458 passed / 26 skipped / 1 failed.** The gap is worth a question:
**neither venv on this laptop had pytest installed at all**, so her numbers come from a different
machine and probably a wider collection path.

## The real MT3 model — known gap #1 is now closed

The model loaded exactly as documented:

| | |
|---|---|
| MT3 | **3,759,510 params**, cpu, val macro-F1 **0.9599** |
| Checkpoint | `ml_analytics/artifacts/mt3_full_d256/best.pt` |
| Semantic encoder | DistilBERT + the real `semantic_pca.pkl` — **Group D was not zero-filled** |
| Threat intel | 1,675 KEV CVEs cached |
| Startup | 98.4 s |

Real Cowrie sessions driven through the honeypot produced genuine MT3 verdicts across three
phases, and the configurator adapted the honeypot each time:

| Micro-state | Confidence | Phase | Honeypot reaction |
|---|---|---|---|
| `ACCESS_BRUTE_SSH` | 0.886 | 1 — Initial Access | interaction → low |
| `EXEC_WGET_EXEC` | 0.630 | 2 — Execution | interaction → medium |
| `EVASION_LOG_WIPE` | 0.986 | 6 — Defense Evasion | interaction → high; planted `/etc/shadow` + SSH host key |

## All four mitigation paths exercised

| Outcome | Count | Detail |
|---|---|---|
| `divert / applied` | 1 | "added to the gateway blacklist" — and `blacklist.json` really received `MT3: EVASION_LOG_WIPE (phase 6 Defense Evasion, conf 0.99)` |
| `divert / skipped` | 3 | "already blacklisted" — executor idempotency works |
| `deny / skipped` | 2 | "not a public unicast address" — the safelist correctly refuses to firewall-block loopback |
| `divert` + `deny / skipped` | 36 | "Docker bridge address (no real peer was found)" — the new `172.16.0.0/12` check works |

`repeat_offender` fired on cue once a source had 3+ sessions at phase ≥ 4. Peer attribution
resolved `172.18.0.1` → `127.0.0.1` correctly once the gateway was in the path.

Also working on Windows: CLI `status`, `blocks`, `audit`, `block`, `unblock`; `replay.py` against a
real results file; a manual block of a public address wrote a correct `blocklist.json` entry with a
real TTL and removed cleanly. The firewall itself was never touched — `host/apply_blocklist.py`
needs Linux and root, so DENY stops at the block list on this machine, as expected.

## New findings — these came from running it, not reading it

**11. When the source address is masked, the layer silently does nothing — at any severity.** The
first run hit the honeypot port directly instead of going through the gateway. Every one of 35
sessions arrived as `172.18.0.1`, and **every decision was skipped** — including the phase-6
`EVASION_LOG_WIPE` at 98.6% confidence. That is the safelist behaving correctly: it must not
blacklist our own Docker bridge.

**Scope — narrower than it first looks.** Her `check_cowrie_ips.py` docstring states the real rule:
the address is masked only when the connection reaches the container **through a proxy process,
which happens for IPv6 and for connections made from the host itself**. On plain IPv4 publishing
Docker rewrites only the destination, so the container sees the real remote address. What I
observed was therefore an artefact of connecting from the host, *not* a VPS failure mode — on a
correctly configured IPv4 VPS, Cowrie sees real attacker addresses and the layer acts normally. She
had already defended both edges: IPv4-only publishing in the compose file, and
`check_cowrie_ips.py` to verify it.

**The residual point still stands.** Whenever masking does occur — a local demo, an IPv6
misconfiguration, a userland-proxy publish — the layer skips quietly, and thousands of
"skipped: Docker bridge" lines are indistinguishable in the audit log from "no attacks happened".
It should escalate instead: a WARNING, a counter, or an ALERT on a sustained run of
bridge-attributed sessions.

**12. `sessions_seen` collapses every attacker into one counter when attribution fails.** It
reached **35** for the single pseudo-address `172.18.0.1`. So `repeat_offender` would fire on the
third session *globally* rather than the third session from one attacker — turning a per-attacker
rule into a per-sensor rule. This compounds improvement #4 (no time decay): the counter is both
unbounded in time and, in this failure mode, shared across everyone.

**13. The startup banner hides the mitigation state.** `startup_info["mitigation"]` is populated
with `mode`, `firewall` and `audit_path`, but `run_pipeline`'s banner never prints it — so you
cannot see at a glance whether the layer is in observe or enforce mode, or whether the firewall is
armed. One-line fix, and it matters most in exactly the situation where it would be dangerous to
guess.

**14. One MT3 false positive silently rewrites the gateway's verdict on every later session from
that IP.** Found during a second run that drove genuinely *benign* SSH sessions through the gateway
into the live Cowrie container. Full treatment in `02-11-2026 FINDINGS.md` finding 1b; the part that
belongs here is what it does to the data:

| Benign session | Gateway heuristic | MT3 verdict | Conf |
|---|---|---|---|
| `whoami ; uptime ; ls ; exit` | **BENIGN (0.14)** | `EXEC_MEMFD_EXEC` | 0.717 |
| `df -h ; free -m ; exit` | MALICIOUS (1.0) | `DISC_PROC_ENUM` | 0.915 |
| `cd /etc ; cat nginx.conf ; systemctl reload nginx` | MALICIOUS (1.0) | `PERSIST_SYSTEMD_SVC` | 0.898 |
| logged in, typed nothing | MALICIOUS (1.0) | `ACCESS_BRUTE_SSH` | 0.640 |

On the first session — the only one where the heuristic had a clean read — **the heuristic was right
and MT3 was wrong**, and MT3's answer is the one that became durable state. `127.0.0.1` was
auto-blacklisted as `EXEC_MEMFD_EXEC (phase 2 Execution, conf 0.72)`, and the honeypot escalated to
high interaction, planting `/etc/shadow` and a fake SSH host key to bait an "attacker" who was
running `cat nginx.conf`.

From that point on, the gateway's verdict for that IP was `MALICIOUS` at score **1.0** with
`signals=['blacklist']` — the blacklist *is* the signal. Those three fields (`gateway_score`,
`gateway_verdict`, `gateway_signals`) are written into every row of `pipeline_results.jsonl`, which
is the file the dashboard reads and the file any later analysis would use.

**So `gateway_*` is not an independent second opinion on a session.** Once an IP has been
blacklisted — by MT3 or by anything else — those columns are a restatement of that decision, and
nothing in the row distinguishes "scored malicious on its own evidence" from "scored malicious
because we already blacklisted it". Two consequences:

- Any evaluation that treats `gateway_verdict` as a comparison label against MT3 is measuring
  agreement with MT3's own past decisions. The A/B study must either record the pre-blacklist score
  separately or exclude blacklist-driven rows.
- It makes a false positive self-reinforcing in the record, which is exactly the failure mode that
  is hardest to notice after the fact.

## State after the runs

Back on `main`, working tree as before — the same 7 modified files, plus the three untracked
documents at the repo root. Nothing merged, nothing committed.

- Branch `mitigation-test` is kept locally.
- Restored from backup after each run: `cowrie.json` (70 lines), the dated rotations,
  `logs/pipeline_results.jsonl` (10 lines), the gateway's whitelist / blacklist / ip_records /
  sessions, and `active_config.json`.
- Evidence kept in the scratchpad: `test-evidence/` (attack run) and `benign-evidence/` (benign
  run), each holding the mitigation audit log, the pipeline results and the Cowrie log as they
  stood at the end of that run.
- **One change not reverted: `pytest` is now installed in `honeypot_dataset/venv`** — it was absent
  from both venvs, which is why the test totals differ from the teammate's.

---
---

# Message to send — honeypots, logs, cloud

> I audited what's actually running on my laptop before you take the mitigation layer further.
> Three things to know:
>
> **There is one honeypot, not four.** A single Cowrie container, `cowrie-honeypot`, image
> `cowrie/cowrie:latest` pinned by digest to version **v3.0.13**. It pretends to be an SSH server
> on an old Debian box (hostname `svr04`, banner `SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2`). Telnet
> is off; there is no web, database or login-page honeypot. Ports: container `2222` → host
> `127.0.0.1:8081`, **loopback only, so it is not reachable from outside my machine**. Logs land in
> `honeypot_dataset/cowrie/logs/cowrie.json`; TTY recordings and fake downloads stay inside Docker
> volumes. The "four honeypots" idea comes from a commented-out list in `traffic_gateway/config.py`
> (lines 45–49) — the live list has one entry, and the gateway's own startup log says
> `"honeypot_count": 1`. `adaptive_honeypot/emulators/` is an empty folder. I'm not counting
> `demo/ssh_honeypot.py` or `demo/real_server.py`; those are demo props.
>
> **Every attack in every log is simulated.** No real attacker traffic exists anywhere on this
> laptop. I confirmed it from the files, not from `DECISIONS.md`:
>
> - *Container log* (8 sessions) — all from `172.18.0.1`, the Docker bridge, meaning the traffic
>   started on my laptop. 100% of client-version events say `SSH-2.0-paramiko_5.0.0`, which is our
>   own `attack_client.py`. Only three dates: 2026-09-08, 09-26, 09-29.
> - *Same file, 46 more sessions* — these were **not written by Cowrie**. They're from
>   `demo/ssh_honeypot.py` (`sensor: "svr04"`, `src_ip 127.0.0.1`, `dst_port 8081`, no `uuid` or
>   `hassh`). So 46 of 54 sessions in that log are prop-injected.
> - *The 15,000-session corpus* (`data/raw/cowrie_logs/cowrie.json`, 336,764 events) — generated by
>   `attack_simulator.py`, which documents this exact file and count. Hard proof:
>   `238.193.218.61` appears as a source address, and 238/8 is multicast which can never be a
>   source; `dst_ip` is uniformly `10.0.0.1–10.0.0.10`; 15,000 sessions have **15,000 unique source
>   IPs with zero repeats**; no `sensor` field anywhere; and the dates are exactly 2024-03-01 to
>   2024-03-30.
> - *Gateway and pipeline logs* — 162 of 163 lines are `127.0.0.1`, all from one afternoon
>   (2026-09-30).
>
> **Cloud: not deployed.** No provider, no OS, nothing to name. No `deploy/` folder in my working
> copy, no Terraform or cloud-init in any tracked file, no public listener. The only cloud strings
> in the code are honeypot bait (the public AWS example key, fake `169.254.169.254` metadata). The
> Oracle Cloud and ARM notes in `deploy/sandbox/` are a plan on your branch, not a running server.
> *Not confirmed:* whether a server exists anywhere outside this laptop — nothing here would reveal
> it.
>
> **Two things that should help you:**
>
> - The model files *are* on this laptop, contrary to known gap #1 —
>   `ml_analytics/artifacts/mt3_full_d256/best.pt` and
>   `honeypot_dataset/data/processed/semantic_pca.pkl`, exactly where `feature_bridge.py` looks.
>   You can run the engine against the real MT3 model here instead of a stand-in.
> - The log-mixing problem your `sensor` / `source` fields solve is already live. The real
>   container and the demo prop write to the same `cowrie.json`, and
>   `deploy/sandbox/docker-compose.yml` mounts that same folder. If the sandbox goes public while
>   the demo is still in use, real and fake sessions end up in one file with no way to separate
>   them. Commit `4a6ed19` is the right fix and worth prioritising.
>
> Both of your unpushed fixes are confirmed missing from my copy — the `172.1`/`172.2` prefix check
> is still a string comparison in `peer_attribution.py:37` and `post_session_pipeline.py:234`, and
> `traffic_gateway/config.py` has no startup validation at all. I've fetched your branch and read
> it, but haven't merged anything yet.

---

---
---

# PART 5 — Phase 1 multi-honeypot groundwork (2026-11-04)

Verification runs for MULTI_HONEYPOT.md Phase 1. Everything below was executed on
this laptop against the live Cowrie container's own log, not reasoned about.

## What changed

| File | Change |
|---|---|
| `honeypot_dataset/src/parsers/cowrie_parser.py` | `build_record()` gains keyword-only `protocol="ssh"`, `dst_port=22`; the two hardcoded literals now read from them |
| `honeypot_dataset/src/parsers/session_contract.py` | **new** — 22 required + 19 optional fields, `validate()` / `assert_valid()` / `describe()` |
| `traffic_gateway/post_session_pipeline.py` | `LogSource` dataclass + `cowrie_source()`; `sources=[...]` parameter; per-source tailing, globbing, close detection and watchdog scheduling; `PIPELINE_SOURCE` provenance tag and `sensor` field on every result |
| `traffic_gateway/tests/test_session_contract.py` | **new** — 35 tests over parity, the contract, provenance and multi-source plumbing |

## The measurement that shaped the design

`build_record()` discards the port the log actually carries:

```
raw cowrie.json dst_ports:  {2222: 39931, 22: 19, 3306: 21, 443: 17, 80: 13}
build_record() emitted:     22, always
```

Every Cowrie session in MT3's training set therefore had
`dst_port_norm = 22/65535 = 0.000336`. Reading the real port would have moved
feature 39 by ~100x at inference time with no error raised. Hence the
defaults-preserve-behaviour decision in DECISIONS.md rather than a straight fix.

## Verification results

**Parity — the Cowrie path is untouched.**

```
parsed 10 sessions from the live Cowrie log
default call: 10/10 records still dst_port=22 protocol=ssh   -> PARITY HELD
build_record(events) == build_record(events)                  -> stable
```

**Contract — conforms, and can actually fail.**

```
contract: 22 required + 19 optional
real Cowrie records conforming: 10/10

missing key       -> ['missing required key: protocol']
wrong type        -> ['dst_port is str, expected int']
None value        -> ['command_text is None']
empty protocol    -> ['protocol is empty -- honeypot_target_for() needs it set']
bad port          -> ['dst_port 99999 out of range 1-65535']
negative duration -> ['session_duration_s is negative (-1.0)']
bool-as-int       -> ['n_events is bool, expected int']
NaN               -> ['session_duration_s is NaN']
```

**Multi-protocol resolution — this is what Phase 1 unlocks.** `honeypot_target_for()`
could only ever return `SSH_HONEYPOT` before today:

```
protocol=ssh    dst_port=22    -> SSH_HONEYPOT
protocol=http   dst_port=8080  -> WEB_HONEYPOT
protocol=https  dst_port=443   -> WEB_HONEYPOT
protocol=mysql  dst_port=3306  -> DB_HONEYPOT
protocol=postgres dst_port=5432 -> DB_HONEYPOT
protocol=tcp    dst_port=3306  -> DB_HONEYPOT   (port decides when protocol is unknown)
```

**Two sources tailed at once**, with a synthetic Heralding-shaped log:

```
default sources: ['cowrie']            real cowrie logs found: 5
two sources:     ['cowrie','heralding'] files across both: 6
heralding record: protocol=http dst_port=8080 sensor=heralding-01
                  contract problems: none
                  honeypot_target_for -> WEB_HONEYPOT
```

**Provenance tag.** `PIPELINE_SOURCE` unset or blank → `unspecified`; accepts
`internet`, `injected`, `lab`, `demo`, `vps-1`, `cowrie.ssh_01`; rejects spaces,
semicolons, quotes, newlines and anything over 40 chars by raising at start-up
rather than storing it.

## Test suite

```
traffic_gateway/tests/test_session_contract.py   35 passed (14 subtests)
traffic_gateway/tests/ (whole suite)             74 passed, 1 failed
```

The single failure is **pre-existing and not caused by this work** — confirmed by
stashing the changes and re-running. `test_router.py::test_honeypot_round_robin`
asserts the router cycles across multiple honeypots, but
`CONFIG.HONEYPOT_TARGETS` has one entry (the four-entry list is commented out at
`traffic_gateway/config.py:45-49`), so `len(seen_targets)` is 1 and the
`assertGreater(..., 1)` fails. It will pass once a second honeypot is actually
deployed in Phase 2, and is a fair red flag until then.

## Finding for Phase 2

`build_record` is Cowrie-specific well beyond protocol and port. Fed
Heralding-shaped events (`auth.attempt`, `session.end`) it returned
`login_attempts: 0` and `micro_state: RECON_IP_SCAN`, because it counts only
`cowrie.login.failed` / `cowrie.login.success` and derives labels from
`COMMAND_PATTERNS`. **`functools.partial(build_record, protocol="http", ...)` is
not a usable Heralding parser** — Heralding needs its own `build` with its own
event→micro-state mapping. `LogSource.build` is the hook for that; the point of
the abstraction is that Phase 2 adds a function rather than editing the Cowrie
path.

## Not done in Phase 1

Deliberately out of scope, per MULTI_HONEYPOT.md:

- no second honeypot deployed — that is Phase 2 (Heralding)
- Phase 1b (the Group D out-of-distribution baseline, and the
  zero-fill-vs-feed decision) is untouched
- `api.py` and the dashboard still report `cowrie_log_dir` / `cowrie_logs_found`;
  the new `sources` list is in `startup()` and `stats()` but nothing renders it
  yet (Phase 6)

---
---

---
---

# PART 6 — Phase 1b: baselining the feature pipeline (2026-11-04)

MULTI_HONEYPOT.md Phase 1b. Two questions, both answered by measurement on this
laptop: how well does MT3 already do on the one real HTTP class it has, and what
happens to Group D when it is fed text it was not fitted on.

## Q1 — the existing HTTP result is real, not a leakage artifact

`ACCESS_BRUTE_HTTP` (id 7) and `RECON_VULN_SCAN` (id 4) are the only
web/auth-relevant classes with any real test data. The worry was that their
numbers come from rows duplicated out of training (29.74% of `test_real` is).
They do not:

```
class                  total   clean    dup   clean%
RECON_VULN_SCAN  (4)     213     128     85    60.1%
ACCESS_BRUTE_HTTP(7)     121     116      5    95.9%
-- for contrast --
EXEC_SHELL_OPEN  (12)   4883     259   4624     5.3%
DISC_ENV_PROBE   (18)  22608   16903   5705    74.8%
```

Class 7 is **95.9% clean** -- the leakage is concentrated elsewhere, most
severely in `EXEC_SHELL_OPEN` at 5.3%.

Re-running MT3 (`best.pt`, cpu) over `test_real` and scoring only clean rows:

```
macro-F1 full  0.8272
macro-F1 clean 0.8183

cls name                  n    prec     rec      f1   recall 95% CI (Wilson)
  4 RECON_VULN_SCAN     128   0.962   1.000   0.981   [0.971, 1.000]  128/128
  7 ACCESS_BRUTE_HTTP   116   1.000   1.000   1.000   [0.968, 1.000]  116/116
  6 ACCESS_BRUTE_SSH   1292   0.985   0.963   0.974   [0.951, 0.972]  1244/1292
 18 DISC_ENV_PROBE    16903   1.000   0.998   0.999   [0.997, 0.999]  16870/16903
```

**MT3 gets every clean HTTP-brute-force row right**, and the Wilson lower bound
puts recall at >=96.8% even pessimistically. Stronger than expected.

**The caveat is representativeness, not noise.** Those 116 rows are
CIC-IDS2017-derived *network flows*, not honeypot captures. A perfect score on
them is not evidence MT3 will classify live Heralding sessions correctly; it is
evidence the network-flow features for that class are highly separable. Quote it
as "the one real HTTP class in the test set is classified correctly on all 116
clean rows", never as "MT3 handles HTTP".

## Q2 — Group D is genuinely out-of-domain for non-SSH text

`semantic_pca.pkl`: PCA 768 -> 30, fitted on shell command text, retaining
98.41% of variance *on that domain* with 89.9% in the first two components alone.
That concentration is the problem -- a narrow basis reconstructs foreign text
badly. Measured with real Cowrie `command_text` as the in-domain control:

```
text domain                   n   recon err   var kept   z-dist
shell commands (IN-DOMAIN)   60      0.2981     0.9080     0.00
HTTP request lines           64      0.5129     0.7358     1.22
SQL injection payloads       64      0.5946     0.6413     0.92
credential pairs             64      0.5284     0.7135     0.74
```

`recon err` = relative L2 of what the 30 axes cannot represent; `var kept` = the
fraction of that text's variance they do capture; `z-dist` = mean per-dimension
|z| against the in-domain projection cloud.

Reconstruction error roughly doubles. The axes keep 90.8% of shell variance but
only 73.6% of HTTP's and **64.1% of SQL's**, and HTTP projections sit ~1.2 sigma
off-centre.

## Q3 — but where does a zero-fill land? (this decided it)

The pipeline zero-fills **raw** features and then applies the frozen scaler, so
raw 0 becomes `(0 - mean)/scale`, not the origin:

```
zero-filled Group D after the frozen scaler:
  mean |z| over 30 dims              0.368 sigma
  max  |z|                           1.179 sigma
  dims beyond 1 sigma                1 of 30
  dims beyond 2 sigma                0 of 30
  L2 norm of the point               2.400

training Group D block (n=20,433, already scaled):
  mean L2 norm of a real row         4.857   (p1 2.201, p99 11.499)
  real rows FARTHER out than it      94.65%
  nearest real training row          1.249 away
  median distance between two rows   7.725
```

The zero-fill point is **inside** the training cloud -- nearer the centre than
94.65% of genuine rows, with a real row 1.25 away where typical rows sit 7.7
apart. It reads as unremarkable command text, not an alien input.

**Decision: zero-fill Group D for non-SSH sessions.** Full reasoning in
DECISIONS.md (2026-11-04). A declared degradation that lands in-distribution
beats a silent distortion that does not.

## Cost, stated plainly

Zero-filling makes Group D constant per protocol, so it carries no information:
non-SSH protocols are classified by **98 of 128 features**. That is the price of
not having a per-protocol PCA, and it must appear in the paper rather than
implying 128 live features on every protocol.

## Artifacts written

- `ml_analytics/artifacts/mt3_full_d256/preds_test_real.npy` (480 KB) -- MT3
  predictions over all 60,000 `test_real` rows, so the per-class and clean-subset
  numbers above can be recomputed without re-running inference.
  **Local only** -- `ml_analytics/.gitignore` excludes `artifacts/`, same as
  `best.pt`. Another machine must regenerate it:
  `predict(load_model('.../best.pt'), X_test_real)`, ~40 s on cpu.

## Not done in Phase 1b

- the protocol-conditional zero-fill is a *decision* here, not an
  implementation; the live flag is still the global `SemanticEncoder.available`
- no per-protocol PCA fitted (would require retraining MT3 -- M2 scale)
- `semantic_available` in the result line still cannot distinguish "DistilBERT
  missing" from "deliberately off for this protocol"; Phase 2 needs that split

---
---

---
---

# PART 7 — Phase 2a: the Heralding parser works, MT3 does not (2026-11-04)

Phase 2 was going to be "deploy Heralding, let MT3 classify it". The parser half
is done and clean. The classification half **fails**, and the failure mode is
unsafe rather than merely inaccurate. Read this before standing Heralding up.

## Two prerequisites were missing, so deployment never started

- **Docker Desktop was down** (`npipe:////./pipe/dockerDesktopLinuxEngine` and
  the `default` context both refused), so Heralding was never run and the
  fixtures below are schema-faithful but **unverified against real output**.
- **`deploy/sandbox/` does not exist on `main`** -- it is 18 files on the
  unmerged `feature/mitigation-layer` branch. The compose entry and
  `verify_sandbox.sh` extension have nowhere to go until that branch lands.

## What was built

| File | Contents |
|---|---|
| `honeypot_dataset/src/parsers/heralding_parser.py` | **new** -- `log_session.json` -> session contract, rule-based labeller, UTC-correct timestamps |
| `traffic_gateway/post_session_pipeline.py` | `heralding_source()` factory beside `cowrie_source()` |
| `traffic_gateway/tests/test_heralding_parser.py` | **new** -- 36 tests across timezone, contract, labelling, taxonomy gap, payload choice, routing, wiring |

Schema taken from Heralding's own source (`heralding/misc/session.py`,
`Session.get_session_info`), not the README:

```python
{'timestamp','duration','session_id','source_ip','source_port',
 'destination_ip','destination_port','protocol','num_auth_attempts',
 'auth_attempts':[{'timestamp','username','password'}],
 'session_ended','auxiliary_data'}
```

Three structural differences from Cowrie, all handled:

1. **One line is a whole session.** `log_session.json` is jsonlines with a final
   record flagged `session_ended`, so `is_closed` asks "is this final" and
   `build` takes the last element. The Phase 1 `LogSource` abstraction absorbed
   this without change.
2. **Naive UTC timestamps.** Heralding writes
   `datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')`. `fromisoformat` accepts
   that and reads it as LOCAL time -- measured 19,800 s (5.5 h) off on this box.
   Reusing `cowrie_parser.to_ts()` would have shifted every session and broken
   `peer_attribution.resolve_peer_ip()`, which matches the gateway log by connect
   time. Hence a dedicated `_utc_ts()`.
3. **No commands, only credentials.** `n_commands` is always 0;
   `credentials_as_payload` (default True) puts `"user:pass ; user:pass"` into
   `command_text` so Group C sees the real attack content.

## Parser verification -- all clean

```
scenario                    protocol  port logins  micro_state           contract
bare connect, no auth       http        80      0  RECON_IP_SCAN         OK
user enum (no passwords)    http        80      3  RECON_USER_ENUM       OK
credential stuffing         http        80      4  ACCESS_CRED_STUFF     OK
factory defaults            http        80      1  ACCESS_DEFAULT_CRED   OK
http brute force            http        80      3  ACCESS_BRUTE_HTTP     OK
ssh brute force             ssh         22      2  ACCESS_BRUTE_SSH      OK
ftp brute force             ftp         21      1  ACCESS_BRUTE_HTTP     OK
mysql (taxonomy gap)        mysql     3306      1  ACCESS_BRUTE_HTTP     OK + loud warning
```

Timezone confirmed: log says `2026-11-04 10:00:00` naive UTC, parser yields
`2026-11-04 10:00:00` UTC. Routing confirmed: http/80 and https/443 ->
`WEB_HONEYPOT`, ssh/22 -> `SSH_HONEYPOT`, override to mysql/3306 -> `DB_HONEYPOT`.

Tests: **36 new, 110 passed** across the suite (the one failure is still the
pre-existing `test_honeypot_round_robin`).

## MT3 verification -- 0 of 6, confidently wrong

Synthetic Heralding records through the real `extract_features()` + the trained
`best.pt`:

```
scenario            rule label            MT3 prediction          conf  phase
http brute force    ACCESS_BRUTE_HTTP     RECON_OS_DETECT        0.567      0
factory defaults    ACCESS_DEFAULT_CRED   EXEC_WGET_EXEC         0.985      2
cred stuffing       ACCESS_CRED_STUFF     EVASION_HIST_ERASE     0.491      6
user enum           RECON_USER_ENUM       PERSIST_BACKDOOR_ADD   0.742      5
bare connect        RECON_IP_SCAN         ACCESS_BRUTE_SSH       0.888      1
ftp brute force     ACCESS_BRUTE_HTTP     EXEC_SHELL_OPEN        0.834      2
```

**Phase 1b's zero-fill does not rescue it** -- still 0/5, one case worse:

```
scenario      rule label            Group D LIVE               Group D ZERO-FILLED
http brute    ACCESS_BRUTE_HTTP     EVASION_HIST_ERASE 0.915   DISC_NETSTAT_SCAN 1.000
defaults      ACCESS_DEFAULT_CRED   EXEC_WGET_EXEC 0.985       EXEC_WGET_EXEC 0.459
stuffing      ACCESS_CRED_STUFF     EVASION_HIST_ERASE 0.491   EXEC_WGET_EXEC 0.559
user enum     RECON_USER_ENUM       PERSIST_BACKDOOR_ADD 0.742 EXEC_WGET_EXEC 0.580
bare          RECON_IP_SCAN         ACCESS_BRUTE_SSH 0.888     DISC_NETSTAT_SCAN 1.000
```

**Diagnosis.** Heralding reports no bytes, no packet sizes, no TCP flags, no TLS
and no commands, so Groups B, C, E and F are largely *defaults* and Group D is
off-domain or constant. MT3 is extrapolating into feature space it never saw.
The earlier "98 of 128 features transfer cleanly" claim was about the *schema*
accommodating HTTP; it was never evidence that a Heralding-shaped vector is
in-distribution, and it is not.

## The safety finding

`MT3_AUTO_BLACKLIST` fires at phase >= 1 and confidence >= 0.5. A **bare connect
with no authentication attempt** is predicted `DISC_NETSTAT_SCAN` at confidence
**1.000** (phase 3). Deployed as-is, Heralding behind this pipeline would
auto-blacklist users for opening a TCP connection, and escalate the honeypot off
the same verdict. **This is the reason Phase 2 deployment is paused**, not the
accuracy numbers.

## Consequent decisions (DECISIONS.md, 2026-11-04)

1. Do not run MT3 on non-SSH sessions until retrained for them -- a per-protocol
   gate, not a confidence threshold, because the verdicts are confidently wrong.
2. Gate `MT3_AUTO_BLACKLIST` by protocol for the same reason.
3. Phase 2 deployment paused. Parser, labeller, factory and tests stand.

**Do not quote MT3 numbers for any non-SSH protocol.** The published macro-F1
figures are Cowrie- and netflow-derived.

## Secondary gap found

`feature_bridge._PORT_TO_HONEYPOT` has no entry for FTP (21), Telnet (23), POP3,
IMAP, SMTP or VNC, and `_PROTO_TO_HONEYPOT` has no `ftp`/`telnet`, so those
sessions fall through to the `SSH_HONEYPOT` default -- visible above, where
`ftp brute force` routed to `SSH_HONEYPOT`. Harmless while only HTTP is enabled;
needs entries before Heralding's other listeners are turned on.

---
---

---
---

# PART 8 — Heralding fine-tune: safety fixed, generalisation not (2026-11-04)

The retrain from PART 7. Three of four acceptance criteria pass, one fails, and
**the gate stayed closed** -- `heralding` was NOT added to
`CONFIG.MT3_TRUSTED_SOURCES`. The interesting part is *which* criterion failed.

## Setup

Separate model (`artifacts/mt3_multi/`), fine-tuned with replay. Reasoning in
DECISIONS.md 2026-11-04; `artifacts/mt3_full_d256/best.pt` was never written, so
every published number still describes the model it was measured on.

| | |
|---|---|
| Training rows | 8,400 synthetic Heralding (70% of 12,000) |
| Replay | 1,200 per class from the frozen `X_train`, stratified |
| Heralding share of the mix | ~13% |
| Hyperparameters | 4 epochs, lr 1e-4, batch 512, AdamW, grad-clip 1.0, seed 2026 |
| Device | cpu |
| Epoch selection | `min(heralding_val_F1, test_real_F1 / baseline)` -- a model that improves on Heralding by forgetting Cowrie cannot win |

Scaling handled explicitly: `data/final/` is already scaled, `extract_features()`
returns raw, so the frozen scaler was applied to the Heralding rows only
(ERRORS.md top two entries).

Held-out Heralding split: 1,800 rows. **40 of its 1,791 distinct rows are
byte-identical to a training row (2.2%)** -- small, and measured rather than
discovered later.

## Results

```
                              before          after       verdict
heralding test macro-F1            --         0.8924       PASS (floor 0.80)
test_real macro-F1             0.8272         0.8284       PASS (-0.0012, i.e. improved)
test_real macro-F1 (clean)     0.8187         0.8187       unchanged
scenario agreement                0.00           0.50      FAIL (floor 0.80)
no confident nonsense            FAIL           PASS
phase sanity                     FAIL           PASS
overall                          FAIL           FAIL
```

**The safety problem is genuinely fixed.** The case that forced the gate in the
first place:

```
before:  bare connect -> DISC_NETSTAT_SCAN  p=1.000  phase 3   (would blacklist)
after:   bare connect -> RECON_IP_SCAN      p=1.000  phase 0   (correct)
```

**Replay worked.** `test_real` went *up* by 0.0012 and the clean figure did not
move at all, so nothing was forgotten.

## The failure, and why it matters more than the pass

Held-out Heralding macro-F1 is **0.8924**, but the six hand-built scenarios score
**3 of 6**:

```
scenario            rule label            MT3                      conf  phase  ok
bare connect        RECON_IP_SCAN         RECON_IP_SCAN           1.000      0  =
user enum           RECON_USER_ENUM       RECON_USER_ENUM         1.000      0  =
cred stuffing       ACCESS_CRED_STUFF     RECON_USER_ENUM         0.998      0  x
factory defaults    ACCESS_DEFAULT_CRED   ACCESS_DEFAULT_CRED     0.993      1  =
http brute force    ACCESS_BRUTE_HTTP     ACCESS_CRED_STUFF       0.974      1  x
ftp brute force     ACCESS_BRUTE_HTTP     RECON_USER_ENUM         0.787      0  x
```

All three errors are confusions *within* the credential-pattern family, and all
are confident.

**Diagnosis: the model learned the generator's distribution, not the concept.**
The acceptance scenarios use 2-4 authentication attempts; the generator emits
3-40. So the scenarios sit at the thin edge of the training distribution. A 0.89
macro-F1 on held-out data that shares the generator's quirks is not evidence of
generalisation -- the hand-built cases are the honest test, and they say it has
not generalised.

Having the acceptance set come from somewhere other than the training
distribution is what made this visible. Had the gate been scored on the held-out
split alone it would have read PASS at 0.89.

## What NOT to do about it

Widening the generator to cover 1-3 attempt bursts would very likely move
agreement past 0.80. **That is tuning the training set to the acceptance set**,
and the resulting number would not be defensible. If it is ever done, the
acceptance set must be replaced at the same time, and the paper must say which
came first.

## Standing position

- The gate is CLOSED. `MT3_TRUSTED_SOURCES` is still `{"cowrie_real"}`.
- Heralding is labelled by `heralding_parser.label_session()` -- the heuristic.
- `mt3_multi/best.pt` exists and is usable for comparison work, but nothing in
  the live pipeline points at it. Pointing the pipeline there and opening the
  gate are a single decision; neither should happen alone.
- The real fix is **independently labelled captures from the VPS**. Synthetic
  rows labelled by our own rules can only ever teach the model to agree with
  those rules (DECISIONS.md).

## Reproduce

```
cd honeypot_dataset && venv/Scripts/python.exe -m src.generators.heralding_simulator
# then extract + split (see PART 8 notes), then:
python -m ml_analytics.mt3_pipeline.finetune_heralding --epochs 4 --replay-per-class 1200
python -m ml_analytics.mt3_pipeline.acceptance_heralding --ckpt ml_analytics/artifacts/mt3_multi/best.pt
```

`finetune_heralding` exits non-zero when the gate fails. **Note:** when run
through a shell pipeline the reported exit status is the last command's, not the
script's -- this caught me out once; read the "overall:" line, or check
`artifacts/mt3_multi/finetune_summary.json`.

**Not captured:** the per-epoch loss/validation trace. Python buffers stdout when
not attached to a terminal and only the tail flushed. Pass `-u` next time. The
final metrics come from `finetune_summary.json`, which is written on disk and is
the authoritative record.

---
---

## Colophon

2026-11-02 · ASUS TUF laptop, Windows 11 · repo back on `main` @ `ae1761b`

**Parts 1–3 were a read-only audit.** Nothing was edited, deleted, committed, pushed, pulled or
merged; no notebook was run; no container was started or stopped. The only write was
`git fetch --all --prune`, which added `origin/feature/mitigation-layer` and `origin/frontend` as
remote-tracking refs.

**Part 4 was two authorised test runs**, and they did change things. For the record:

- Created local branch `mitigation-test` from `origin/feature/mitigation-layer` and checked it out;
  afterwards switched back to `main`. The branch still exists locally.
- Installed `pytest` into `honeypot_dataset/venv` (it was absent). **Not reverted.**
- Started and stopped the pipeline watcher and the inspection gateway. Did not start or stop the
  Cowrie container — it was already running.
- Drove real SSH sessions into the honeypot — hostile ones with `demo/attack_client.py` and
  `demo/brute_force.py`, benign ones with a scratchpad Paramiko script — which appended to
  `cowrie.json`, `pipeline_results.jsonl`, the gateway state files and `active_config.json`.
- Cleared the gateway's `whitelist.json` / `blacklist.json` / `ip_records.json` before each run, so
  that `127.0.0.1` was not whitelisted and the mitigation layer could actually act.
- Backed all of those up before each run, then **restored them**, so the figures quoted in Parts 1
  and 2 still describe the files as they are now. The output of both runs is kept separately in the
  scratchpad (`test-evidence/` and `benign-evidence/`).
- Nothing was committed at any point, and `main` is still identical to `origin/main`.

Anything stated as "not confirmed" is marked as such in place.
