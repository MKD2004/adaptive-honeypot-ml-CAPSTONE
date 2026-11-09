# Changes after 30 September 2026

A plain-English record of every commit made after 30 September 2026, what each one changed, and what is
still not committed.

**Updated 2026-11-04.** Sections 1-8 below still describe the
`feature/mitigation-layer` branch exactly as written on 11-02, and are left
unchanged as the record of that work. What has changed since is that **the branch
is merged and 14 more commits have landed on `main`** — see section 11, which also
corrects the now-false parts of sections 9 and 10.

- **Cut-off (as written 11-02):** the newest commit on `main` was `ae1761b`, dated
  2026-09-29. **No longer true** — `main` is now at `4a87c34` (2026-11-04).
- **Where the work lives:** branch `feature/mitigation-layer`, pushed 2026-11-02,
  starting from `ae1761b`. **Merged into `main` on 2026-11-04** as `f7810ee`.
- **Size:** 9 commits, all by Anushka Singh (each has a Claude co-author line). 60 files changed, +8,509 lines, -41 lines.
  Roughly 3,200 lines of code, 4,800 lines of tests, 500 lines of docs.
- **Written:** 2026-11-02, from `git log` and `git diff`. **This file is committed as
  of 2026-11-04** — `STATUS.md` now points at it, and an uncommitted file that
  other docs reference is how the multi-machine sync drifts.

---

## 1. At a glance

| # | Commit | Date | What it did | Files | Lines |
|---|---|---|---|---|---|
| 1 | `49b97fd` | 11-01 | Fixed a wrong "is this the Docker proxy?" check in the gateway | 3 | +195 / -6 |
| 2 | `21db37a` | 11-01 | Gateway settings for auto-blacklist and data/log folders now come from the environment | 2 | +176 / -5 |
| 3 | `e20f966` | 11-01 | `CLAUDE.md`: added a "Communication Style" section (plain-English replies) | 1 | +9 |
| 4 | `64d3957` | 11-01 | New package `response_mitigation/`: policy, safety list, audit log, engine | 16 | +1,775 |
| 5 | `5cb7b68` | 11-01 | The pipeline now sends its blacklist decision through that engine | 2 | +259 / -33 |
| 6 | `edefce2` | 11-01 | The firewall layer: block list file, firewall executor, root script for the Linux host | 13 | +2,012 / -2 |
| 7 | `c18b632` | 11-02 | `deploy/sandbox/`: everything to run Cowrie on a public server safely | 18 | +1,994 |
| 8 | `570c5f4` | 11-02 | Finished mitigation: manual actions, command line, replay tool, chat alerts, lock | 16 | +2,037 / -30 |
| 9 | `4a6ed19` | 11-02 | Every pipeline result now says which honeypot saw it and where the data comes from | 2 | +87 |

Commits from other people after 30 September: only `3cec27c` by anushashrivastava on branch `origin/frontend`
(2026-11-01, "Add frontend implementation"). It adds a new `frontend/` folder (a React app) and touches none of the
files above. A simulated merge of the two branches is clean.

---

## 2. The story in plain words

1. **A bug fix.** The gateway thought any address starting with `172.1` or `172.2` was its own Docker proxy.
   That also matched real internet addresses such as `172.217.x.x`, so a real attacker could be ignored.
2. **Settings from the environment.** Three gateway settings that were fixed in code can now be set with
   environment variables, and a wrong value stops start-up with a clear message.
3. **A mitigation layer.** Before, one inline block in the pipeline blacklisted a source. Now a small engine decides
   (policy), checks it is safe (safety list), acts (executors), and writes every decision down (audit log).
4. **A real firewall option.** The engine can put an address on a block list. A small script on the Linux host,
   run by a timer, makes the real firewall (nftables) match that list. The pipeline never needs root.
5. **A kit to run it on the internet.** Docker settings for Cowrie, a rule that stops the honeypot calling out,
   a locked-down service for the pipeline, a runbook, and checks.
6. **Finishing touches.** People can block and unblock by command line, a replay tool shows what the policy would
   have done on recorded sessions, and a chat alert can go out for late-stage attackers.
7. **Provenance.** Each result records which honeypot saw the session and whether the data is real or injected.

---

## 3. Commit by commit

### 1. `49b97fd` Fix Docker-bridge check (gateway)
- **Why:** the old text check (`"172.1"`, `"172.2"`) matched public addresses. Effects: `peer_attribution` could relabel a
  real attacker as the proxy, and the pipeline skipped a real attacker when auto-blacklisting.
- **What:** both places now use Python's `ipaddress` and the real private range `172.16.0.0/12`.
  Loopback is still treated as a proxy in `looks_like_proxy()`. The pipeline's guard uses the new
  `is_docker_bridge_addr()` only, because loopback is a legitimate peer in single-laptop demos.
- **Files:** `traffic_gateway/peer_attribution.py`, `traffic_gateway/post_session_pipeline.py`,
  new `traffic_gateway/tests/test_peer_attribution.py`.
- **Tests:** 17 new.

### 2. `21db37a` Gateway settings from the environment
- **New variables:** `GATEWAY_MT3_AUTO_BLACKLIST`, `GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE` (0-8),
  `GATEWAY_MT3_AUTO_BLACKLIST_CONF` (0-1), `GATEWAY_DATA_DIR`, `GATEWAY_LOG_DIR`. Defaults are unchanged.
- **Behaviour:** a bad value raises `ValueError` at start-up naming the variable. `"0"` now means off for the new switch
  (the older pattern in the file treated `"0"` as on; that pattern is left alone for `CLASSIFIER_ROUTING` and `DEBUG`).
- **Files:** `traffic_gateway/config.py`, new `traffic_gateway/tests/test_config_env.py`.
- **Tests:** 10 new. They point the folders at a temp directory, so no tracked file is touched.

### 3. `e20f966` CLAUDE.md communication style
- Adds a short "Communication Style" section asking for plain, simple replies.
- Requested by Anushka. It is its own commit so it can be dropped from a pull request.
  `CLAUDE.md` is a shared file (see `TEAMMATES.md`), so Mahith may want to own changes to it.

### 4. `64d3957` The `response_mitigation` package
Turns one MT3 verdict into planned actions and applies them under a mode.

| File | Job |
|---|---|
| `policy.py` | Pure rules: verdict to planned actions |
| `safelist.py` | Strict IP parsing. Never acts on loopback, private, multicast, whitelisted or Docker-range addresses (for the firewall); the gateway divert still allows private addresses so the two-laptop demo works |
| `audit.py` | One JSON line per decision, flushed to disk. A firewall block is refused if the log cannot be written |
| `config.py` | `MITIGATION_*` settings. Bad values fail loudly |
| `engine.py` | Safety checks, hourly cap on new blocks, kill-switch file. Never raises into the pipeline |
| `executors/gateway.py` | Same blacklist call as before |
| `executors/alert.py` | At this point only a log line |

**Actions:** OBSERVE (write it down), DIVERT (gateway blacklist: send to the honeypot), DENY (firewall drop for a limited
time), ALERT (tell a person).

**Modes:** `off` (does nothing), `observe` (default: DIVERT as before, ALERT and DENY only logged as "would apply"),
`enforce` (DIVERT and ALERT applied; DENY applied only if `MITIGATION_FIREWALL=1`).

**Policy rows:**

| Rule | When | Action |
|---|---|---|
| `divert_attack` | phase 1 or higher, confidence 0.5 or higher | DIVERT |
| `late_stage_alert` | phase 7 or higher | ALERT |
| `repeat_offender` | phase 4 or higher and 3 or more sessions from the same address | DENY for 24 hours |

- **Tests:** 86, including one that runs the old inline condition next to the new engine over 2,916 combinations
  (10 address types, phases 0-8, 6 confidence values, whitelisted/blacklisted states, both modes) and checks they
  blacklist the same addresses with the same reason text.

### 5. `5cb7b68` The pipeline uses the engine
- **What:** the inline blacklist block in `post_session_pipeline.py` is replaced by one call to the engine.
- **Same as before (default settings):** the same addresses get blacklisted with the same reason text.
- **Different:**
  - text that is not a valid IP address is no longer blacklisted
  - the decision is written to the audit log
  - each result line gains a `mitigation` list (old fields kept, including `auto_blacklisted`)
  - a bad `MITIGATION_*` setting stops start-up before the slow model loads
  - an engine error is logged and never loses the session
- **Tests:** 13 new. These are the first automated tests of the auto-blacklist decision.
- **File touched:** `traffic_gateway/post_session_pipeline.py` (Mahith's module).

### 6. `edefce2` The firewall layer
```
pipeline (no root) -> blocklist.json -> apply_blocklist.py (root, systemd timer, every 15 s) -> nftables
```
- `blocklist.py`: atomic writes. A file it cannot read is never replaced.
- `executors/firewall.py`: the DENY executor. It checks the address again before writing.
- `host/apply_blocklist.py`: runs as root on the Linux host and treats the file as untrusted. It re-checks every address,
  refuses private, loopback, Docker, multicast and the host's own addresses and the never-block list, refuses a broken
  or oversized file (leaving the firewall as it is), and calls `nft` without a shell. It rebuilds the table if it is
  wiped. A kill-switch file removes every block.
- `host/honeypot-guard.service` and `.timer`: hardened systemd units.
- `engine.py`: registers the firewall executor. A failing executor check now becomes a FAILED decision instead of
  raising out of the engine (a gap found while building this).
- **Off by default:** needs `MITIGATION_MODE=enforce` and `MITIGATION_FIREWALL=1`.
- **Tests:** tried on Ubuntu 24.04 (WSL2, nftables 1.0.9) with 14 tests using real TCP connections between network
  namespaces: a blocked address is dropped, its neighbour still connects, a block expires by itself, the kill switch
  lifts it, a wiped or damaged table is rebuilt. The systemd unit and timer were also run for real.
  One bug was found only on Linux (a folder given as the block list crashed the root script) and fixed.

### 7. `c18b632` `deploy/sandbox/` (internet kit)
- **Cowrie in Docker:** its own bridge `br-honeypot`, published on IPv4 only, no extra capabilities.
  SSH forwarding off. Logins use `AuthRandom` (the repo's `userdb.txt` is demo-only: it denies common passwords).
- **Outbound block** (`egress.nft` + unit): the honeypot network cannot start any outbound connection or reach the host.
  Reason: Cowrie's fake `wget` and `curl` make real requests to wherever an attacker points them
  (advisory GHSA-83jg-m2pm-4jxj).
- **Pipeline service:** runs as an unprivileged user on a read-only filesystem. The folders it may write to were found
  by recording every file the pipeline writes.
- **Settings examples**, **`requirements-pipeline.txt`** (the packages the pipeline really imports),
  **`verify_sandbox.sh`** and **`check_cowrie_ips.py`** (checks, including whether Cowrie sees real attacker addresses
  instead of Docker's), and a **runbook** (`README.md`): part A tests privately on port 2222, part B moves your own SSH
  and goes public on 22.
- **`tools/record_pipeline_writes.py`** and tests keep the kit consistent with the code and fail if the pipeline starts
  writing outside the allowed folders.
- **Note:** the version in this commit is the first one. Fixes found later are not committed yet (section 8).

### 8. `570c5f4` Finishing the mitigation layer
- **Lock** (`blocklist.py`): a lock file shared by every process that writes the block list, so the pipeline and the
  command line can never overwrite each other. Four processes writing at once lose nothing (tested).
- **Manual actions** (`engine.py`): `firewall_block`, `firewall_unblock`, `set_kill_switch`, `record_manual`, `status`.
  A person can act in every mode, but with the same safety checks as an automatic block, and every action is audited.
- **Who did it:** every decision now records an `actor` (`policy`, `cli:<user>`, `dashboard`). `AuditLog.tail()` reads the
  newest decisions without reading the whole file.
- **Command line** (`cli.py`): see section 6.
- **Replay tool** (`replay.py`): runs recorded sessions through the policy on a simulated clock (so the hourly cap and
  block times behave as they would live) and, given labels, reports TP, FP, FN, TN and the false-positive rate.
  It works in a temporary folder and touches nothing real.
- **Chat alerts** (`executors/alert.py`, `config.py`): a webhook for Slack, Discord or any JSON webhook. Background
  thread, an hourly limit, never follows a redirect, never writes the URL to a log. Off unless
  `MITIGATION_ALERT_WEBHOOK` is set. A message holds the address, phase, label and confidence, and nothing the
  attacker typed.
- **Tests:** new files for the command line (28), manual actions (31), replay (23) and alerts (25), plus additions for the
  lock and the audit tail.

### 9. `4a6ed19` Provenance in pipeline results
- Each result line now has `sensor` (the honeypot's own name, read from the `sensor` field Cowrie writes on every event)
  and `source` (set by `PIPELINE_SOURCE`, for example `internet`, `injected`, `lab`, `demo`).
- `PIPELINE_SOURCE` allows 1-40 letters, digits, dots, dashes or underscores. Anything else stops start-up instead of
  being stored. Unset gives `unspecified`.
- Purpose: real internet sessions and injected or lab sessions are never pooled in one statistic.
- **Tests:** 6 new, including one over a Cowrie-format log.
- **File touched:** `traffic_gateway/post_session_pipeline.py` (Mahith's module). Existing fields are unchanged.

---

## 4. What behaves differently now

With default settings the pipeline blacklists the same addresses with the same reason text as before.
The differences:

- Text that is not a valid IP address is no longer blacklisted.
- Each decision goes to an audit log (`response_mitigation/logs/mitigation_audit.jsonl`, not tracked by git).
- Each result line has new fields: `mitigation`, `sensor`, `source`.
- A wrong `MITIGATION_*`, `GATEWAY_*` or `PIPELINE_SOURCE` value stops start-up with a clear message.
- Nothing is blocked at the firewall unless both `MITIGATION_MODE=enforce` and `MITIGATION_FIREWALL=1` are set.

## 5. New settings

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_MT3_AUTO_BLACKLIST` | on | Blacklist sources MT3 puts in an attack phase |
| `GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE` | 1 | Lowest phase that triggers it (0-8) |
| `GATEWAY_MT3_AUTO_BLACKLIST_CONF` | 0.5 | Lowest confidence (0-1) |
| `GATEWAY_DATA_DIR`, `GATEWAY_LOG_DIR` | folders inside `traffic_gateway/` | Where the gateway keeps data and logs |
| `MITIGATION_MODE` | `observe` | `off`, `observe` or `enforce` |
| `MITIGATION_FIREWALL` | `0` | May the pipeline put addresses on the firewall block list? |
| `MITIGATION_MAX_NEW_BLOCKS_PER_HOUR` | 50 | Cap on automatic blocks (0-1000) |
| `MITIGATION_NEVER_BLOCK` | empty | Addresses or networks that can never be firewall-blocked |
| `MITIGATION_KILL_FILE` | `response_mitigation/MITIGATION_DISABLED` | If this file exists, nothing automatic happens and blocks are removed |
| `MITIGATION_BLOCKLIST_PATH`, `MITIGATION_AUDIT_PATH` | inside `response_mitigation/` | Where the block list and audit log live |
| `MITIGATION_DENY_TTL_HOURS` | 24 | How long a block lasts (1-720) |
| `MITIGATION_ALERT_MIN_PHASE`, `MITIGATION_DENY_MIN_PHASE`, `MITIGATION_DENY_REPEAT_SESSIONS` | 7, 4, 3 | Policy thresholds |
| `MITIGATION_ALERT_WEBHOOK`, `MITIGATION_ALERT_MAX_PER_HOUR` | off, 30 | Chat alerts |
| `PIPELINE_SOURCE` | `unspecified` | Where the data comes from |
| `HONEYPOT_GUARD_NEVER_BLOCK` | empty | The same never-block list, for the root script on the host |

Command line (`python -m response_mitigation ...`): `status`, `blocks`, `block IP`, `unblock IP`, `off`, `on`,
`audit`, `replay RESULTS.jsonl`. It uses the same `MITIGATION_*` settings as the pipeline.

## 6. New files by folder

- **`response_mitigation/`** (35 files): `policy.py`, `safelist.py`, `audit.py`, `config.py`, `engine.py`, `models.py`,
  `blocklist.py`, `cli.py`, `__main__.py`, `replay.py`, `executors/` (gateway, firewall, alert), `host/` (the root
  script, two systemd units, README), `tests/` (14 test files).
- **`deploy/sandbox/`** (18 files): compose and Cowrie config, outbound block, two systemd units, three settings
  examples, package list, `verify_sandbox.sh`, `check_cowrie_ips.py`, runbook, `tools/record_pipeline_writes.py`, 4 test files.
- **`traffic_gateway/`** (6 files): `config.py`, `peer_attribution.py`, `post_session_pipeline.py` and three test files.
- **`CLAUDE.md`** (1 file).

## 7. How it was tested

- Test totals on the committed branch (everything after 30 September, nothing from the uncommitted work):
  **458 passed, 26 skipped, 1 failed**. The skipped tests need Linux and root. The one failure,
  `test_honeypot_round_robin`, was already failing before any of this work (the gateway config has only one honeypot target).
- **Real Linux tests** (Ubuntu 24.04 in WSL2, as root): real TCP connections between network namespaces for the firewall
  and the outbound block; the systemd units run for real; four processes writing the block list at once.
- **Same-as-today proof:** the 2,916-combination comparison described in commit 4.
- **Break-it-on-purpose checks:** the code was broken deliberately, one safety rule at a time, in a temporary copy,
  and a test had to fail. The unmodified code had to pass first. An earlier run of this check was invalid (its baseline
  failed, so everything looked "caught"); it was found and redone.
  - **Firewall layer (commit 6):** 21 breaks. 18 were caught at once. One was a real gap (an unreadable kill-switch file
    counted as "off"), closed with new tests. One (the block-list file mode) is only visible on Linux, where it is caught.
    One was harmless (a default that is never used).
  - **Later mitigation work (commit 8) and provenance (commit 9):** 25 breaks, all caught.
  - **Outbound block and pipeline write list (commit 7):** 5 and 3 breaks, all caught.
- **Mistakes caught along the way:** several of the new tests were wrong the first time, a Windows-only file-mode check hid a
  gap that Linux showed, and a crash on a folder passed as the block list showed up only on Linux. All fixed.

## 8. Known gaps (committed work)

- **Never run with the real MT3 model on real sessions.** The model files (`best.pt`, `semantic_pca.pkl`) are on the DGX,
  not on this laptop. Tests use a stand-in model.
- **Not run on a real cloud server.** The Docker behaviour was checked only in a throwaway Ubuntu in WSL2.
- **The policy thresholds are guesses** (3 sessions, phase 4 or higher). The replay tool is how to tune them, once there
  is real labelled data.
- **The hourly cap is kept in memory** and resets when the pipeline restarts.
- **The chat webhook** was only tested against a server on this machine, never a real Slack or Discord.
- **Blocked downloads look different in the data.** With the outbound block on, every attacker `wget` is logged as
  `cowrie.session.file_download.failed`. The project's Cowrie parser only counts `cowrie.session.file_download`, so
  `n_downloads` is 0 for those sessions. The parser belongs to the dataset owner and was not changed.
- **`CLAUDE.md`** is a shared file. Commit 3 changes it.

## 9. Not committed yet (as of 2026-11-02 — see section 11 for what has changed)

**The sandbox kit fixes.** The kit in commit 7 is the first version. Fixes found by running the real Cowrie image
(Docker 29.9.2, Cowrie 3.1.4) are not committed:
- the container's health check connected to Cowrie every 30 seconds, putting a fake session from `127.0.0.1` into the log
- the block-test step needed a Python environment that a collect-only server does not have, and its "end a block early"
  tip was wrong
- the Cowrie image was `latest`, now pinned to 3.1.4
- new: a collect-only mode (run Cowrie before the model files arrive), a check that Docker's network does not clash with
  the server's routes, a script to pack the model files on the DGX, `tools/mitigation.sh` (the command line as the right
  user), and Oracle Cloud and ARM notes

**The dashboard work (held back on purpose, by your rule).** A login on every change to the API, audit entries for
dashboard clicks, TRUST and UNBLOCK also lifting a firewall block, a new Mitigation page, and a token prompt on the
existing pages. This includes `traffic_gateway/api.py`, `response_mitigation/web.py`, `dashboard/` and their tests.
Until it is committed, `api.py` on `main` still has open cross-origin access and no login, as it did before.

> ⚠️ **2026-11-04: `api.py` has since been changed on `main` by someone else, so
> this held-back work will now conflict.** A separate, smaller authentication
> layer was written and committed as `26a7e10` — see section 11. It covers the
> token, the origins and a start-up guard, but **none** of the UI side listed
> above (no login prompt, no audit entry per dashboard click, no TRUST/UNBLOCK
> lifting a firewall block, no Mitigation page). Those are still wanted. Whoever
> lands this branch should expect to merge `traffic_gateway/api.py` and to decide
> whether `response_mitigation/web.py` replaces `traffic_gateway/api_auth.py` or
> sits on top of it. **Do not assume the auth question is settled because a token
> exists.**

## 10. Suggested order for a reviewer (written pre-merge; the branch is now merged)

1. Commit 1 and 2 (small, in `traffic_gateway/`).
2. Commit 4, then commit 5: the engine and how the pipeline uses it. The same-as-today test is the key one.
3. Commit 6: the firewall layer. Read `response_mitigation/host/apply_blocklist.py` first, since it runs as root.
4. Commit 8 and 9.
5. Commit 7 last: it is a new folder and does not change existing behaviour.

---

## 11. What happened after this file was written (2026-11-04)

Fourteen commits on `main`, `156c82d` → `4a87c34`, all pushed. The branch above is
merged. The measurements live in `HONEYPOT_AUDIT.md` PARTS 5-10 and the reasoning
in `DECISIONS.md`; `STATUS.md` has the session snapshot. This section is the
commit-by-commit view, matching the style of section 1.

| # | Commit | What it did | Files | Lines |
|---|---|---|---|---|
| 10 | `156c82d` | Gave a human 120 s to log in to the demo's real server, not 20 s | 2 | +11 / -1 |
| 11 | `7cf0030` | Phase 1: the pipeline can read more than one honeypot's log | 5 | +748 / -23 |
| 12 | `79186b0` | Committed `HONEYPOT_AUDIT.md` and added PART 5 | 1 | +971 |
| 13 | `aaa7b23` | Phase 1b: switch off the text features for non-SSH honeypots | 3 | +295 / -45 |
| 14 | `686d37e` | Phase 2: a Heralding parser; MT3 cannot classify it, so no deployment | 6 | +884 / -11 |
| 15 | `62bb614` | MT3's verdict may only act on honeypots it was trained on | 5 | +259 / -3 |
| 16 | `4984bfa` | A synthetic Heralding generator and the gate a retrained model must pass | 4 | +563 / -2 |
| 17 | `f362ab4` | Fine-tuned MT3 for Heralding: safety fixed, accuracy not. Gate stays shut | 5 | +508 / -8 |
| 18 | `f7810ee` | **Merged `feature/mitigation-layer`** (the 9 commits above) | 60 | +8,553 / -46 |
| 19 | `a843de0` | A strong verdict may now overrule a whitelist — for diversion, never a firewall drop | 11 | +371 / -32 |
| 20 | `26a7e10` | A password on the API's write endpoints, and it refuses to start up unprotected | 5 | +633 / -5 |
| 21 | `6608182` | The sandbox kit now records where its data came from; two of its own tests fixed | 7 | +268 / -6 |
| 22 | `838fcc4` | One bad session no longer averages away to nothing in the reputation score | 4 | +552 / -11 |
| 23 | `4a87c34` | `STATUS.md`: today's session, and the two-session gap before it | 1 | +129 |

### The story in plain words

1. **The demo had a 20-second login limit.** Fine for a script, impossible for a
   person clearing an SSH host-key prompt and then typing a password. The server
   hung up and the client said "Connection closed", which reads as a firewall
   fault and is not one. Hit live during the two-laptop demo.

2. **The pipeline could only ever read one honeypot.** Every parsed session was
   stamped "SSH, port 22" by hand, so the code that decides *which* honeypot a
   session belongs to could only ever answer "the SSH one". The obvious fix —
   read the real port from the log — would have been **wrong**: the training data
   carries port 2222 on 39,931 events but was always flattened to 22, so the model
   has only ever seen one value there. Reading the real port would shift that
   feature about a hundredfold at prediction time, with no error. They became
   settings whose defaults reproduce the old behaviour exactly.

3. **Writing down what a session looks like.** 22 required fields and 19 optional
   ones, with a test every parser must pass. With one parser there was nothing to
   disagree with; with two, a missing field does not crash — it quietly becomes a
   default and one of the 128 features goes wrong.

4. **The text features are now switched off for non-SSH honeypots.** The language
   model behind them was fitted on shell commands. Measured: it keeps 90.8% of
   shell-command variation but only 73.6% of HTTP's and 64.1% of SQL's. Filling
   those features with zeros instead lands *closer to the centre of the training
   data than 94.65% of real rows*, so the model reads it as unremarkable rather
   than alien. The cost, which belongs in the paper: non-SSH honeypots are
   classified on 98 of the 128 features.

5. **A second honeypot was prepared and then NOT deployed.** The Heralding parser
   works. The model does not: on six hand-built scenarios it agreed with the rules
   **zero times**, and was confident while wrong — a bare connection with no
   login attempt came back as a network scan at 100% confidence, which is enough
   to trigger an automatic block. Deploying it would have blocked people for
   opening a TCP connection. Cause: Heralding reports no byte counts, no packets,
   no TLS and no commands, so only **55 of 128** features have any value in them.

6. **So the model was put on a leash.** Its verdict is still calculated and
   written down for every honeypot, but may only *act* — block an address, change
   the honeypot — for Cowrie, which it was trained on. A fine-tune was then tried:
   it fixed the dangerous case and did not make the old results worse, but only
   agreed on 3 of the 6 scenarios, so the leash stayed on. The model had learned
   the generator's habits rather than the idea. Widening the generator to pass its
   own exam was deliberately not done.

7. **The mitigation branch was merged**, with one real conflict. The branch sent
   every verdict to the new engine unconditionally; merged as-is, that would have
   quietly undone the leash in point 6 and blocked people again. The engine now
   inherits it.

8. **All three findings from the 11-02 review are closed.** A password and a
   start-up refusal on the API (it also no longer listens to the network at all by
   default — nothing outside ever needed it); a strong verdict may now overrule a
   whitelist for diversion but never for a firewall drop, since that can lock you
   out of your own server; and one bad session in a clean history no longer
   averages away to nothing (0.166 → 0.542, while the all-clean and
   all-bad scores stayed identical to six decimal places).

9. **The internet kit was audited before use.** It had never set the field that
   records where data came from, so every real capture on a public server would
   have been filed as "unspecified" — impossible to separate afterwards from
   months of simulated traffic. Two of the kit's own tests were also broken, one
   because it depended on whatever state the last demo left behind.

### What this changes about section 8's known gaps

- "**Never run with the real MT3 model on real sessions**" — the model now runs on
  this laptop and has been used against the mitigation layer, synthetic Heralding
  sessions and the full `test_real` split. Still never run on *real attacker*
  sessions, because there are none.
- "**Not run on a real cloud server**" — still true. This is the only thing
  blocking Phase 0, and it needs a cloud account.
- "**The policy thresholds are guesses**" — still true, and two more were added
  with the whitelist override (phase 2, confidence 0.90). Also a guess, and
  deliberately stricter than the ordinary block thresholds.

### Still open

- The model is untrusted for every honeypot except Cowrie, so a second honeypot
  can collect but not drive anything.
- `ml_analytics/artifacts/mt3_multi/best.pt` exists but nothing points at it.
  Opening the gate and repointing the pipeline are one decision, not two.
- The React dashboard does not yet show the new fields (`sources`,
  `mt3_trusted`, `group_d_mode`).
- The reputation score tops out at 0.750 against a 0.70 blocking threshold — a
  pre-existing calibration question, deliberately not touched while fixing the
  averaging.
