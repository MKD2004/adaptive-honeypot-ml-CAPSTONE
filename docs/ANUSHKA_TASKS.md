# Anushka — what to work on next

**Short version:** Mahith is rebuilding the dataset for the next two to three
weeks. That work is all inside `honeypot_dataset/`, so it does not touch anything
of yours. Meanwhile the **mitigation and deployment half of the project has never
actually run on a real server**, and that is your half.

You and Anusha can finish that together. She owns the Oracle Cloud VM and has
already run Cowrie on it for 13 days. You wrote the kit that is supposed to run
there. Neither of you needs Mahith for any of it.

Plain English throughout. If something below is wrong, you know this code better
than the rest of us — say so and we will fix the plan, not the code.

---

## Task 1 — Commit your dashboard work. Please do this first.

**What it is:** back on 2 November you wrote, but deliberately did not commit, a
set of dashboard changes: a login on every API change, audit entries for dashboard
clicks, TRUST and UNBLOCK also lifting a firewall block, a new Mitigation page,
and a token prompt on the existing pages. It is recorded in
`CHANGES_AFTER_30_SEPT.md` section 9.

**Why it is urgent:** that work exists **only in your working folder**. It is not
in `main` and not in any branch — we checked. If that laptop dies, it is gone.

**And it now conflicts, which is our fault.** On 4 November we added
authentication to the API ourselves (`traffic_gateway/api_auth.py`, commit
`26a7e10`) because it was an open security hole and we did not know your version
was coming. So `traffic_gateway/api.py` has changed underneath you.

**The good news:** the two do not overlap much. Ours only does the plumbing — a
bearer token, narrowed CORS, and a refusal to start up unprotected. **None of the
UI side you built exists**, and all of it is still wanted:

- the login prompt on the pages
- an audit entry per dashboard click
- TRUST and UNBLOCK lifting a firewall block
- the Mitigation page

**What to do:** merge your version on top of ours. One real decision to make, and
it is yours: does `response_mitigation/web.py` **replace**
`traffic_gateway/api_auth.py`, or sit on top of it? Either is fine. Pick whichever
is less code and tell us which you chose.

**Please commit it even if it is unfinished.** A messy branch we can see beats
clean work we cannot.

---

## Task 2 — Put the mitigation layer on the real VM (with Anusha)

**The gap:** you wrote `deploy/sandbox/` — the whole internet-facing kit, 18
files, with a runbook, systemd units, nftables egress rules and the pipeline
service. Your own notes say it was **"not run on a real cloud server"**, only a
throwaway Ubuntu in WSL2.

Anusha's VM is now real, exposed to the internet, and has 13 days of proven
uptime. That is the box your kit was written for.

**How to split it with her:**

| | |
|---|---|
| **You** | know how the kit is supposed to behave, and what "working" looks like |
| **Anusha** | owns the VM, has SSH access, and has already done Docker + Oracle networking on it |

So: you drive, she runs the commands. Work through `deploy/sandbox/README.md`
together — it is your own runbook, so this is also a chance to find out which
steps do not survive contact with a real machine.

**The one thing we already fixed for you:** the kit never set `PIPELINE_SOURCE`.
Without it every capture is filed as `"unspecified"` and we cannot tell real
internet sessions apart from months of simulated ones afterwards. It is in
`pipeline.env.example` now and `verify_sandbox.sh` warns if it is missing. Make
sure it is actually set on the VM.

**A warning from Anusha's Cowrie deployment:** Oracle has **two** firewalls. The
VCN security list in the web console is not enough — Oracle's Ubuntu images also
ship a local `iptables` rule that drops nearly everything. She has hit this
already, so ask her.

---

## Task 3 — Actually watch a block work

**The gap:** nothing in the firewall layer has ever been seen to block real
traffic. Two reasons, both deliberate and both still in place:

- `MITIGATION_FIREWALL` defaults to `False` in `response_mitigation/config.py`
- the policy starts in observe-only, so it records decisions instead of acting

That was the right call for development. It also means **the executor and
`response_mitigation/host/apply_blocklist.py` have never run for real**, and that
script runs as root.

**What to do, on the VM, in this order:**

1. Leave it in observe mode. Let real attackers hit it for a day. Read the audit
   log and confirm the decisions it *would* have made look sensible.
2. Then set `MITIGATION_FIREWALL=1` and pick **one** address to block —
   ideally the noisiest bot, something like the IP that made thousands of
   connections.
3. Confirm the block actually works: traffic from that address stops arriving.
4. Confirm it lifts cleanly when the block expires or is removed.

**Keep `MITIGATION_MAX_NEW_BLOCKS_PER_HOUR` low — 2 or 3 — for the first run.**
It defaults to 50, and the first live run is not the moment to find out whether a
bug blocks the whole internet.

**And before you start: make sure your own SSH access is on a port that is not
managed by any of this, and that you can still log in on it.** If the firewall
layer locks you both out of the VM, we lose the Cowrie capture too.

---

## Task 4 — Two gaps you already wrote down yourself

Both are from your own notes in `CHANGES_AFTER_30_SEPT.md` section 8.

**a) The hourly block cap only lives in memory.** `engine.py` keeps the count of
recent blocks in the process, so if the pipeline restarts the cap resets to zero.
A crash loop could therefore issue far more blocks than the limit allows. It
needs to be stored on disk next to the other state.

**b) The chat webhook was never tested against a real service.** Only against a
local server on your machine. `MITIGATION_ALERT_WEBHOOK` needs one real Slack or
Discord test, so we find out now rather than during a demo that the message
format is wrong.

---

## Task 5 — Fix the one failing test (small, satisfying)

`traffic_gateway/tests/test_router.py::TestTrafficRouter::test_honeypot_round_robin`
is the only failing test in the whole project — 695 others pass.

It fails honestly: the test asserts the router cycles across several honeypots,
while `CONFIG.HONEYPOT_TARGETS` currently holds exactly one entry
(`web://127.0.0.1:8081`). The four-entry list above it is commented out.

**This is about to become real.** Anusha is deploying Heralding as a second
sensor, so multi-target routing stops being hypothetical. Good moment to decide
whether the test or the config is wrong, and fix whichever it is.

---

## Please do not touch these while Mahith is in the dataset

Not because the work is secret — because two people editing the same file in
different directions wastes an afternoon.

```
honeypot_dataset/**                     generators, extractors, validators, schema, notebooks
honeypot_dataset/data/final/**          frozen until the rebuild is validated
honeypot_dataset/src/parsers/*.py       session aggregation is being changed
```

**One file to be careful with: `traffic_gateway/feature_bridge.py`.** It is the
seam between the live pipeline and the dataset code, and it has now been changed
twice from the live side and twice from the dataset side. If you need to change
it, say so first and we will coordinate. It merged cleanly so far, which is luck
more than design.

Everything else is yours: `traffic_gateway/`, `response_mitigation/`, `deploy/`,
`dashboard/`.

---

## Suggested order

1. **Task 1** — commit the dashboard work. Today if you can; it is the only item
   where waiting costs something.
2. **Task 2** — the VM deployment, with Anusha. The big one.
3. **Task 3** — watch a real block work. Needs task 2 done first.
4. **Tasks 4 and 5** — whenever. Good filler while waiting on Anusha.

## Why this matters

Right now the honest description of this project is: a real honeypot collecting
real attacks, an ML model that does not yet fit that data, and **a mitigation
layer that has never defended anything.** You built the third part. Getting it to
genuinely block a real attacker on a real server turns it from code into a
result — and it is the part a reviewer will ask about first, because it is the
only part that *does* something.

Nothing here needs Mahith or the dataset. Two to three weeks of your and Anusha's
time, in parallel, and the deployment half is finished.
