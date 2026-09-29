# ROADMAP — from capstone to research paper

Last updated: 2026-09-28 (added: literature/novelty survey, dataset-novelty
finding, deployment topology)

This is the plan for turning the working system into a publishable paper. It is
deliberately honest about what we have, what is weak, and what to do next. Read
`DECISIONS.md` and `STATUS.md` alongside it — this file says *where we are going*,
those say *how we got here*.

---

## 1. Where we actually are (no spin)

**What works and is genuine:**
- A real medium-interaction honeypot (**Cowrie 3.0.13**, industry-standard) behind
  a traffic gateway that classifies each source IP and routes benign → real
  server, hostile → honeypot.
- A closed adaptive loop: honeypot session → 128-feature extraction → **MT3**
  (3.76M params) classifies it into 45 MITRE-mapped micro-states → the honeypot's
  fake filesystem is reconfigured (per-session, no restart) → source auto-blocked.
- A model comparison on frozen, identical splits.

**What is scaffolding, not research:**
- `demo/ssh_honeypot.py`, `demo/real_server.py` — hardcoded-response props for the
  offline demo. Not honeypots. Never describe them as such in the paper.

**The honest weaknesses (a reviewer finds these on page 1):**
1. **No real honeypot data.** Genuinely real data is CIC-IDS2017 + UNSW-NB15 only,
   anchoring **13 of 45** classes (all network-flow). The 15k "Cowrie" sessions in
   the training set are synthetic. We have never deployed a honeypot to the open
   internet. (See `DECISIONS.md`, 2026-08-28.)
2. **The models tie.** On `test_real`, MT3 (0.8187 clean macro-F1) and the
   CNN-LSTM baseline (0.7976) are statistically indistinguishable (McNemar
   p = 0.617). MT3's transformer fusion does not beat concatenation+MLP at 20x
   the parameters. This is a real *negative* result, not a win.
3. **MT3 has no CRF** despite the name, and `KILL_CHAIN_DAG` never enters
   training. Both are claimed by the architecture's framing but not implemented.
4. **The adaptive loop is demonstrated, not evaluated.** We show it reconfigures;
   we have never measured whether adapting collects *more or better* intelligence
   than a static honeypot.

---

## 2. The contribution (pick one, commit to it)

We have three candidate contributions and can only defend one as the headline.

| Candidate | Honest status | Role in the paper |
|---|---|---|
| The HoneySynth dataset | 13/45 real-anchored, rest synthetic | Supporting, not headline |
| The MT3 model | Ties the baseline | Report as an honest ablation |
| **The adaptive closed loop** | Novel, working, **unmeasured** | **The headline** |

**Decision: the paper is about the adaptive closed loop** — a honeypot that
reconfigures itself from real-time ML classification of the attacker's kill-chain
phase, and whether that adaptation improves intelligence yield.

This framing survives the weaknesses above: it does **not** depend on MT3 beating
a baseline (MT3 is just the classifier inside the loop), and it turns "the models
tie" into an honest ablation rather than a headline we have to defend.

**One-line contribution statement (draft):**
> We present an adaptive SSH honeypot that classifies an attacker's kill-chain
> phase in real time and escalates its own interaction level in response, and we
> measure — on live internet traffic — whether phase-driven adaptation collects
> more attacker intelligence than a static honeypot of equal fidelity.

---

## 3. Related work & novelty positioning (literature survey, 2026-09-28)

A web survey of prior art. The blunt finding: **every individual component of our
system already exists in the literature.** Novelty, if any, is in the specific
combination and in two narrow elements. Read this before writing any "we are the
first to…" sentence.

### 3.1 Component-by-component prior art

| Component | Prior art found | Novel alone? |
|---|---|---|
| Adaptive honeypot | Well established — RL/PPO, semi-Markov decision processes, Stackelberg game theory, dynamic container orchestration | No |
| CVE / threat-intel + honeypot | Established, but mostly the *honeypot → threat-intel* direction (honeypots detect which CVEs are exploited); closed-loop firewall-rule frameworks and anti-fingerprint banners exist | Mostly no |
| Kill-chain / phase labelling | Q-Cowrie (8 MITRE-mapped states), Kill-Chain State Machines (2021) | No |
| Deep classifier (MT3) | Standard; and **ours ties the CNN-LSTM baseline** (p=0.617), so it is a component, not a contribution | No |
| CVSS + EPSS + KEV fusion | Heavily done — but on the *vulnerability-ranking* side ("which CVE to patch"), not fused into attacker session records | No (in vuln world) |
| **EPSS *drift* fused into kill-chain session sequences** | **Found nothing** | **Yes — the one open seam** |

### 3.2 Nearest-neighbour papers — MUST read before writing

These sit closest to our whole thesis and could partially pre-empt it. Read in
full and write an explicit differentiation against each; do not claim system
novelty until this is done.

- **Q-Cowrie** — adaptive Cowrie, attacker transition probabilities across 8
  MITRE-mapped lifecycle states. Nearest neighbour to the *system*.
  https://link.springer.com/article/10.1007/s10207-026-01221-5
- **An Adaptive Multi-Layered Honeynet Architecture for Threat Behavior Analysis
  via Deep Learning** (arXiv 2512.07827, 2025). Deep-learning + adaptive +
  honeynet — appeared in nearly every search.
  https://arxiv.org/html/2512.07827v1
- **A Practical Honeypot-Based Threat Intelligence Framework for Cyber Defence in
  the Cloud** (arXiv 2512.05321, 2025). Closed-loop Cowrie + MITRE + automated
  response. https://arxiv.org/pdf/2512.05321
- **Multi-Stage Attack Detection via Kill Chain State Machines** (arXiv 2103.14628).
  Prior art for kill-chain state sequences. https://arxiv.org/pdf/2103.14628

### 3.3 What we can still defend

1. **Adaptation driven by a supervised 45-class kill-chain *phase classifier*, not
   RL.** The adaptive-honeypot literature is RL-dominated; a classifier-driven
   mechanism is genuinely different in kind.
2. **EPSS drift** — temporal exploit-probability change fused into session
   features. The one element found nowhere.
3. **The measured result, not the mechanism.** "Does phase-driven adaptation
   collect more intelligence than a static honeypot, on live traffic?" is an
   *evaluation* contribution. Mechanisms get scooped; a rigorous measured result
   on a real deployment does not, as easily. **This is the safest thing to lead
   with** (see Section 5, the A/B study).

### 3.4 Dataset novelty — narrower than first hoped

Original hope: "no dataset has attack sequences + kill-chain validation + EPSS
drift." Survey verdict:
- Kill-chain-labelled honeypot datasets **exist** (Q-Cowrie; KCSM; and 2025
  releases — a 4-month SSH honeypot set of 145k events, MURHCAD multi-regional
  T-Pot, BETH). So "a kill-chain honeypot dataset" is **not** novel.
- CVSS/EPSS/KEV fusion **exists** but only in the vulnerability-ranking world
  (`jgamblin/KEV_EPSS`, Kaggle CVE+KEV+EPSS sets), **not** fused into honeypot
  sessions.
- The **intersection** — honeypot attack sessions, labelled as kill-chain
  micro-state *sequences*, enriched with per-session EPSS/KEV/CVSS **and EPSS
  drift** — was **not found**. That narrow seam is the only defensible dataset
  novelty, and **EPSS drift is its strongest element**.

Two honesty flags for the dataset angle:
- **Circularity:** EPSS itself consumes honeypot signals as a model input, so
  using EPSS as a feature on honeypot sessions must be justified explicitly.
- **Coverage ceiling:** a single low-interaction SSH honeypot yields mostly
  shallow classes (Recon / Initial Access / basic Execution). Real data will
  populate perhaps 5–15 of the 45 classes with volume; the deep kill-chain
  classes stay empty. A "full 45-class real dataset" claim will not hold on one
  honeypot — it needs multiple honeypot types.

**Decision:** ship the dataset as a **companion artifact** to the system paper
(with its own data card), lead its novelty claim with **EPSS drift**, and do not
bet a standalone dataset paper on it — each ingredient already has prior art.

Survey sources: Q-Cowrie (above); arXiv 2512.07827; arXiv 2512.05321; arXiv
2103.14628; jgamblin/KEV_EPSS (https://github.com/jgamblin/KEV_EPSS); Kaggle
CVE/KEV/EPSS datasets
(https://www.kaggle.com/datasets/francescomanzoni/vulnerability-management-datasets);
4-month SSH honeypot dataset (https://zenodo.org/records/19815504); MURHCAD
(https://arxiv.org/pdf/2601.05813); EPSS overview, notes honeypots as an input
(https://www.crowdstrike.com/en-us/cybersecurity-101/exposure-management/exploit-prediction-scoring-system-epss/);
adaptive-honeypot RL/game-theory
(https://arxiv.org/pdf/1906.12182, https://www.mdpi.com/2673-3951/7/1/23,
https://www.sciencedirect.com/science/article/abs/pii/S1389128625009478).

---

## 4. Deployment topology — how to test in real life

We already run a **genuine** honeypot (Cowrie 3.0.13 in Docker). What is missing
is **real attackers**, which means internet exposure. Two distinct topologies,
for two distinct purposes:

| Deployment | Gateway in front? | Purpose |
|---|---|---|
| **Internet VPS** (real data, the paper) | **No** — Cowrie direct on port 22 | collect real attacks; run MT3 + adaptive loop against real adversaries |
| **LAN demo** (already recorded) | **Yes** | show benign-vs-malicious routing — needs both traffic types |

### 4.1 Why the gateway is dropped for data collection

On a public honeypot VPS, ~100% of traffic is hostile and there is no real
service to protect, so the gateway's whole job (route benign → real, malicious →
honeypot) has nothing to do. Dropping it is a **net simplification**:
- real attacker IPs land **directly** in Cowrie's log — no proxy, so
  `peer_attribution.py` becomes unnecessary and `src_ip` is genuine;
- rate limiting, the pre-filter, and routing are all irrelevant when everyone is
  an attacker;
- the pipeline (features → MT3 → adaptive config → dashboard) runs **unchanged**,
  pointed at the real Cowrie log.

The gateway is **not** wasted work — it is the right layer for the "protect a real
service beside the honeypot" topology, which is what the LAN demo exercises.

### 4.2 VPS choice and time

- **Oracle Cloud Always-Free ARM (Ampere A1, up to 4 cores / 24 GB)** — $0
  forever, enough to run Cowrie + pipeline + MT3 on CPU. Friction: credit-card
  verification, frequent ARM "out of capacity" in busy regions, and a
  **double firewall** (OS firewall **and** the OCI security list — open ports in
  both or it silently fails).
- **Fallback:** DigitalOcean / Vultr / Linode droplet ~$5/mo — provisions in
  ~60s, none of Oracle's friction.
- **Hands-on setup:** ~1–1.5 h if provisioning is smooth (account + verify 15–30
  min; instance + SSH 10 min; move admin SSH off port 22, install Docker, open
  both firewall layers 30–45 min; deploy Cowrie 15 min). The only unpredictable
  part is Oracle ARM capacity.

### 4.3 Safety rules (non-negotiable)

- **Move your own admin SSH off port 22 first**, and confirm login on the new
  port, *before* exposing 22. Otherwise you lock yourself out or expose admin.
- **Isolate the box** — no real secrets, no other services, nothing you value.
- **Filter outbound traffic** — Cowrie captures malware fetch attempts; contain
  egress so nothing can be pulled/run or used to attack others from the VPS.
- **Check the provider ToS** (most allow honeypots; a few do not).
- **Ethics/data-handling note** — you collect attacker IPs and credentials;
  standard, but write the paragraph now (reviewers expect it).

### 4.4 Gotcha to verify on day one

With Docker port publishing (`host:22 → container:2222`), confirm Cowrie logs the
**real attacker IP**, not a Docker bridge address (`172.x`). Modern Docker's
iptables NAT usually preserves the source IP; if `src_ip` shows `172.x`, switch
the container to `network_mode: host`. Real IPs vs bridge addresses is the
difference between usable and useless data.

---

## 5. The experiment that makes it a paper

The headline claim needs a measured result. Design:

**Setup.** Two internet-facing honeypots on identical cheap VPS instances, same
banner, same credentials, same base filesystem:
- **Control:** static Cowrie (fixed interaction level).
- **Treatment:** our adaptive Cowrie (MT3 drives per-session escalation).
Split incoming traffic so each attacker IP is deterministically assigned to one
arm (hash of IP), so the two arms see comparable attacker populations.

**Metrics (intelligence yield):**
- commands captured per session,
- session depth / duration before the attacker leaves,
- unique tools, malware URLs, and credentials observed,
- kill-chain depth reached (how far down the DAG attackers progress),
- fraction of sessions that advance past Initial Access.

**Hypothesis:** the adaptive arm collects significantly more of the above,
because escalating fidelity keeps attackers engaged longer and lures deeper
behaviour. Report effect sizes and significance; a null result here is still
publishable and honest.

**Secondary study (already have the data):** MT3 vs CNN-LSTM vs linear-probe as an
ablation of the classifier inside the loop — with the tie reported plainly and the
29.74% train/test leakage disclosed (quote the clean column).

---

## 6. Milestones

### M1 — Collect real data (start immediately, runs in background)
- [ ] Deploy Cowrie to a public VPS (~$5/mo). Data accrues from day one.
- [ ] Harden: isolated host, no real secrets, outbound egress filtered, legal/ToS
      of the provider checked, an IRB/ethics note drafted (attacker data handling).
- [ ] After ~2–4 weeks: a genuinely real capture set of thousands of sessions.
- [ ] Re-run notebook 01 → 02 on the real captures; report real-anchored class
      coverage honestly (expect the honeypot-command classes to finally have a
      real anchor).

### M2 — Fix the integrity gaps (before any writing)
- [ ] MT3 CRF: implement a real CRF/transition layer over `KILL_CHAIN_DAG`, **or**
      rename and drop the claim. Measure whether it helps.
- [ ] Get `KILL_CHAIN_DAG` into training (structured loss or CRF), or state
      explicitly that it is used only for validity checking, not learning.
- [ ] Rebuild the split deduplicated-by-value (kills the 29.74% leakage) and
      re-report all numbers on the clean split.

### M3 — Run the A/B intelligence-yield study (M1 must be live first)
- [ ] Stand up control + treatment honeypots with the metric logging above.
- [ ] Run ≥4 weeks; freeze the dataset; analyse effect sizes + significance.
- [ ] This produces the paper's headline figure.

### M4 — Broaden (optional, strengthens scope)
- [ ] Add a second protocol honeypot (web/HTTP via a real honeypot, not the demo
      prop) so the loop is shown to generalise beyond SSH.
- [ ] Consider T-Pot as the deployment substrate if going multi-honeypot.

### M5 — Write
- [ ] Contribution = the adaptive loop (Section 2). MT3 comparison = ablation.
- [ ] Threats to validity: synthetic-data provenance, single-protocol scope,
      attacker-population confounds, honeypot detectability.
- [ ] Release code + the real dataset (anonymised) — reproducibility is a
      reviewing plus and we already have the pipeline.

---

## 7. What NOT to claim

- Do **not** claim MT3 outperforms the baseline. It ties. Say so.
- Do **not** call the demo props (`ssh_honeypot.py`, `real_server.py`) honeypots.
- Do **not** describe the dataset as majority-real. 13/45 classes, network-flow
  only, are real; the rest is synthetic.
- Do **not** claim kill-chain/CRF modelling until M2 makes it true.
- Do **not** claim system or dataset novelty until the Section 3.2 nearest-
  neighbour papers have been read and differentiated in writing.
- Do **not** describe `demo/ssh_honeypot.py` or `demo/real_server.py` as
  honeypots — they are offline demo props (see Section 1).

Honesty here is not a weakness — a paper whose limitations section pre-empts the
obvious attacks reviews far better than one that oversells and gets caught.

---

## 8. Immediate next actions (ordered)

1. **Deploy Cowrie to a VPS this week** (Section 4). Data only accrues on
   wall-clock time — start the clock; everything else runs in parallel.
2. **Read the three nearest-neighbour papers** (Section 3.2) and write one
   paragraph each on how we differ. This gates every novelty claim.
3. **Verify real attacker IPs** reach Cowrie's log (Section 4.4).
4. Then proceed with M2 (integrity fixes) and M3 (the A/B study).
