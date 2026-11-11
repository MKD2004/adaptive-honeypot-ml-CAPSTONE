# docs/

Everything written about this project. Moved here from the repo root on
2026-11-04 — there were 22 markdown files at the top level, which made the root
unreadable.

Only two stay at the root, and both for a reason: `README.md` (what people expect
to find there) and `CLAUDE.md` (loaded automatically from the repo root, so it
cannot move).

**Python docstrings cite these by bare filename** — "see `DECISIONS.md`",
"`HONEYPOT_AUDIT.md` PART 7". Those citations were left as-is rather than
rewritten into paths: ~30 of them across 10 files is a large, risky diff for no
functional gain, and the filenames are unique, so a search still finds them. If
you add a doc, keep its name unique for the same reason.

## Read these first

| File | What it is |
|---|---|
| `STATUS.md` | Where the project is right now. Start here. Machine-tagged, updated at the end of a session. |
| `ROADMAP.md` | Capstone → paper: the contribution, the novelty positioning, the A/B experiment, milestones M1-M5. Read before any paper decision. |
| `DECISIONS.md` | **Why** a non-obvious choice was made. Check before redoing something or "fixing" something deliberate. Newest first. |
| `ERRORS.md` | Bugs already hit and fixed. Check before re-debugging the same crash. |

## Reference

| File | What it is |
|---|---|
| `SCHEMA.md` | The 45 micro-states and 128 features, for writing prompts fast. `configs/schema.py` is the source of truth if they disagree. |
| `MULTI_HONEYPOT.md` | The plan for growing from one honeypot to four. Expansion of ROADMAP M4. Read before adding a honeypot or claiming the system has more than one. |
| `TEAMMATES.md` | Hard rules for collaborators and any AI assistant. |
| `MT3_PROMPT.md` | The binding spec for the MT3 pipeline. **Cited from code** — `mt3_pipeline/data.py`, `evaluate.py` and `losses.py` all reference it as the requirement they implement. |

## Findings and audits

Written as the work happened. These carry the measurements; the code comments
point at them rather than repeating the numbers.

| File | What it is |
|---|---|
| `HONEYPOT_AUDIT.md` | The big one, 11 parts. PARTS 1-4 are the 2026-11-02 reality check (how many honeypots exist, whether any captured traffic is real, the mitigation-layer review). PARTS 5-11 are the 2026-11-04 work, each with its measurements. |
| `02-11-2026 FINDINGS.md` | Six questions asked while reviewing the live pipeline. Finding #1 — MT3 has no benign class — is still the most important open item. |
| `REAL_DATA_2026-11-09.md` | **The first real honeypot data.** 45,648 internet-captured Cowrie sessions from an Oracle Cloud VM. Also the measurement that matters: real data sits 226x outside MT3's training distribution, because 7 of 24 temporal features were dead in the frozen training set. |
| `WORKLOG_2026-11-03_04.md` | The 3-4 November sessions in one self-contained file, including a section on mistakes made and corrected. |
| `CHANGES_AFTER_30_SEPT.md` | Every commit after 30 September, in plain English. Section 9 carries a collision warning about a held-back dashboard branch. |
| `FIDELITY_ANALYSIS.md` | How closely the synthetic data matches the real data. |

## Machine-specific (gitignored — each machine has its own)

Present on this laptop only; do not expect them on another machine, and do not
follow another machine's copy.

| File | What it is |
|---|---|
| `ASUS.md` | This machine's role and work log. |
| `HARDWARE.md` | GPU/VRAM/venv specs and what they imply for batch sizes. |
| `SETUP.md` | Environment setup for this OS and GPU. |
| `DEMORUN.md` | The screen-recording script for the live demo. Five acts, with the traps that break each one. |
| `FINDINGS_2026-08-30.md`, `TEAMMATE_*.md` | Older working notes. |

`DGX.md` is committed rather than ignored, because every machine needs to know
what the DGX was for — even though it is no longer in use.

## Diagrams

`architecture.png`, `ER diagram.png`, `Master class diagram.png`,
`Use case.png` — wanted for the paper.
