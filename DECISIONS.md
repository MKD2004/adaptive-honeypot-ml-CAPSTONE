# DECISIONS

Reference only — not committed. Log *why* a non-obvious choice was made, so we
don't re-debate or accidentally re-break it later. Newest first.

---

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
