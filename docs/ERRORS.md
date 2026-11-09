# ERRORS

Shared reference — **committed**, identical on every machine (ASUS / Dell / DGX).
Change it once and push; do not fork it locally. Every entry: what broke, root
cause, fix, how to tell if it's happening again. Check this before re-debugging
something from scratch. Newest first.

---

## `data/final/` splits are ALREADY scaled — re-applying `feature_scaler.pkl` silently corrupts the input

**Symptom:** No crash. A model trained on `data/final/` that calls
`scaler.transform(X_train)` first trains on garbage: column means jump from
~0.002 to ~4.8, per-column stds collapse to ~0.02 for some features and blow up
past 10 for others, and values reach ±2000. Accuracy looks plausible-but-poor
rather than obviously broken, so it reads as "the model needs tuning."

**Root cause:** `ml_analytics/README.md` and `DGX.md` both say *"load this exact
scaler; do NOT re-fit"*, which is easy to read as "transform your inputs with
it." But notebook 05 already did that. Cell 11:

```python
scaler = StandardScaler(); scaler.fit(X_train)
X_train_s = scaler.transform(X_train).astype(np.float32)   # ... and val/test
joblib.dump(scaler, DATA_FINAL / "feature_scaler.pkl")
```

and cell 13 saves the `*_s` arrays as `X_train.npy` / `X_val.npy` /
`X_test_real.npy` / `X_test_synth.npy`. So the shipped `.npy` files are the
**already-transformed** data and the shipped scaler is the object that produced
them — kept for provenance and for putting *raw* live sessions on the same
footing at inference time, not for re-use on the splits.

The real danger is asymmetry: if the CNN-LSTM baseline re-transforms and MT3
doesn't (or vice versa), the two models are no longer trained on the same
inputs, and the whole baseline-vs-MT3 comparison — the point of the frozen
dataset — is void.

**Fix (2026-08-28):** `ml_analytics/mt3_pipeline/data.py` loads the scaler,
records it in every checkpoint's provenance block
(`scaler_refit: false`, `scaler_reapplied_to_splits: false`), and never applies
it to the frozen splits. `data.check_scaling()` runs on every load and raises
rather than guessing if the arrays ever stop looking pre-scaled.
`data.transform_raw()` is the separate, explicit path for raw features.
Smoke-test step 3 additionally asserts that re-applying the scaler *would* shift
the means by >5x, so a regression is loud instead of silent.

**How to tell if it's happening again:** compare the two numbers directly —

```python
X = np.load("honeypot_dataset/data/final/X_train.npy", mmap_mode="r")[:20000]
sc = joblib.load("honeypot_dataset/data/final/feature_scaler.pkl")
np.abs(X.mean(0)).mean()      # ~0.002  -> data is already scaled
np.abs(sc.mean_).mean()       # ~137    -> scaler was fit on RAW features
```

If the first number is near 0 and the second is large, the data is scaled and
`transform()` must not be called. Any model whose training-time feature stats
have |mean| ≈ 4.8 or |max| in the thousands has double-scaled.

---

## `feature_scaler.pkl` is a joblib dump — `pickle.load()` fails on it

**Symptom:**

```
_pickle.UnpicklingError: invalid load key, '\x0a'.
```

when loading `honeypot_dataset/data/final/feature_scaler.pkl` with
`pickle.load(open(path, "rb"))`. Confusing because the file *starts* with a
valid pickle header (`\x80\x04\x95...`, `sklearn.preprocessing._data
StandardScaler`), so it looks like a truncated or line-ending-corrupted pickle.
It is neither: the file is intact and contains no CRLF.

**Root cause:** notebook 05 saves it with `joblib.dump`. joblib writes a pickle
stream in which each numpy array is replaced by an `NDArrayWrapper` sub-pickle
followed by the array's raw bytes. Stock `pickle` parses the outer frame fine and
then walks straight into the raw array payload, hitting `0x0a` where it expects
an opcode. `pickletools.dis` confirms it: the stream ends cleanly at
`BUILD` (position 404) with the joblib-specific keys `allow_mmap` and
`numpy_array_alignment_bytes`, and blows up at position 405.

**Fix:** use `joblib.load(path)`, or `ml_analytics.mt3_pipeline.data.load_scaler()`
which wraps it and re-raises with this explanation attached.

**How to tell if it's happening again:** `invalid load key` on a file that
*starts* with a valid pickle protocol header (`\x80\x04` / `\x80\x05`) means
joblib, not corruption — the stream is fine, `pickle` just can't read joblib's
array framing. `pickletools.dis(open(p,"rb").read())` naming `allow_mmap` right
before it dies confirms it. This is not specific to the scaler: **every `.pkl`
this pipeline writes is joblib**, verified —
`data/processed/semantic_pca.pkl` (a `sklearn.decomposition.PCA`) fails the same
way with `invalid load key, '\x0c'` and loads fine under `joblib.load`.

---

## TabSyn VAE mode collapse — trained on 10/45 classes instead of 45

**Symptom:** After a full VAE training run (on the old laptop), notebook 03's
output showed `Micro-states: 10 unique classes` where 45 were expected. The VAE
(and any diffusion model trained downstream of it) would only ever have learned
to generate sessions for those 10 classes — a form of mode collapse driven by
the *input data*, not the model.

**Root cause (three compounding issues, all in notebook 01):**
1. `Found 0 Cowrie log files` — `data/raw/cowrie_logs/` was empty at run time, so
   0 of the ~15,000 Cowrie sessions (which cover 14 distinct micro-states,
   including several — `PRIVESC_SUDO_ABUSE`, `DISC_SUID_HUNT`, `EVASION_*`,
   `PERSIST_*` — not reachable from CIC/UNSW at all) contributed anything.
2. CIC-IDS2017's "Web Attack" labels are stored with a corrupted separator
   character (`U+FFFD`) that didn't match `CIC_LABEL_MAP`'s keys, so those rows
   silently mapped to `NaN` and got dropped — losing `ACCESS_BRUTE_HTTP` entirely
   (no other source provides it).
3. UNSW-NB15's real `attack_cat` value is `'Backdoor'` (singular) but
   `UNSW_LABEL_MAP` had the key as `'Backdoors'` (plural) — same silent-drop
   effect, losing `PERSIST_BACKDOOR_ADD` entirely (no other source provides it).

With only CIC + UNSW contributing, and those two bugs on top, real data landed on
almost exactly the ~10 classes that happen to be well-represented network-flow
categories (`DISC_ENV_PROBE`, `RECON_IP_SCAN`, `DISC_NETSTAT_SCAN`,
`ACCESS_BRUTE_SSH`, etc.) — none of the honeypot-specific attack-chain classes.

**Fix (2026-08-11):** Put Cowrie logs in place; fixed the CIC label normalization
and the UNSW map key (see DECISIONS.md for the "why normalize vs. hardcode"
reasoning). Re-ran notebook 01: **22/45 classes** now covered from real data
(737,319 sessions).

**How to tell if it's happening again:** Notebook 02 cell 7 prints
`Classes covered: N/45` and lists `missing_cls` — sanity-check N is in the
low-to-mid 20s (real-data-only), not single digits, before proceeding to TabSyn.
If it drops back toward ~10, check the same three things: are Cowrie logs
present, do CIC/UNSW label counts match what's in SCHEMA.md's expected list, and
re-check `df_real["source"].value_counts()` includes all three sources.

**Still open / not yet a confirmed bug:** `EVENT_MAP` in notebook 01's Cowrie
parsing cell is defined but never referenced by `build_record()` — the actual
if/elif chain has no branch for `cowrie.direct-tcpip.request` (537 real events in
the current log), so it never contributes `LATERAL_SSH_SPREAD` from Cowrie.
Not fixed since `LATERAL_SSH_SPREAD` is still reachable via UNSW's `Worms`
category (174 rows) — low priority, but if `LATERAL_SSH_SPREAD` coverage ever
looks thin, this is why.

---

## Notebook 02 feature extraction: 3 crash bugs from `None`/`NaN` field gaps

**Symptom:** `TypeError: object of type 'NoneType' has no len()`, then
`ValueError: truth value of an array with more than one element is ambiguous`,
then `ValueError: cannot convert float NaN to integer` — three separate crashes,
one after another, each appearing only after fixing the previous one.

**Root cause:** `df_cowrie` (from Cowrie logs) has several fields — `src_port`,
`event_timestamps`, `t_first_auth`, `t_first_cmd`, `src_ip`, `n_downloads` — that
`cic_aligned`/`unsw_aligned` (built in notebook 01 from CIC/UNSW) never set.
`pd.concat()` fills those gaps: as `None` for list-typed columns
(`event_timestamps`), as `NaN` (float) for scalar numeric columns (`src_port`).
Downstream extractor code assumed `session.get(key, default)` alone was enough —
but `.get()` only substitutes `default` when the key is *missing*, not when it's
present with value `None`/`NaN`. And the common defensive pattern
`session.get(key, default) or default` *also* fails for `NaN` (truthy in Python,
unlike `0`/`""`/`None`) and for numpy arrays (ambiguous truthiness).

**Fixes (all in `honeypot_dataset/src/extractors/`, 2026-08-11):**
1. `temporal.py:63` — `event_timestamps`: was `session.get(k, [])` (crashes on
   `None`, since `len(None)` fails). Fixed to explicit `is None` check, then
   `list(...)` (also handles the numpy-array case from Cowrie rows after a
   parquet round-trip, where `array or []` is itself ambiguous).
2. `network.py:67-68` — `src_port`/`dst_port`: was `int(session.get(k, d) or d)`
   (crashes on `NaN`, since `int(nan)` raises and `NaN or d` returns `NaN`, not
   `d`). Fixed with a new `_safe_int()` helper that explicitly checks
   `v is None` and `isinstance(v, float) and v != v` (NaN) before calling `int()`.

**Audited and confirmed NOT bugs (don't re-fix these):** every other
`session.get(...)` call across all 5 extractors either (a) already guards with
`or default` and only ever receives `float()`/`str()`-safe values that tolerate
`NaN` silently (cleaned up by the final `np.nan_to_num()` in each extractor), or
(b) references a field that literally no data source sets, so it's genuinely
absent from the row dict (not `NaN`) and `.get()`'s default applies correctly.
`network.py`'s `pkt_sizes_in`/`pkt_sizes_out` look similarly unguarded but are
safe today because they use truthy `if pkt_sizes_in:` checks and no source
currently populates them (`None` is falsy, so it just no-ops) — this becomes a
live risk only if a future data source starts setting these fields with `NaN`.

**How to tell if it's happening again:** Any `TypeError`/`ValueError` inside
`src/extractors/*.py` when running notebook 02, specifically anything mentioning
`NoneType has no len()`, `truth value of an array`, or `cannot convert float NaN`.
If a new data source is added to notebook 01, check its session-dict field
coverage against Cowrie's full field list (see `build_record()` in notebook 01)
before assuming extractors will handle the gaps.

---

## EPSS API call fails with 404 (harmless, not fixed)

**Symptom:** `WARNING EPSS batch failed: 404 Client Error: Not Found for url:
https://api.first.org/data/1.0/epss?cve=` during notebook 02 cell 3.

**Root cause:** `associated_cve` is hardcoded to `""` (empty string) by all three
real-data sources (Cowrie, CIC, UNSW never actually attach a CVE), so
`all_cves = df_real["associated_cve"].dropna().unique().tolist()` ends up with
just `['']`, and the EPSS API call is made with an empty `cve=` query param.

**Fix:** None applied — this doesn't crash anything, and the entire threat-intel
feature group (E, indices 106-119) is currently inert (all zeros) for real data
regardless, since there are no real CVE associations yet. Only matters once a
data source actually populates `associated_cve`.

---

## TabSyn's --epochs/--training_batch_size CLI args are silently ignored

**Symptom:** No crash — just wrong behavior. The notebook's hardware-aware batch
sizing (`vae_batch=512` on this laptop, `vae_epochs=500`) is passed via
`--training_batch_size`/`--epochs` to `tabsyn/main.py`, which parses them fine
into `args`, but the actual training functions never read those attributes.

**Root cause:** `tabsyn/tabsyn/vae/main.py`'s `main(args)` hardcodes
`num_epochs = 4000` and `batch_size = 4096` as local variables, completely
ignoring `args.epochs`/`args.training_batch_size`. Same in
`tabsyn/tabsyn/main.py` (diffusion): hardcoded `num_epochs = 10000 + 1`,
`batch_size = 4096`. This means **every VAE/diffusion run to date has used
4000/10001 epochs at batch 4096**, never whatever the notebook intended.
This likely explains a "diffusion took ~19 hours" memory better than the
notebook's own `diff_epochs = 2000` comment would.

**Fix (2026-08-11):** Changed both to
`num_epochs = getattr(args, 'epochs', 4000)` /
`batch_size = getattr(args, 'training_batch_size', 4096)` — respects the CLI
arg when the pipeline passes one, falls back to the original hardcoded value
when run standalone (its own argparse doesn't define these flags). Now the
notebook's hardware-aware batch sizing actually works.

**How to tell if it's happening again:** Check the printed
`self.category_embeddings.weight.shape` and epoch progress bar (`Epoch N/M`)
at the start of a run — `M` should match what the notebook computed
(`vae_epochs`/`diff_epochs`), not 4000/10001, and the batch count per epoch
(`total` in the tqdm bar) should match `train_rows / training_batch_size`.

## TabSyn VAE OOMs on a 4GB card — three separate unbatched full-dataset forward passes

**Symptom:** `torch.OutOfMemoryError: CUDA out of memory. Tried to allocate
6.20 GiB` (end of epoch 1, during validation) and, once that's fixed,
`Tried to allocate 55.82 GiB` (at the very end of training, saving latent
embeddings) — both on a 4GB GPU, both regardless of the training batch size.

**Root cause:** `tabsyn/tabsyn/vae/main.py` batches the *training* loop
correctly via `DataLoader(..., batch_size=batch_size)`, but has two other
places that run the **entire** dataset through the attention-based encoder in
a single unbatched forward pass: (1) the per-epoch validation step
(`model(X_test_num, X_test_cat)` on all ~98,506 test rows), and (2) the final
latent-embedding save (`pre_encoder(X_train_num, X_train_cat)` on all ~886,549
training rows). Attention cost scales badly with batch size, so both blow up
memory once the dataset is large — fine on a 24GB card, fatal on 4GB.

**Fix (2026-08-11):** Rewrote both spots to loop over `batch_size`-sized
chunks and accumulate (loss values for eval; concatenated arrays for the
latent embeddings), instead of one unbatched forward pass. Confirmed working
end-to-end on this laptop: 3-epoch test run completed cleanly, checkpoints
(`model.pt`, `encoder.pt`, `decoder.pt`, `train_z.npy`) all saved.

**How to tell if it's happening again:** Any `CUDA out of memory` error whose
traceback goes through `tabsyn/vae/model.py`'s attention forward (`a = q @
k.transpose(1, 2)` or similar) rather than through the training loop's own
`DataLoader` iteration — that's the signature of an unbatched full-dataset
pass, not a training-batch-size-too-large problem.

## `ReduceLROnPlateau(..., verbose=True)` — TypeError on this torch version

**Symptom:** `TypeError: ReduceLROnPlateau.__init__() got an unexpected
keyword argument 'verbose'` immediately on starting VAE or diffusion training.

**Root cause:** PyTorch removed the `verbose` kwarg from
`ReduceLROnPlateau` in a version newer than whatever TabSyn was originally
written against — pure version skew between the vendored TabSyn code and our
`torch==2.13.0+cu126`.

**Fix (2026-08-11):** Removed `verbose=True` from both call sites
(`tabsyn/tabsyn/vae/main.py:115`, `tabsyn/tabsyn/main.py:54`).

## TabSyn's `zero` dependency is a PyPI name collision, not the library the code expects

**Symptom:** `ModuleNotFoundError: No module named 'pkg_resources'` raised
*inside* the installed `zero` package's own `__init__.py`, when all we did was
`import zero` as a transitive dependency of `tabsyn/src/__init__.py`.

**Root cause:** `pip install zero` installs "Linear circuit simulator" by
Sean Leavey — completely unrelated to the small ML training-utility library
TabSyn's `src/deep.py`/`src/util.py` actually expect (a Yandex Research
package, apparently never published under this exact name on PyPI, likely
originally installed from GitHub when TabSyn was first written).
`pip index versions zero` confirms every available version (0.6.3 through
0.9.2) is the circuit simulator — there's no version pin that fixes this.

**Fix (2026-08-11):** Added `tabsyn/zero.py` — a local shim implementing only
the 4 things actually referenced (`zero.random.get_state`/`set_state`,
`zero.iter_batches`, `zero.hardware.get_gpus_info`), none of which turned out
to be called by the actual VAE/diffusion training paths (only imported at
module load time via `from .deep import *`). Works because Python puts a
script's own directory ahead of site-packages on `sys.path`, so this shadows
the real PyPI package whenever code runs with `cwd=tabsyn/` (which is how the
notebook always invokes it).

**How to tell if it's happening again:** If `tabsyn/zero.py` ever gets deleted
or someone runs TabSyn code from a different working directory (so the shim
isn't found first), the `pkg_resources` `ModuleNotFoundError` will come back.

## TabSyn's own exception handling hides the real import error

**Note, not a bug we fixed:** `tabsyn/utils.py`'s `execute_function()` wraps
the dynamic `importlib.import_module(module_name)` call in a bare
`except ModuleNotFoundError: print(f"Module {module_name} not found."); exit(1)`.
This swallows the *actual* traceback — every missing-dependency error above
(`icecream`, `category_encoders`, `tomli`, the `zero`/`pkg_resources` issue)
first appeared as the unhelpful `Module tabsyn.vae.main not found.` when run
via `python main.py --method vae ...`. **To debug any future TabSyn import
failure, don't trust that message — run `python -c "import tabsyn.vae.main"`
directly** (bypassing `execute_function`) to see the real traceback.

## venv torch installed as CPU-only build despite GPU present

**Symptom:** `torch.cuda.is_available()` returned `False` even though `nvidia-smi`
correctly showed the RTX 3050 and a working driver.

**Root cause:** Not fully diagnosed (pip likely resolved a CPU wheel by default),
but the venv's Python is 3.14.7, which is new enough that CUDA-wheel availability
needed an explicit index URL rather than the default PyPI resolution.

**Fix:** `pip install torch==2.13.0+cu126 --index-url https://download.pytorch.org/whl/cu126`
— confirmed via `pip index versions torch --index-url .../cu126` that a `cp314`
wheel exists for this exact torch version before installing. See HARDWARE.md for
the full verified command and version pins.
