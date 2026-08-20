# TabSyn 4GB-VRAM Patches

Six changes applied on top of upstream `amazon-science/tabsyn` to make VAE
and diffusion training runnable on a 4GB laptop GPU (RTX 3050). Without
these, TabSyn OOMs almost immediately — the upstream code assumes enough
VRAM to hold a full test-set forward pass and a full 700k-row encoding
pass in memory at once, plus it hardcodes batch size / epoch count and
gives no way to checkpoint or monitor a multi-hour run.

**Base commit:** `cb5ac0f` (upstream `origin/main`, "Merge pull request #20
from hengruizhang98/main") — this is what a fresh `git clone
https://github.com/amazon-science/tabsyn.git` gives you today, and what
`setup.sh` / `setup.ps1` in the project root will silently clone if
`tabsyn/` doesn't already exist. **A fresh clone does not have these
patches applied** — see "Applying to a fresh clone" below.

**Where these patches currently live (as of 2026-08-06):** partly as one
local git commit inside `tabsyn/`'s own repo (`d19f0b2`, never pushed —
`tabsyn/` isn't the maintainers' repo, so there's nowhere to push it to),
partly as *uncommitted* working-tree changes in the same local clone. That
means right now they exist in exactly one place: this laptop's
`tabsyn/` directory. If that directory is deleted or a fresh clone is
made (e.g. on the college machine), the patches are gone unless applied
from `tabsyn_patches.patch` (checked into *this* repo, alongside this
doc — that's the actual backup copy).

---

## The six patches

### 1. Batch the VAE evaluation pass

**Problem:** the eval step ran the *entire* held-out test set through the
model in one forward pass (`model(X_test_num, X_test_cat)` with no
batching). On a 700k-row dataset this alone is enough to OOM a 4GB card
regardless of training batch size.

**Fix:** eval now takes only the first `eval_batch = min(batch_size,
len(X_test_num))` rows each epoch, matching the training batch size
instead of the full test set.

`tabsyn/vae/main.py`:
```python
eval_batch = min(batch_size, X_test_num.shape[0])
X_test_eval = X_test_num[:eval_batch].to(device)
X_test_cat_eval = X_test_cat[:eval_batch].to(device)
Recon_X_num, Recon_X_cat, mu_z, std_z = model(X_test_eval, X_test_cat_eval)
```

### 2. Keep the test set on CPU; only move the active eval batch to GPU

**Problem:** upstream moved the *entire* test tensor to GPU once at
startup (`X_test_num.float().to(device)`) and kept it resident in VRAM
for the whole run — permanent memory pressure on top of the training
batch and model weights.

**Fix:** test tensors stay on CPU; only the small eval-batch slice
(patch #1) gets `.to(device)`, and only transiently during the eval step.

`tabsyn/vae/main.py`:
```python
X_test_num = X_test_num.float()   # was: .float().to(device)
X_test_cat = X_test_cat           # was: .to(device)
```

### 3. Batch the post-training encoding pass

**Problem:** after training, the full training set (up to ~700k rows)
was encoded to the latent space in a single forward pass
(`pre_encoder(X_train_num, X_train_cat)`) to produce `train_z.npy` for
the diffusion stage — same OOM shape as patch #1, just at the end of the
run instead of every epoch (so it could burn through 16 hours of VAE
training and then OOM on the very last step).

**Fix:** encode in chunks of `batch_size` and concatenate the results on
CPU.

`tabsyn/vae/main.py`:
```python
train_z_parts = []
enc_batch = batch_size
for i in range(0, len(X_train_num), enc_batch):
    xn = X_train_num[i:i+enc_batch].to(device)
    xc = X_train_cat[i:i+enc_batch].to(device)
    z_part = pre_encoder(xn, xc).detach().cpu()
    train_z_parts.append(z_part)
train_z = torch.cat(train_z_parts, dim=0).numpy()
```

### 4. Configurable batch size and epoch count

**Problem:** batch size (4096) and epoch count (4000 for VAE, 10000 for
diffusion) were hardcoded constants. No way to shrink the batch for a
4GB card, or to run a short diagnostic pass, without editing the library
source directly.

**Fix:** both now read from CLI args if provided, falling back to the
original hardcoded defaults if not — so upstream behavior is unchanged
unless you explicitly pass the new flags.

`tabsyn/vae/main.py` / `tabsyn/main.py`:
```python
batch_size = args.training_batch_size if hasattr(args, 'training_batch_size') and args.training_batch_size else 4096
num_epochs = args.epochs if hasattr(args, 'epochs') and args.epochs else 4000   # (10000 for diffusion)
```
New CLI args added in `utils.py:get_args()` are consumed via `getattr`,
so this also required patch #6's arg-parser additions.

*This is the actual mechanism behind the documented VAE run:
`--training_batch_size 512 --epochs 500` overrode both defaults for the
4GB-card run described in SESSION_NOTES.md / PANEL_REVIEW_UPDATE.md.*

### 5. Periodic checkpointing

**Problem:** upstream only saved a checkpoint every 1000 epochs for
diffusion and had no periodic checkpointing at all for the VAE — on a
multi-hour run on a laptop that might get interrupted (sleep, reboot,
crash), losing partial progress was a real risk. This gap is also what
made the diffusion collapse (see PANEL_REVIEW_UPDATE.md §4.4) worse than
it needed to be — the good pre-collapse state at epoch 119 fell between
checkpoint intervals and was never saved.

**Fix:** new `--ckpt_every N --ckpt_dir PATH` args save a checkpoint
every N epochs to the given directory, for both VAE and diffusion.

`tabsyn/vae/main.py` / `tabsyn/main.py`:
```python
if ckpt_dir and ckpt_every > 0 and (epoch + 1) % ckpt_every == 0:
    ckpt_path = os.path.join(ckpt_dir, f'vae_epoch_{epoch+1}.pt')  # or diffusion_epoch_{epoch+1}.pt
    torch.save(model.state_dict(), ckpt_path)
```

**Lesson for the rerun:** set `--ckpt_every` low enough (e.g. 50–100
epochs, not 200) that a mid-training divergence like the epoch-120
collapse can't erase the best checkpoint before it's saved.

### 6. Per-epoch status/loss logging to a file

**Problem:** the only training feedback was stdout — nothing durable to
check progress against on a machine you're not actively watching (e.g.
reviewing an overnight run the next morning), and nothing that could be
plotted directly without re-running.

**Fix:** new `--status_file PATH` arg writes a CSV-ish log, one line per
epoch, with the loss breakdown. This is exactly what
`data/synthetic/tabsyn_status.txt` and
`data/synthetic/tabsyn_diffusion_status.txt` are — and it's what caught
the epoch-120 diffusion collapse in the first place.

`tabsyn/vae/main.py`:
```python
if status_file:
    with open(status_file, 'a') as f:
        f.write(f"{epoch},{beta:.6f},{num_loss:.6f},{cat_loss:.6f},{kl_loss:.6f},"
                 f"{val_mse_loss.item():.6f},{val_ce_loss.item():.6f},"
                 f"{train_acc.item():.6f},{val_acc.item():.6f},{best_train_loss:.6f}\n")
```
`tabsyn/main.py` (diffusion) writes the analogous
`epoch,train_loss,best_loss,time_elapsed` line.

New arg declarations for both #5 and #6 live in `utils.py:get_args()`:
```python
parser.add_argument('--ckpt_every', type=int, default=0, help='Save checkpoint every N epochs (0=off).')
parser.add_argument('--ckpt_dir', type=str, default=None, help='Directory for periodic checkpoints.')
parser.add_argument('--status_file', type=str, default=None, help='Path to write per-epoch loss log.')
```

---

## Bonus (not counted in the six): configurable sample count

`tabsyn/sample.py` also got a minor `--num_samples` override so sampling
doesn't always have to match the training set size 1:1:
```python
num_samples = args.num_samples if hasattr(args, 'num_samples') and args.num_samples else train_z.shape[0]
```
Not one of the six VRAM fixes — listed here for completeness since it's
in the same patch file.

---

## Applying to a fresh clone

If `tabsyn/` was just cloned fresh (by `setup.sh`, `setup.ps1`, or
manually) and doesn't have these patches:

```bash
cd tabsyn
git apply ../honeypot_dataset/docs/tabsyn_patches.patch
```

Verify it applied cleanly — `git status` inside `tabsyn/` should show
`tabsyn/main.py`, `tabsyn/sample.py`, `tabsyn/vae/main.py`, and
`utils.py` as modified, matching this doc's six patches (plus the bonus
`--num_samples` change).

**This step is not yet wired into `setup.sh` / `setup.ps1`.** Both
scripts currently clone vanilla upstream TabSyn and stop — applying this
patch is a manual step until the scripts are updated to do it
automatically after cloning.

## Training commands using the new flags

```bash
# VAE — 4GB card, matches the documented 500-epoch run
python -m tabsyn.vae.main --dataname honeypot_sessions \
    --training_batch_size 512 --epochs 500 \
    --ckpt_every 50 --ckpt_dir ../data/synthetic/tabsyn_checkpoints \
    --status_file ../data/synthetic/tabsyn_status.txt

# Diffusion — matches the documented 2000-epoch run
python -m tabsyn.main --dataname honeypot_sessions --mode train \
    --training_batch_size 4096 --epochs 2000 \
    --ckpt_every 50 --ckpt_dir ../data/synthetic/tabsyn_diffusion_checkpoints \
    --status_file ../data/synthetic/tabsyn_diffusion_status.txt
```

Note `--ckpt_every 50` above, not the 200 used in the run that lost the
epoch-119 checkpoint (see patch #5's rerun lesson) — recommended for the
college rerun regardless of the extra VRAM headroom, since it's a
correctness/safety change, not a memory one.
