# HoneySynth-1M — Dataset Generation Pipeline

Publication-grade synthetic dataset for the Adaptive Honeypot Threat Intelligence
Platform. Generates 1.2M labelled sessions (128 features, 45 MITRE ATT&CK-mapped
micro-states) for training the CNN-LSTM-DistilBERT baseline and the proposed
MT3 + TabSyn + Markov + EPSS-Drift architecture.

## Dataset Composition

| Source | Sessions | % | Generator |
|---|---|---|---|
| Real Cowrie logs | 180,000 | 15% | Your honeypot deployment |
| Real transfer (CIC-IDS2017/UNSW-NB15) | 60,000 | 5% | Public datasets |
| TabSyn synthetic | 720,000 | 60% | VAE + diffusion (ICLR 2023) |
| GReaT synthetic | 240,000 | 20% | Fine-tuned GPT-2 |
| **Total** | **1,200,000** | 100% | |

## Folder Structure

```
honeypot_dataset/
├── configs/
│   └── schema.py              ← 45 micro-states, 128-feature layout, kill-chain DAG
├── src/
│   ├── extractors/
│   │   ├── temporal.py        ← Group A: 24 features → LSTM
│   │   ├── network.py         ← Group B: 28 features → CNN
│   │   ├── payload.py         ← Group C: 24 features → CNN
│   │   ├── semantic.py        ← Group D: 30 features → DistilBERT+PCA
│   │   ├── threat_intel.py    ← Group E: 14 features → CNN+LSTM
│   │   ├── tls_host.py        ← Group F: 8 features → CNN
│   │   └── pipeline.py        ← Orchestrates all 6 extractors
│   ├── generators/
│   │   ├── kill_chain_simulator.py  ← Markov DAG validity filter + simulator
│   │   └── epss_drift.py            ← Temporal EPSS drift injection (novelty)
│   └── validators/
│       └── quality_checks.py  ← Wasserstein, adversarial AUC, TSTR
├── notebooks/
│   ├── 01_process_real_data.ipynb       ← Parse Cowrie logs + CIC/UNSW transfer
│   ├── 02_feature_extraction.ipynb      ← Extract all 128 features
│   ├── 03_tabsyn_generation.ipynb       ← Train + sample TabSyn (720k)
│   ├── 04_great_generation.ipynb        ← Fine-tune + sample GReaT (240k)
│   └── 05_assembly_validation.ipynb     ← Merge, split, normalise, validate
├── data/
│   ├── raw/            ← put Cowrie logs + CIC/UNSW CSVs here
│   ├── processed/      ← real session features
│   ├── synthetic/      ← TabSyn + GReaT output
│   └── final/           ← train/val/test splits ready for model training
├── requirements.txt
└── .env.example
```

## Setup

```bash
cd honeypot_dataset
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt
cp .env.example .env              # add your NVD_API_KEY

# Place your data:
mkdir -p data/raw/cowrie_logs data/raw/cic_ids2017
# Copy cowrie.json.* files into data/raw/cowrie_logs/
# Download CIC-IDS2017 CSVs into data/raw/cic_ids2017/
```

## Execution Order

Run notebooks in sequence. Notebooks 01–02 work on laptop (CPU/light GPU).
Notebooks 03–04 require the college system (RTX 4500 Ada, 24GB VRAM).

```bash
jupyter notebook notebooks/01_process_real_data.ipynb       # ~30 min
jupyter notebook notebooks/02_feature_extraction.ipynb      # ~1-2 hours
# ── switch to college system ──
jupyter notebook notebooks/03_tabsyn_generation.ipynb       # ~4 hours
jupyter notebook notebooks/04_great_generation.ipynb        # ~6 hours
jupyter notebook notebooks/05_assembly_validation.ipynb     # ~30 min
```

## Output

After Notebook 05 completes, `data/final/` contains:

```
X_train.npy        X_val.npy        X_test_synth.npy   X_test_real.npy
y_train.npy        y_val.npy        y_test_synth.npy   y_test_real.npy
feature_scaler.pkl
quality_report.json
dataset_card.json
```

`X_test_real.npy` is held out specifically for **TSTR** (Train-Synthetic-Test-Real)
evaluation — your paper's key result proving synthetic data transfers to real attacks.

## Quality Gates Before Training

Check `data/final/quality_report.json`:

- `adversarial_auc < 0.60` — synthetic data indistinguishable from real
- All `wasserstein.*.mean_W < 0.5` — per-group distributional fidelity
- `tstr.tstr_macro_f1 > 0.80` — synthetic data transfers to real attacks
- `balance_check.passed == true` — no class has < 2,000 samples

If any gate fails, see the notebook's troubleshooting cells before training
the CNN-LSTM-DistilBERT baseline or MT3.

## Citation Methods Used

- **TabSyn**: Zhang et al., "Mixed-Type Tabular Data Synthesis with Score-based
  Diffusion in Latent Space", ICLR 2024
- **GReaT**: Borisov et al., "Language Models are Realistic Tabular Data
  Generators", ICLR 2023
- **MITRE ATT&CK**: mitre.org/attack — all 45 micro-states mapped to technique IDs
