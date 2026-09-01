"""
ml_analytics/models/cnn_lstm.py

CNN-LSTM baseline for kill-chain micro-state classification.

This is the "baseline" architecture the project compares against MT3
(ml_analytics/models/mt3.py). It consumes the same 128-d feature vector produced
by the honeypot_dataset extraction pipeline, splits it into the six named groups
(honeypot_dataset/configs/schema.py FEATURE_GROUPS), and runs each group through
the branch encoder its "arch" designates.

Difference from MT3 -- deliberately only the fusion step:
  - MT3     : branch embeddings -> Transformer encoder (self-attention over the
              six branch tokens) -> mean-pool -> emission head + phase head.
  - baseline: branch embeddings -> concatenate -> MLP -> emission head.
The branch encoders are intentionally identical to MT3's, so a difference in
scores is attributable to the fusion mechanism (and MT3's auxiliary phase head)
rather than to unrelated encoder capacity.

NO TRANSFORMER IS LOADED OR RUN HERE. The D_semantic block (columns 76-105) is
*already* the DistilBERT CLS -> PCA(30) projection, computed offline in notebook
02; this module consumes those 30 numbers through a plain dense branch. A live
end-to-end DistilBERT branch (raw command_text -> transformer) is a different
design that needs the parquet and the dataset owner's agreement -- see
ml_analytics/README.md.

Notes on the frozen dataset (honeypot_dataset/data/final/, 2026-08-28):
  - X_* is ALREADY scaled (column means ~0, stds ~1). Do not apply
    feature_scaler.pkl to it again; that scaler is for new/live sessions.
  - E_threat_intel (106-119) and F_tls_host (120-127) are constant-zero for
    every row -- no CVE and no TLS/JA3 data in the sources. Their branches are
    kept by default so the input contract matches MT3, but they carry no signal.
    Pass use_groups=(...) to drop them for the ablation.

FEATURE_GROUPS below is a local copy of the values in
honeypot_dataset/configs/schema.py -- kept local, as in mt3.py, because
ml_analytics and honeypot_dataset are independent top-level packages with no
shared installable dependency between them.
"""
from __future__ import annotations

from typing import Dict, Optional, Sequence, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

N_FEATURES = 128
N_CLASSES = 45

FEATURE_GROUPS: Dict[str, Dict[str, object]] = {
    "A_temporal":     {"start": 0,   "end": 24,  "arch": "LSTM"},
    "B_network":      {"start": 24,  "end": 52,  "arch": "CNN"},
    "C_payload":      {"start": 52,  "end": 76,  "arch": "CNN"},
    "D_semantic":     {"start": 76,  "end": 106, "arch": "DistilBERT"},
    "E_threat_intel": {"start": 106, "end": 120, "arch": "CNN+LSTM"},
    "F_tls_host":     {"start": 120, "end": 128, "arch": "CNN"},
}

# Groups whose columns are constant-zero in the frozen dataset. Informational --
# the model still reads them by default so the 128-d contract matches MT3.
DEAD_GROUPS: Tuple[str, ...] = ("E_threat_intel", "F_tls_host")


class _LSTMBranch(nn.Module):
    """Each scalar feature is one timestep; final hidden state is the branch embedding."""

    def __init__(self, d_model: int) -> None:
        super().__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=d_model, batch_first=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        _, (h_n, _) = self.lstm(x.unsqueeze(-1))  # (B, in_dim, 1) -> h_n: (1, B, d_model)
        return h_n[-1]


class _CNNBranch(nn.Module):
    """1-D conv over the flat feature vector, pooled to a fixed embedding."""

    def __init__(self, d_model: int) -> None:
        super().__init__()
        self.conv = nn.Sequential(
            nn.Conv1d(1, 16, kernel_size=3, padding=1), nn.ReLU(),
            nn.Conv1d(16, 32, kernel_size=3, padding=1), nn.ReLU(),
            nn.AdaptiveAvgPool1d(1),
        )
        self.proj = nn.Linear(32, d_model)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = self.conv(x.unsqueeze(1)).squeeze(-1)  # (B, 32)
        return self.proj(h)


class _CNNLSTMBranch(nn.Module):
    """Conv1d feature extraction followed by an LSTM over the resulting sequence."""

    def __init__(self, d_model: int) -> None:
        super().__init__()
        self.conv = nn.Sequential(nn.Conv1d(1, 16, kernel_size=3, padding=1), nn.ReLU())
        self.lstm = nn.LSTM(input_size=16, hidden_size=d_model, batch_first=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        h = self.conv(x.unsqueeze(1)).permute(0, 2, 1)  # (B, in_dim, 16)
        _, (h_n, _) = self.lstm(h)
        return h_n[-1]


class _DenseBranch(nn.Module):
    """Plain projection for already-embedded features (the offline DistilBERT CLS + PCA block)."""

    def __init__(self, in_dim: int, d_model: int) -> None:
        super().__init__()
        self.net = nn.Sequential(nn.Linear(in_dim, d_model), nn.GELU(), nn.LayerNorm(d_model))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


_BRANCH_CTORS = {
    "LSTM":       lambda in_dim, d_model: _LSTMBranch(d_model),
    "CNN":        lambda in_dim, d_model: _CNNBranch(d_model),
    "CNN+LSTM":   lambda in_dim, d_model: _CNNLSTMBranch(d_model),
    # "DistilBERT" names the feature *provenance*, not a transformer: the block is
    # already a PCA(30) projection of DistilBERT CLS vectors, so a dense branch is
    # the correct consumer.
    "DistilBERT": lambda in_dim, d_model: _DenseBranch(in_dim, d_model),
}


def focal_loss(
    logits: torch.Tensor,
    targets: torch.Tensor,
    gamma: float = 2.0,
    weight: Optional[torch.Tensor] = None,
) -> torch.Tensor:
    """Multi-class focal loss; `weight` is the usual per-class weight vector."""
    log_p = F.log_softmax(logits, dim=-1)
    log_pt = log_p.gather(1, targets.unsqueeze(1)).squeeze(1)
    loss = -((1.0 - log_pt.exp()) ** gamma) * log_pt
    if weight is not None:
        w = weight[targets]
        return (loss * w).sum() / w.sum().clamp_min(1e-8)
    return loss.mean()


class CNNLSTM(nn.Module):
    """Multi-branch CNN-LSTM baseline over the 128-d session feature vector.

    Args:
        n_features: width of the input vector (must match the slices in FEATURE_GROUPS).
        n_classes: number of micro-states (45).
        d_model: per-branch embedding width.
        hidden_dim: width of the fusion MLP.
        dropout: dropout applied in the fusion MLP.
        use_groups: subset of FEATURE_GROUPS to encode. Defaults to all six (the
            MT3-parity setting). Dropped columns are simply not read; the input is
            still expected to be n_features wide.
        loss_type: "ce" (cross-entropy) or "focal".
        focal_gamma: focusing parameter when loss_type="focal".
        class_weights: optional per-class weight vector, registered as a buffer so
            it follows .to(device). See class_weights_from_labels().
        label_smoothing: passed to cross-entropy; ignored for focal loss.

    forward(x, labels=None) -> (logits, loss); loss is None when labels is None.
    """

    def __init__(
        self,
        n_features: int = N_FEATURES,
        n_classes: int = N_CLASSES,
        d_model: int = 64,
        hidden_dim: int = 256,
        dropout: float = 0.3,
        use_groups: Optional[Sequence[str]] = None,
        loss_type: str = "ce",
        focal_gamma: float = 2.0,
        class_weights: Optional[torch.Tensor] = None,
        label_smoothing: float = 0.0,
        feature_groups: Optional[Dict[str, Dict[str, object]]] = None,
    ) -> None:
        super().__init__()
        feature_groups = feature_groups or FEATURE_GROUPS
        if loss_type not in ("ce", "focal"):
            raise ValueError(f"loss_type must be 'ce' or 'focal', got {loss_type!r}")

        names = list(use_groups) if use_groups is not None else list(feature_groups)
        unknown = [n for n in names if n not in feature_groups]
        if unknown:
            raise ValueError(f"unknown feature group(s): {unknown}")
        if not names:
            raise ValueError("use_groups must select at least one feature group")

        self.n_features = n_features
        self.n_classes = n_classes
        self.loss_type = loss_type
        self.focal_gamma = focal_gamma
        self.label_smoothing = label_smoothing
        self.group_names = names
        self.group_slices = [
            (feature_groups[n]["start"], feature_groups[n]["end"]) for n in names
        ]

        self.branches = nn.ModuleList([
            _BRANCH_CTORS[feature_groups[n]["arch"]](
                feature_groups[n]["end"] - feature_groups[n]["start"], d_model
            )
            for n in names
        ])

        fused_dim = d_model * len(names)
        self.fusion = nn.Sequential(
            nn.LayerNorm(fused_dim),
            nn.Linear(fused_dim, hidden_dim), nn.ReLU(), nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim // 2), nn.ReLU(), nn.Dropout(dropout),
        )
        self.head = nn.Linear(hidden_dim // 2, n_classes)

        if class_weights is not None:
            w = torch.as_tensor(class_weights, dtype=torch.float32)
            if w.shape != (n_classes,):
                raise ValueError(
                    f"class_weights must have shape ({n_classes},), got {tuple(w.shape)}"
                )
            self.register_buffer("class_weights", w, persistent=True)
        else:
            self.class_weights = None

    def forward(
        self, x: torch.Tensor, labels: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, Optional[torch.Tensor]]:
        if x.shape[-1] != self.n_features:
            raise ValueError(f"expected {self.n_features} input features, got {x.shape[-1]}")

        branch_embeds = [
            branch(x[:, start:end])
            for branch, (start, end) in zip(self.branches, self.group_slices)
        ]
        fused = self.fusion(torch.cat(branch_embeds, dim=1))  # (B, hidden_dim // 2)
        logits = self.head(fused)

        loss = None
        if labels is not None:
            if self.loss_type == "focal":
                loss = focal_loss(logits, labels, self.focal_gamma, self.class_weights)
            else:
                loss = F.cross_entropy(
                    logits, labels,
                    weight=self.class_weights,
                    label_smoothing=self.label_smoothing,
                )
        return logits, loss

    @torch.no_grad()
    def predict(self, x: torch.Tensor) -> torch.Tensor:
        """Argmax micro-state ids for a batch. Caller handles eval() and device placement."""
        logits, _ = self.forward(x)
        return logits.argmax(dim=-1)

    def count_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def class_weights_from_labels(
    y: Sequence[int], n_classes: int = N_CLASSES, scheme: str = "inverse_sqrt",
) -> torch.Tensor:
    """Per-class weights from a label array, normalised to mean 1 over present classes.

    "inverse"      -> 1/count       (aggressive; can destabilise at this 28x imbalance)
    "inverse_sqrt" -> 1/sqrt(count) (default)
    Classes absent from y get weight 0, so they cannot skew the normalisation.
    """
    if scheme not in ("inverse", "inverse_sqrt"):
        raise ValueError(f"unknown scheme {scheme!r}")
    counts = torch.bincount(torch.as_tensor(y, dtype=torch.long), minlength=n_classes).float()
    present = counts > 0
    w = torch.zeros(n_classes, dtype=torch.float32)
    w[present] = 1.0 / (counts[present] if scheme == "inverse" else counts[present].sqrt())
    return w / w[present].mean()
