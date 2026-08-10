"""
ml_analytics/models/mt3.py

MT3 — Multi-branch Transformer for kill-chain micro-state classification.

This is the "proposed" architecture referenced in honeypot_dataset/README.md
("MT3 + TabSyn + Markov + EPSS-Drift"), as opposed to the CNN-LSTM-DistilBERT
baseline in ml_analytics/models/cnn_lstm.py.

The 128-d feature vector produced by honeypot_dataset's extraction pipeline
is split into its six named groups (honeypot_dataset/configs/schema.py
FEATURE_GROUPS), each run through a branch encoder matching that group's
designated architecture ("LSTM" / "CNN" / "CNN+LSTM" / "DistilBERT"),
projected to a common width, then fused across branches with a small
Transformer encoder (self-attention over the six branch embeddings).

Two heads sit on the fused representation:
  - emissions  (N_CLASSES=45): primary micro-state logits
  - hp_logits  (N_PHASES=9):   auxiliary kill-chain-phase logits

The phase head is supervised automatically from the micro-state label via
DEFAULT_IDX_TO_PHASE, so callers only need to provide the 45-way label.

FEATURE_GROUPS / DEFAULT_IDX_TO_PHASE below are a local copy of the values
in honeypot_dataset/configs/schema.py — kept local because ml_analytics and
honeypot_dataset are independent top-level packages with no shared
installable dependency between them.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

N_FEATURES = 128
N_CLASSES = 45
N_PHASES = 9

FEATURE_GROUPS: Dict[str, Dict[str, object]] = {
    "A_temporal":     {"start": 0,   "end": 24,  "arch": "LSTM"},
    "B_network":      {"start": 24,  "end": 52,  "arch": "CNN"},
    "C_payload":      {"start": 52,  "end": 76,  "arch": "CNN"},
    "D_semantic":     {"start": 76,  "end": 106, "arch": "DistilBERT"},
    "E_threat_intel": {"start": 106, "end": 120, "arch": "CNN+LSTM"},
    "F_tls_host":     {"start": 120, "end": 128, "arch": "CNN"},
}

# micro-state id -> kill-chain phase (0-8). Mirrors schema.py IDX_TO_PHASE.
DEFAULT_IDX_TO_PHASE: List[int] = (
    [0] * 6    # 0-5   Reconnaissance
    + [1] * 6  # 6-11  Initial Access
    + [2] * 6  # 12-17 Execution
    + [3] * 5  # 18-22 Discovery
    + [4] * 4  # 23-26 Privilege Escalation
    + [5] * 5  # 27-31 Persistence
    + [6] * 5  # 32-36 Defense Evasion
    + [7] * 3  # 37-39 Lateral Movement
    + [8] * 5  # 40-44 Exfiltration
)
assert len(DEFAULT_IDX_TO_PHASE) == N_CLASSES


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
    """Plain projection for already-embedded features (DistilBERT CLS + PCA)."""

    def __init__(self, in_dim: int, d_model: int) -> None:
        super().__init__()
        self.net = nn.Sequential(nn.Linear(in_dim, d_model), nn.GELU(), nn.LayerNorm(d_model))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


_BRANCH_CTORS = {
    "LSTM":       lambda in_dim, d_model: _LSTMBranch(d_model),
    "CNN":        lambda in_dim, d_model: _CNNBranch(d_model),
    "CNN+LSTM":   lambda in_dim, d_model: _CNNLSTMBranch(d_model),
    "DistilBERT": lambda in_dim, d_model: _DenseBranch(in_dim, d_model),
}


class MT3(nn.Module):
    def __init__(
        self,
        n_features: int = N_FEATURES,
        n_classes: int = N_CLASSES,
        n_phases: int = N_PHASES,
        d_model: int = 64,
        nhead: int = 4,
        num_fusion_layers: int = 2,
        dropout: float = 0.1,
        aux_loss_weight: float = 0.3,
        feature_groups: Optional[Dict[str, Dict[str, object]]] = None,
        idx_to_phase: Optional[List[int]] = None,
    ) -> None:
        super().__init__()
        feature_groups = feature_groups or FEATURE_GROUPS
        idx_to_phase = idx_to_phase or DEFAULT_IDX_TO_PHASE
        if len(idx_to_phase) != n_classes:
            raise ValueError(f"idx_to_phase must have {n_classes} entries, got {len(idx_to_phase)}")

        self.n_features = n_features
        self.aux_loss_weight = aux_loss_weight
        self.group_names = list(feature_groups.keys())
        self.group_slices = [(g["start"], g["end"]) for g in feature_groups.values()]

        self.branches = nn.ModuleList([
            _BRANCH_CTORS[g["arch"]](g["end"] - g["start"], d_model)
            for g in feature_groups.values()
        ])

        self.branch_pos_embed = nn.Parameter(torch.randn(1, len(self.branches), d_model) * 0.02)
        fusion_layer = nn.TransformerEncoderLayer(
            d_model=d_model, nhead=nhead, dim_feedforward=d_model * 4,
            dropout=dropout, batch_first=True, activation="gelu",
        )
        self.fusion = nn.TransformerEncoder(fusion_layer, num_layers=num_fusion_layers)
        self.pre_head_norm = nn.LayerNorm(d_model)

        self.emission_head = nn.Linear(d_model, n_classes)
        self.phase_head = nn.Linear(d_model, n_phases)

        self.register_buffer(
            "idx_to_phase", torch.tensor(idx_to_phase, dtype=torch.long), persistent=False
        )

    def forward(
        self, x: torch.Tensor, labels: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor, Optional[torch.Tensor]]:
        if x.shape[-1] != self.n_features:
            raise ValueError(f"expected {self.n_features} input features, got {x.shape[-1]}")

        branch_embeds = [
            branch(x[:, start:end])
            for branch, (start, end) in zip(self.branches, self.group_slices)
        ]
        tokens = torch.stack(branch_embeds, dim=1)  # (B, n_branches, d_model)
        tokens = tokens + self.branch_pos_embed
        fused = self.fusion(tokens)                    # (B, n_branches, d_model)
        pooled = self.pre_head_norm(fused.mean(dim=1))  # (B, d_model)

        emissions = self.emission_head(pooled)
        hp_logits = self.phase_head(pooled)

        loss = None
        if labels is not None:
            state_loss = F.cross_entropy(emissions, labels)
            phase_loss = F.cross_entropy(hp_logits, self.idx_to_phase[labels])
            loss = state_loss + self.aux_loss_weight * phase_loss

        return emissions, hp_logits, loss

    def count_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad)
