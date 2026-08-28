"""
Loss functions for MT3 training.

Why the loss is computed here and not inside MT3.forward
--------------------------------------------------------
MT3.forward(x, labels) already returns a loss:

    loss = CE(emissions, labels) + aux_loss_weight * CE(hp_logits, phase(labels))

That built-in loss is UNWEIGHTED. MT3_PROMPT.md requires a class-weighted /
focal loss (train split runs 6,055 -- 173,722 samples per class, ~29x), and the
headline metric is macro-F1, which unweighted CE optimises poorly.

So the trainer calls forward WITHOUT labels and rebuilds the same two-term
objective here with a weighted / focal state term. This changes no architecture
(mt3.py is untouched, per the hard rule) -- only the objective. Passing
--loss ce reproduces MT3.forward's own loss exactly, which is verified in
smoke_test.py.
"""
from __future__ import annotations

from typing import Optional, Sequence

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

WEIGHT_SCHEMES = ("none", "balanced", "inv_sqrt", "effective")


def build_class_weights(
    y: np.ndarray,
    n_classes: int,
    scheme: str = "balanced",
    beta: float = 0.999,
    clip: Optional[float] = 20.0,
) -> Optional[np.ndarray]:
    """Per-class loss weights, normalised to mean 1 so the LR stays comparable.

    balanced   n / (k * count)              -- sklearn's class_weight="balanced"
    inv_sqrt   1 / sqrt(count)              -- gentler, usually safer for macro-F1
    effective  (1-beta) / (1-beta**count)   -- Cui et al. 2019 effective number
    none       no weighting

    Classes absent from y get weight 0 (they cannot contribute a gradient anyway,
    and a huge weight on an unseen class destabilises training).
    """
    if scheme == "none":
        return None
    if scheme not in WEIGHT_SCHEMES:
        raise ValueError(f"unknown class-weight scheme {scheme!r}, expected {WEIGHT_SCHEMES}")

    counts = np.bincount(np.asarray(y, dtype=np.int64), minlength=n_classes).astype(np.float64)
    present = counts > 0
    w = np.zeros(n_classes, dtype=np.float64)

    if scheme == "balanced":
        w[present] = counts[present].sum() / (present.sum() * counts[present])
    elif scheme == "inv_sqrt":
        w[present] = 1.0 / np.sqrt(counts[present])
    elif scheme == "effective":
        eff = (1.0 - np.power(beta, counts[present])) / (1.0 - beta)
        w[present] = 1.0 / eff

    w[present] /= w[present].mean()  # mean-1 over present classes
    if clip is not None:
        w = np.clip(w, 0.0, clip)
        if w[present].mean() > 0:
            w[present] /= w[present].mean()
    return w.astype(np.float32)


class FocalLoss(nn.Module):
    """Multi-class focal loss (Lin et al. 2017) with optional class weights.

    Computed from log-softmax for numerical stability; supports label smoothing
    via the standard CE term when gamma == 0.
    """

    def __init__(
        self,
        gamma: float = 1.5,
        weight: Optional[torch.Tensor] = None,
        label_smoothing: float = 0.0,
        reduction: str = "mean",
    ) -> None:
        super().__init__()
        self.gamma = float(gamma)
        self.label_smoothing = float(label_smoothing)
        self.reduction = reduction
        self.register_buffer("weight", weight if weight is not None else None, persistent=False)

    def forward(self, logits: torch.Tensor, target: torch.Tensor) -> torch.Tensor:
        logp = F.log_softmax(logits.float(), dim=-1)
        logpt = logp.gather(1, target.unsqueeze(1)).squeeze(1)
        pt = logpt.exp()
        focal = (1.0 - pt).pow(self.gamma)

        if self.label_smoothing > 0.0:
            n = logits.shape[-1]
            smooth = -logp.mean(dim=-1)
            nll = -logpt
            base = (1.0 - self.label_smoothing) * nll + self.label_smoothing * smooth * n / max(n - 1, 1)
        else:
            base = -logpt

        loss = focal * base
        if self.weight is not None:
            w = self.weight.to(loss.device)[target]
            loss = loss * w
            if self.reduction == "mean":
                denom = w.sum().clamp_min(1e-8)
                return loss.sum() / denom
        if self.reduction == "mean":
            return loss.mean()
        if self.reduction == "sum":
            return loss.sum()
        return loss


def build_state_criterion(
    loss_name: str,
    class_weights: Optional[np.ndarray],
    focal_gamma: float = 1.5,
    label_smoothing: float = 0.0,
    device: str = "cpu",
) -> nn.Module:
    """State (45-way) criterion.

    ce           plain cross-entropy (reproduces MT3.forward's own loss)
    weighted_ce  cross-entropy with per-class weights
    focal        focal loss (optionally class-weighted)
    """
    w = None
    if class_weights is not None and loss_name != "ce":
        w = torch.as_tensor(class_weights, dtype=torch.float32, device=device)

    if loss_name == "ce":
        return nn.CrossEntropyLoss(label_smoothing=label_smoothing)
    if loss_name == "weighted_ce":
        return nn.CrossEntropyLoss(weight=w, label_smoothing=label_smoothing)
    if loss_name == "focal":
        return FocalLoss(gamma=focal_gamma, weight=w, label_smoothing=label_smoothing)
    raise ValueError(f"unknown loss {loss_name!r}; expected ce|weighted_ce|focal")


class MT3Objective(nn.Module):
    """The two-term MT3 objective: state loss + aux_weight * phase loss.

    Mirrors the structure inside MT3.forward so that --loss ce is numerically
    identical to the model's built-in loss, while the weighted/focal variants
    swap only the state term.

    The 9-way phase target is derived from the 45-way label with the model's own
    idx_to_phase buffer -- callers never supply a phase label.
    """

    def __init__(
        self,
        state_criterion: nn.Module,
        idx_to_phase: Sequence[int] | torch.Tensor,
        aux_loss_weight: float = 0.3,
        phase_class_weights: Optional[np.ndarray] = None,
        device: str = "cpu",
    ) -> None:
        super().__init__()
        self.state_criterion = state_criterion
        self.aux_loss_weight = float(aux_loss_weight)
        pw = (
            torch.as_tensor(phase_class_weights, dtype=torch.float32, device=device)
            if phase_class_weights is not None
            else None
        )
        self.phase_criterion = nn.CrossEntropyLoss(weight=pw)
        idx = (
            idx_to_phase.clone().detach()
            if isinstance(idx_to_phase, torch.Tensor)
            else torch.as_tensor(list(idx_to_phase), dtype=torch.long)
        )
        self.register_buffer("idx_to_phase", idx.to(torch.long), persistent=False)

    def forward(
        self,
        emissions: torch.Tensor,
        hp_logits: torch.Tensor,
        labels: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        state_loss = self.state_criterion(emissions, labels)
        phase_target = self.idx_to_phase.to(labels.device)[labels]
        phase_loss = self.phase_criterion(hp_logits, phase_target)
        total = state_loss + self.aux_loss_weight * phase_loss
        return total, state_loss.detach(), phase_loss.detach()
