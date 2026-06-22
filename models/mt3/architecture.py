"""
models/mt3/architecture.py

MT3 — MITRE-Aware Temporal Threat Transformer
==============================================
The paper's main contribution. A transformer classifier over attacker
sessions that introduces three architectural novelties over the
CNN-LSTM-DistilBERT baseline:

  1. Feature-group tokenization
     Each of the 6 feature groups (A_temporal, B_network, C_payload,
     D_semantic, E_threat_intel, F_tls_host) is projected into its own
     transformer token. Self-attention then learns cross-group interactions
     (e.g. how threat-intel features modulate temporal burst patterns).

  2. Kill-chain phase positional encoding
     A learned encoding over the 9 kill-chain phases is injected into the
     group tokens, giving the model a structural prior about where in the
     attack lifecycle a session sits.

  3. CRF decoding head
     A linear-chain CRF replaces plain softmax. At inference, Viterbi
     decoding is constrained by the KILL_CHAIN_DAG so that no forbidden
     state-to-state transition can ever be emitted — Kill-Chain Violation
     Rate (KCVR) = 0.00% by construction. The softmax baseline cannot make
     this guarantee.

A multi-task honeypot head simultaneously predicts the 4-class deployment
target (SSH / WEB / DB / AUTH) from the same forward pass.

Reference: TEAM_BRIEFING.md Section 5, Model 2.

Smoke test (also runnable via ``python -m models.mt3.architecture``)::

    import torch
    from models.mt3.architecture import MT3
    model = MT3()
    x = torch.randn(4, 128)
    y = torch.randint(0, 45, (4,))
    emissions, hp_logits, loss = model(x, labels=y)
    preds = model.decode(x)
"""
from __future__ import annotations

import os
import sys
import math
from typing import List, Optional, Tuple

import torch
import torch.nn as nn

# ─── Schema constants (stable; mirrored from configs/schema.py) ──────────────
# Feature-group layout — see configs/schema.py:FEATURE_GROUPS
GROUP_NAMES: List[str] = [
    "A_temporal", "B_network", "C_payload",
    "D_semantic", "E_threat_intel", "F_tls_host",
]
GROUP_SLICES: List[Tuple[int, int]] = [
    (0, 24), (24, 52), (52, 76), (76, 106), (106, 120), (120, 128),
]
GROUP_SIZES: List[int] = [hi - lo for lo, hi in GROUP_SLICES]  # [24,28,24,30,14,8]

N_FEATURES = 128
N_GROUPS = 6
N_CLASSES = 45     # 45 MITRE-mapped micro-states
N_PHASES = 9       # 9 kill-chain phases
N_HONEYPOTS = 4    # SSH / WEB / DB / AUTH deployment targets

assert sum(GROUP_SIZES) == N_FEATURES, "feature-group sizes must sum to 128"


# ─── Kill-chain DAG constraint loader ────────────────────────────────────────
def _load_dag_constraint(num_tags: int = N_CLASSES,
                         penalty: float = -1e4) -> Tuple[torch.Tensor, bool]:
    """
    Build an additive (num_tags, num_tags) transition-constraint matrix from
    configs/schema.py:KILL_CHAIN_DAG.

    Entry [i, j] is 0.0 if micro-state j is a valid successor of micro-state i,
    else ``penalty`` (a large negative number). Added to the CRF transition
    scores during Viterbi decoding so that forbidden transitions are never
    selected — this is what guarantees KCVR = 0%.

    Returns (constraint_matrix, loaded_from_schema). If the schema cannot be
    imported, returns an all-zero matrix (no constraint) so the model still
    runs; ``loaded_from_schema`` reports which path was taken.
    """
    constraint = torch.zeros(num_tags, num_tags, dtype=torch.float32)
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(os.path.dirname(here))
        dataset_dir = os.path.join(project_root, "honeypot_dataset")
        if dataset_dir not in sys.path:
            sys.path.insert(0, dataset_dir)
        from configs.schema import KILL_CHAIN_DAG, LABEL_TO_IDX  # type: ignore

        allowed = torch.zeros(num_tags, num_tags, dtype=torch.bool)
        for src_label, dst_labels in KILL_CHAIN_DAG.items():
            i = LABEL_TO_IDX[src_label]
            for dst_label in dst_labels:
                allowed[i, LABEL_TO_IDX[dst_label]] = True
        constraint = torch.where(
            allowed, torch.zeros_like(constraint),
            torch.full_like(constraint, penalty),
        )
        return constraint, True
    except Exception:  # pragma: no cover - fallback for path/import issues
        return constraint, False


# ─── Linear-chain CRF ────────────────────────────────────────────────────────
class CRF(nn.Module):
    """
    Linear-chain Conditional Random Field.

    Self-contained implementation of the forward (partition) algorithm and
    Viterbi decoding — no external ``pytorch-crf`` dependency. API and maths
    follow Lafferty et al. (2001) / the kmkurn pytorch-crf reference.

    In MT3 the "sequence" is a campaign of sessions: a batch of B sessions is
    treated as one sequence of length B, and the learned transition matrix
    captures kill-chain ordering between consecutive attacker actions.
    """

    def __init__(self, num_tags: int, batch_first: bool = True) -> None:
        super().__init__()
        self.num_tags = num_tags
        self.batch_first = batch_first
        self.start_transitions = nn.Parameter(torch.empty(num_tags))
        self.end_transitions = nn.Parameter(torch.empty(num_tags))
        self.transitions = nn.Parameter(torch.empty(num_tags, num_tags))
        self.reset_parameters()

    def reset_parameters(self) -> None:
        nn.init.uniform_(self.start_transitions, -0.1, 0.1)
        nn.init.uniform_(self.end_transitions, -0.1, 0.1)
        nn.init.uniform_(self.transitions, -0.1, 0.1)

    def forward(self, emissions: torch.Tensor, tags: torch.Tensor,
                mask: Optional[torch.Tensor] = None,
                reduction: str = "token_mean") -> torch.Tensor:
        """Return the (reduced) log-likelihood of ``tags`` given ``emissions``."""
        self._validate(emissions, tags=tags, mask=mask)
        if mask is None:
            mask = torch.ones(emissions.shape[:2], dtype=torch.bool,
                              device=emissions.device)
        if mask.dtype != torch.bool:
            mask = mask.bool()
        if self.batch_first:
            emissions = emissions.transpose(0, 1)
            tags = tags.transpose(0, 1)
            mask = mask.transpose(0, 1)

        numerator = self._compute_score(emissions, tags, mask)
        denominator = self._compute_normalizer(emissions, mask)
        llh = numerator - denominator  # (batch,)

        if reduction == "none":
            return llh
        if reduction == "sum":
            return llh.sum()
        if reduction == "mean":
            return llh.mean()
        if reduction == "token_mean":
            return llh.sum() / mask.float().sum()
        raise ValueError(f"unknown reduction: {reduction}")

    def decode(self, emissions: torch.Tensor,
               mask: Optional[torch.Tensor] = None,
               transitions: Optional[torch.Tensor] = None) -> List[List[int]]:
        """Viterbi decode. ``transitions`` overrides the learned matrix
        (used to inject the kill-chain DAG constraint at inference)."""
        self._validate(emissions, mask=mask)
        if mask is None:
            mask = torch.ones(emissions.shape[:2], dtype=torch.bool,
                              device=emissions.device)
        if mask.dtype != torch.bool:
            mask = mask.bool()
        if self.batch_first:
            emissions = emissions.transpose(0, 1)
            mask = mask.transpose(0, 1)
        return self._viterbi_decode(emissions, mask, transitions)

    # ── internals ────────────────────────────────────────────────────────────
    def _validate(self, emissions: torch.Tensor,
                  tags: Optional[torch.Tensor] = None,
                  mask: Optional[torch.Tensor] = None) -> None:
        if emissions.dim() != 3:
            raise ValueError(
                f"emissions must be 3-D (got {emissions.dim()}-D)")
        if emissions.size(2) != self.num_tags:
            raise ValueError(
                f"expected last dim {self.num_tags}, got {emissions.size(2)}")

    def _compute_score(self, emissions: torch.Tensor, tags: torch.Tensor,
                       mask: torch.Tensor) -> torch.Tensor:
        # emissions: (seq, batch, num_tags); tags/mask: (seq, batch)
        seq_length, batch_size = tags.shape
        mask_f = mask.float()
        idx = torch.arange(batch_size, device=tags.device)

        score = self.start_transitions[tags[0]]
        score = score + emissions[0, idx, tags[0]]
        for i in range(1, seq_length):
            score = score + self.transitions[tags[i - 1], tags[i]] * mask_f[i]
            score = score + emissions[i, idx, tags[i]] * mask_f[i]

        seq_ends = mask.long().sum(dim=0) - 1
        last_tags = tags[seq_ends, idx]
        score = score + self.end_transitions[last_tags]
        return score

    def _compute_normalizer(self, emissions: torch.Tensor,
                            mask: torch.Tensor) -> torch.Tensor:
        seq_length = emissions.size(0)
        score = self.start_transitions + emissions[0]  # (batch, num_tags)
        for i in range(1, seq_length):
            broadcast_score = score.unsqueeze(2)            # (b, tags, 1)
            broadcast_emissions = emissions[i].unsqueeze(1)  # (b, 1, tags)
            next_score = broadcast_score + self.transitions + broadcast_emissions
            next_score = torch.logsumexp(next_score, dim=1)  # (b, tags)
            score = torch.where(mask[i].unsqueeze(1), next_score, score)
        score = score + self.end_transitions
        return torch.logsumexp(score, dim=1)

    def _viterbi_decode(self, emissions: torch.Tensor, mask: torch.Tensor,
                        transitions: Optional[torch.Tensor]) -> List[List[int]]:
        if transitions is None:
            transitions = self.transitions
        seq_length, batch_size = mask.shape

        score = self.start_transitions + emissions[0]  # (batch, num_tags)
        history: List[torch.Tensor] = []
        for i in range(1, seq_length):
            broadcast_score = score.unsqueeze(2)
            broadcast_emission = emissions[i].unsqueeze(1)
            next_score = broadcast_score + transitions + broadcast_emission
            next_score, indices = next_score.max(dim=1)
            score = torch.where(mask[i].unsqueeze(1), next_score, score)
            history.append(indices)

        score = score + self.end_transitions
        seq_ends = mask.long().sum(dim=0) - 1

        best_tags_list: List[List[int]] = []
        for b in range(batch_size):
            _, best_last_tag = score[b].max(dim=0)
            best_tags = [best_last_tag.item()]
            for hist in reversed(history[: seq_ends[b]]):
                best_last_tag = hist[b][best_tags[-1]]
                best_tags.append(best_last_tag.item())
            best_tags.reverse()
            best_tags_list.append(best_tags)
        return best_tags_list


# ─── MT3 sub-modules ─────────────────────────────────────────────────────────
class FeatureGroupTokenizer(nn.Module):
    """Project each of the 6 feature groups into a d_model token.

    Output: (B, 6, d_model) — one token per feature group.
    """

    def __init__(self, group_sizes: List[int], d_model: int) -> None:
        super().__init__()
        self.projections = nn.ModuleList([
            nn.Sequential(
                nn.Linear(size, d_model),
                nn.LayerNorm(d_model),
                nn.GELU(),
            )
            for size in group_sizes
        ])

    def forward(self, groups: List[torch.Tensor]) -> torch.Tensor:
        tokens = [proj(g) for proj, g in zip(self.projections, groups)]
        return torch.stack(tokens, dim=1)  # (B, n_groups, d_model)


class KillChainPhaseEncoding(nn.Module):
    """Kill-chain phase positional encoding.

    Holds a fixed sinusoidal encoding table over the 9 kill-chain phases and a
    learnable soft assignment from the 6 feature-group tokens to those phases.
    Each group token receives a phase-context vector, injecting a structural
    prior about the attack lifecycle. Added to the tokens like a classic
    positional encoding.
    """

    def __init__(self, n_phases: int, n_groups: int, d_model: int) -> None:
        super().__init__()
        self.register_buffer("phase_table",
                             self._sinusoidal(n_phases, d_model))
        # learnable soft assignment: each group token attends over 9 phases
        self.group_to_phase = nn.Parameter(torch.zeros(n_groups, n_phases))

    @staticmethod
    def _sinusoidal(n_phases: int, d_model: int) -> torch.Tensor:
        pe = torch.zeros(n_phases, d_model)
        position = torch.arange(0, n_phases, dtype=torch.float32).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2, dtype=torch.float32)
            * (-math.log(10000.0) / d_model)
        )
        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        return pe

    def forward(self, tokens: torch.Tensor) -> torch.Tensor:
        # soft (n_groups, n_phases) @ (n_phases, d_model) -> (n_groups, d_model)
        weights = torch.softmax(self.group_to_phase, dim=-1)
        phase_enc = weights @ self.phase_table  # (n_groups, d_model)
        return tokens + phase_enc.unsqueeze(0)  # broadcast over batch


class ClassifierHead(nn.Module):
    """Flattened transformer output -> 45 micro-state emission scores."""

    def __init__(self, in_dim: int, n_classes: int, dropout: float) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 512), nn.LayerNorm(512), nn.GELU(), nn.Dropout(dropout),
            nn.Linear(512, 256), nn.LayerNorm(256), nn.GELU(), nn.Dropout(dropout),
            nn.Linear(256, n_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


class HoneypotHead(nn.Module):
    """Flattened transformer output -> 4 deployment-target logits."""

    def __init__(self, in_dim: int, n_targets: int, dropout: float) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(in_dim, 128), nn.GELU(), nn.Dropout(dropout),
            nn.Linear(128, n_targets),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)


# ─── MT3 ─────────────────────────────────────────────────────────────────────
class MT3(nn.Module):
    """MITRE-Aware Temporal Threat Transformer.

    Args:
        d_model: transformer width (default 256).
        n_heads: attention heads (default 8).
        n_layers: transformer encoder layers (default 4, Pre-LN).
        dropout: dropout probability (default 0.1).
        honeypot_loss_weight: weight on the auxiliary honeypot CE loss (0.3).
        constrain_decoding: if True, Viterbi decoding is masked by the
            kill-chain DAG so KCVR = 0% at inference.
    """

    def __init__(self,
                 d_model: int = 256,
                 n_heads: int = 8,
                 n_layers: int = 4,
                 dropout: float = 0.1,
                 honeypot_loss_weight: float = 0.3,
                 constrain_decoding: bool = True) -> None:
        super().__init__()
        self.d_model = d_model
        self.n_groups = N_GROUPS
        self.n_classes = N_CLASSES
        self.honeypot_loss_weight = honeypot_loss_weight
        self.constrain_decoding = constrain_decoding

        # 1. tokenize feature groups
        self.tokenizer = FeatureGroupTokenizer(GROUP_SIZES, d_model)

        # 2. group-type + kill-chain phase encodings
        self.group_type_embedding = nn.Embedding(N_GROUPS, d_model)
        self.phase_encoding = KillChainPhaseEncoding(N_PHASES, N_GROUPS, d_model)

        # 3. Pre-LN transformer encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=n_heads,
            dim_feedforward=4 * d_model,
            dropout=dropout,
            activation="gelu",
            batch_first=True,
            norm_first=True,  # Pre-LN
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=n_layers)

        # 4. heads
        flat_dim = N_GROUPS * d_model  # 6 * 256 = 1536
        self.classifier = ClassifierHead(flat_dim, N_CLASSES, dropout)
        self.honeypot_head = HoneypotHead(flat_dim, N_HONEYPOTS, dropout)

        # 5. CRF over the batch-as-sequence + DAG decode constraint
        self.crf = CRF(N_CLASSES, batch_first=True)
        dag_constraint, dag_loaded = _load_dag_constraint(N_CLASSES)
        self.register_buffer("dag_constraint", dag_constraint)
        self.dag_loaded = dag_loaded

        self.honeypot_loss_fn = nn.CrossEntropyLoss()

        self.register_buffer(
            "_group_ids", torch.arange(N_GROUPS), persistent=False)
        self._init_weights()

    def _init_weights(self) -> None:
        nn.init.normal_(self.group_type_embedding.weight, std=0.02)

    # ── feature splitting ─────────────────────────────────────────────────────
    @staticmethod
    def split_features(x: torch.Tensor) -> List[torch.Tensor]:
        """Split a (B, 128) batch into the 6 feature-group tensors."""
        return [x[:, lo:hi] for lo, hi in GROUP_SLICES]

    # ── encode ────────────────────────────────────────────────────────────────
    def _encode(self, x: torch.Tensor) -> torch.Tensor:
        groups = self.split_features(x)
        tokens = self.tokenizer(groups)                       # (B, 6, d)
        tokens = tokens + self.group_type_embedding(self._group_ids)  # (B, 6, d)
        tokens = self.phase_encoding(tokens)                  # (B, 6, d)
        encoded = self.encoder(tokens)                        # (B, 6, d)
        return encoded.flatten(start_dim=1)                   # (B, 6*d)

    # ── forward ───────────────────────────────────────────────────────────────
    def forward(self, x: torch.Tensor,
                labels: Optional[torch.Tensor] = None,
                honeypot_labels: Optional[torch.Tensor] = None,
                ) -> Tuple[torch.Tensor, torch.Tensor, Optional[torch.Tensor]]:
        """
        Returns ``(emissions, honeypot_logits, loss)``.

        emissions:        (B, 45) micro-state emission scores
        honeypot_logits:  (B, 4)  deployment-target logits
        loss:             scalar multi-task loss if ``labels`` is given, else None
                          loss = CRF_NLL + 0.3 * CE(honeypot)
        """
        flat = self._encode(x)
        emissions = self.classifier(flat)         # (B, 45)
        honeypot_logits = self.honeypot_head(flat)  # (B, 4)

        loss: Optional[torch.Tensor] = None
        if labels is not None:
            # treat the batch as one sequence of length B for the CRF
            emis_seq = emissions.unsqueeze(0)       # (1, B, 45)
            tags_seq = labels.long().unsqueeze(0)   # (1, B)
            mask = torch.ones_like(tags_seq, dtype=torch.bool)
            log_likelihood = self.crf(emis_seq, tags_seq, mask,
                                      reduction="token_mean")
            loss = -log_likelihood
            if honeypot_labels is not None:
                loss = loss + self.honeypot_loss_weight * self.honeypot_loss_fn(
                    honeypot_logits, honeypot_labels.long())

        return emissions, honeypot_logits, loss

    # ── decode ────────────────────────────────────────────────────────────────
    @torch.no_grad()
    def decode(self, x: torch.Tensor) -> List[int]:
        """Viterbi-decode the most likely DAG-valid micro-state sequence for a
        batch of sessions. Returns a list of B micro-state ids."""
        self.eval()
        flat = self._encode(x)
        emissions = self.classifier(flat)          # (B, 45)
        emis_seq = emissions.unsqueeze(0)           # (1, B, 45)
        mask = torch.ones(emis_seq.shape[:2], dtype=torch.bool, device=x.device)

        transitions = None
        if self.constrain_decoding:
            transitions = self.crf.transitions + self.dag_constraint

        paths = self.crf.decode(emis_seq, mask, transitions=transitions)
        return paths[0]  # single sequence -> list of B tags

    # ── utility ───────────────────────────────────────────────────────────────
    def count_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


# ─── self-test ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    torch.manual_seed(0)
    model = MT3()
    x = torch.randn(4, 128)
    y = torch.randint(0, 45, (4,))
    emissions, hp_logits, loss = model(x, labels=y)
    preds = model.decode(x)
    print(f"emissions: {tuple(emissions.shape)}")
    print(f"hp_logits: {tuple(hp_logits.shape)}")
    print(f"crf_loss: {loss.item():.4f}")
    print(f"preds: {preds}")
    print(f"params: {model.count_parameters():,}")
    print(f"dag_constraint loaded from schema: {model.dag_loaded}")
    print("MT3 smoke test PASSED")
