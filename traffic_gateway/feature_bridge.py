"""
traffic_gateway/feature_bridge.py

Turns one parsed session dict into a 128-d MT3 input and runs inference.
Owns the two things that are easy to get wrong at the boundary: live features
come out of the extractors RAW so the frozen scaler MUST be applied here (the
opposite of data/final/, see ERRORS.md), and KEV/EPSS are fetched once and
cached for an hour rather than per session.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from .ext_paths import DATA_FINAL, DATA_PROCESSED, REPO_ROOT, ensure_paths, pin_ti_cache

log = logging.getLogger("traffic_gateway.feature_bridge")

# transformers prints a multi-line weight-load report per model load, and the
# HF hub client logs every cache-validation request; one line in our own log is
# enough for both.
for _noisy in ("transformers", "httpx", "httpcore", "huggingface_hub", "filelock"):
    logging.getLogger(_noisy).setLevel(logging.ERROR)

MT3_CKPT = REPO_ROOT / "ml_analytics" / "artifacts" / "mt3_full_d256" / "best.pt"
SEMANTIC_PCA = DATA_PROCESSED / "semantic_pca.pkl"

TI_CACHE_TTL_SEC = 3600.0   # KEV + EPSS refresh interval (Step 3c: "cache for 1 hour")

PHASE_NAMES = [
    "Reconnaissance", "Initial Access", "Execution", "Discovery",
    "Privilege Escalation", "Persistence", "Defense Evasion",
    "Lateral Movement", "Exfiltration",
]

# Which emulator a phase's traffic belongs on. The gateway only runs an SSH
# (Cowrie) honeypot today; the web/db targets exist in CONFIG.HONEYPOT_TARGETS.
_PROTO_TO_HONEYPOT = {
    "ssh": "SSH_HONEYPOT",
    "http": "WEB_HONEYPOT",
    "https": "WEB_HONEYPOT",
    "web": "WEB_HONEYPOT",
    "mysql": "DB_HONEYPOT",
    "postgres": "DB_HONEYPOT",
}
_PORT_TO_HONEYPOT = {
    22: "SSH_HONEYPOT", 2222: "SSH_HONEYPOT", 2022: "SSH_HONEYPOT",
    80: "WEB_HONEYPOT", 443: "WEB_HONEYPOT", 8080: "WEB_HONEYPOT",
    8000: "WEB_HONEYPOT", 8443: "WEB_HONEYPOT",
    3306: "DB_HONEYPOT", 5432: "DB_HONEYPOT", 27017: "DB_HONEYPOT",
    6379: "DB_HONEYPOT",
}


class ThreatIntelCache:
    """KEV set + EPSS scores, refreshed at most once per TTL."""

    def __init__(self, ttl: float = TI_CACHE_TTL_SEC) -> None:
        self.ttl = ttl
        self._kev: set = set()
        self._epss: Dict[str, dict] = {}
        self._fetched_at = 0.0

    @property
    def age_sec(self) -> float:
        return time.time() - self._fetched_at if self._fetched_at else float("inf")

    def prefetch(self, cves: Optional[List[str]] = None, force: bool = False) -> Dict[str, Any]:
        """Fetch (or refresh) the KEV catalog and any EPSS scores we need."""
        ensure_paths()
        pin_ti_cache()
        from src.extractors.threat_intel import fetch_epss, get_kev_set  # type: ignore

        if force or self.age_sec > self.ttl:
            try:
                self._kev = get_kev_set()
            except Exception as exc:                      # offline / API down
                log.warning("KEV fetch failed (%s); continuing with %d cached ids",
                            exc, len(self._kev))
            self._fetched_at = time.time()

        wanted = [c for c in (cves or []) if c and c not in self._epss]
        if wanted:
            try:
                self._epss.update(fetch_epss(wanted))
            except Exception as exc:
                log.warning("EPSS fetch failed (%s); scores default to 0", exc)

        return {"kev_count": len(self._kev), "epss_count": len(self._epss),
                "age_sec": round(self.age_sec, 1)}

    @property
    def kev_set(self) -> set:
        return self._kev

    @property
    def epss_data(self) -> Dict[str, dict]:
        return self._epss


class SemanticEncoder:
    """Group D (30 dims). Loads DistilBERT + the fitted PCA ONCE and reuses them.

    src/extractors/semantic.py's public `extract_semantic_batch()` calls
    `_load_models()` internally, so it re-reads DistilBERT from disk on every
    invocation -- fine for one batched offline pass over the dataset, far too
    slow for a per-session live loop. This holds the tokenizer/model/PCA and
    calls the extractor's own `_encode_batch`, so the arithmetic is identical
    while the load happens once.

    If DistilBERT or the PCA is unavailable the block is zero-filled and
    `available` goes False -- inference still runs, but 30 of 128 features are
    dead, so the caller surfaces the degraded state instead of silently
    mispredicting.
    """

    def __init__(self, pca_path: Path = SEMANTIC_PCA) -> None:
        self.pca_path = Path(pca_path)
        self.available: Optional[bool] = None
        self._reason = ""
        self._tok = self._model = self._device = self._pca = None
        self._encode_batch = None

    def load(self) -> bool:
        if self.available is not None:
            return self.available
        ensure_paths()
        try:
            import joblib

            if not self.pca_path.exists():
                raise FileNotFoundError(f"semantic PCA missing: {self.pca_path}")
            # joblib, not pickle -- every .pkl this pipeline writes is a joblib
            # dump and pickle.load raises "invalid load key" on them (ERRORS.md).
            self._pca = joblib.load(self.pca_path)
            from src.extractors import semantic as _sem  # type: ignore

            self._tok, self._model, self._device = _sem._load_models()
            self._encode_batch = _sem._encode_batch
            probe = self._project(["uname -a"])
            if probe.shape != (1, 30):
                raise ValueError(f"unexpected semantic shape {probe.shape}")
            self.available = True
            log.info("semantic encoder ready (DistilBERT on %s, PCA %s)",
                     self._device, self.pca_path.name)
        except Exception as exc:
            self._reason = f"{type(exc).__name__}: {exc}"
            log.warning("semantic (Group D) unavailable -- zero-filling 30 features: %s",
                        self._reason)
            self.available = False
        return self.available

    def _project(self, texts: List[str]) -> np.ndarray:
        emb768 = self._encode_batch(texts, self._tok, self._model, self._device)
        return self._pca.transform(emb768).astype(np.float32)

    def encode(self, text: str) -> np.ndarray:
        if not self.load():
            return np.zeros(30, dtype=np.float32)
        try:
            return self._project([text or ""])[0].astype(np.float32)
        except Exception as exc:
            log.warning("semantic encode failed (%s); zero-filling", exc)
            return np.zeros(30, dtype=np.float32)

    def status(self) -> Dict[str, Any]:
        return {"available": bool(self.available), "reason": self._reason,
                "device": self._device, "pca_path": str(self.pca_path)}


class MT3Inference:
    """Loads the trained MT3 checkpoint and predicts one session at a time."""

    def __init__(self, ckpt_path: Path = MT3_CKPT, device: str = "auto") -> None:
        self.ckpt_path = Path(ckpt_path)
        self.device = device
        self.model = None
        self.n_params = 0
        self.meta: Dict[str, Any] = {}
        self.label_names: List[str] = []
        self._scaler = None

    def load(self) -> "MT3Inference":
        ensure_paths()
        import torch  # noqa: F401  (import cost paid once, up front)
        from ml_analytics.mt3_pipeline import data as mt3_data
        from ml_analytics.mt3_pipeline.evaluate import load_model, pick_device

        if not self.ckpt_path.exists():
            raise FileNotFoundError(f"MT3 checkpoint not found: {self.ckpt_path}")

        self.device = pick_device(self.device)
        self.model, ckpt = load_model(self.ckpt_path, device=self.device)
        self.n_params = self.model.count_parameters()
        self.label_names = mt3_data.load_label_names()
        # RAW live features must go through the frozen scaler (ERRORS.md: the
        # data/final/ arrays are already scaled, live sessions are not).
        self._scaler = mt3_data.load_scaler(DATA_FINAL)
        self.meta = {
            "checkpoint": str(self.ckpt_path),
            "device": self.device,
            "n_params": self.n_params,
            "best_val_macro_f1": ckpt.get("best_val_macro_f1"),
            "best_epoch": ckpt.get("best_epoch"),
            "model_kwargs": ckpt.get("model_kwargs", {}),
        }
        log.info("MT3 loaded: %s params on %s (val macro-F1 %.4f)", f"{self.n_params:,}",
                 self.device, float(ckpt.get("best_val_macro_f1") or 0.0))
        return self

    def scale(self, x_raw: np.ndarray) -> np.ndarray:
        x = np.asarray(x_raw, dtype=np.float64).reshape(1, -1)
        return self._scaler.transform(x).astype(np.float32)

    def predict(self, x_raw: np.ndarray) -> Dict[str, Any]:
        """RAW 128-d vector -> micro-state / phase / confidence."""
        if self.model is None:
            raise RuntimeError("MT3Inference.load() must be called first")
        import torch

        xs = self.scale(x_raw)
        with torch.no_grad():
            emissions, hp_logits, _ = self.model(
                torch.from_numpy(xs).to(self.device)
            )
            probs = torch.softmax(emissions.float(), dim=-1)[0].cpu().numpy()
            phase_probs = torch.softmax(hp_logits.float(), dim=-1)[0].cpu().numpy()

        idx = int(probs.argmax())
        label = self.label_names[idx] if idx < len(self.label_names) else f"class_{idx}"
        # The phase is derived from the micro-state (the DAG's own mapping); the
        # auxiliary head is reported alongside as a consistency signal only.
        from ml_analytics.mt3_pipeline.data import IDX_TO_PHASE

        phase = int(IDX_TO_PHASE[idx])
        top3 = np.argsort(probs)[::-1][:3]
        return {
            "micro_state": label,
            "micro_state_id": idx,
            "phase": phase,
            "phase_name": PHASE_NAMES[phase],
            "confidence": round(float(probs[idx]), 4),
            "aux_phase_head": int(phase_probs.argmax()),
            "aux_phase_agrees": bool(int(phase_probs.argmax()) == phase),
            "top3": [
                {"micro_state": self.label_names[int(i)], "p": round(float(probs[int(i)]), 4)}
                for i in top3
            ],
        }


class TrainingDistribution:
    """How far a scaled feature vector sits from MT3's training data.

    Mahalanobis distance against a stratified sample of `X_train`, reported on
    every result so a verdict can be seen for what it is. It is an HONESTY
    SIGNAL, deliberately NOT a gate -- see the numbers below for why.

    Measured 2026-11-04, and the reason this exists:

        X_train rows          p50   5.5   p95  15.4
        held-out test_real    p50   3.5   p95   7.4   (inside -- the measure is sound)
        LIVE Cowrie sessions        425 - 642

    A live session produced by the running pipeline is roughly 75x further from
    the training distribution than the held-out test data is. Both benign and
    hostile live sessions sit out there, so this cannot separate them and must not
    be used to decide anything -- gating on it would suppress every live verdict,
    including real attacks. What it does say, truthfully, is that the published
    macro-F1 describes data that does not look like what the live system feeds
    the model. See 02-11-2026 FINDINGS.md #1 and HONEYPOT_AUDIT.md PART 11.
    """

    def __init__(self, stride: int = 60, ridge: float = 1e-4) -> None:
        self.stride, self.ridge = stride, ridge
        self._mu = self._inv = None
        self._p95: Optional[float] = None
        self._failed = False

    def _load(self) -> bool:
        if self._mu is not None:
            return True
        if self._failed:
            return False
        try:
            path = DATA_FINAL / "X_train.npy"
            X = np.load(path, mmap_mode="r")
            sub = np.asarray(X[::self.stride], dtype=np.float64)
            self._mu = sub.mean(axis=0)
            cov = np.cov(sub, rowvar=False) + np.eye(sub.shape[1]) * self.ridge
            self._inv = np.linalg.inv(cov)
            d = sub[:3000] - self._mu
            ref = np.sqrt(np.maximum(np.einsum("ij,jk,ik->i", d, self._inv, d), 0.0))
            self._p95 = float(np.percentile(ref, 95))
            log.info("training-distribution reference built from %s (p95 %.1f)",
                     path.name, self._p95)
        except Exception as exc:
            log.warning("training-distribution reference unavailable (%s); "
                        "ood_distance will be None", exc)
            self._failed = True
            return False
        return True

    def distance(self, x_scaled: np.ndarray) -> Optional[float]:
        """Mahalanobis distance of one SCALED vector, or None if unavailable."""
        if not self._load():
            return None
        try:
            d = np.asarray(x_scaled, dtype=np.float64).reshape(-1) - self._mu
            return round(float(np.sqrt(max(d @ self._inv @ d, 0.0))), 2)
        except Exception:
            return None

    @property
    def p95(self) -> Optional[float]:
        self._load()
        return self._p95


def honeypot_target_for(session: Dict[str, Any]) -> str:
    """Which emulator this session belongs to, from its protocol/port."""
    proto = str(session.get("protocol", "") or "").lower()
    if proto in _PROTO_TO_HONEYPOT:
        return _PROTO_TO_HONEYPOT[proto]
    try:
        port = int(session.get("dst_port", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    return _PORT_TO_HONEYPOT.get(port, "SSH_HONEYPOT")


# Sources whose text Group D's PCA was actually fitted on. Anything else gets a
# zero-filled semantic block -- Phase 1b's decision, see group_d_mode() below.
_SEMANTIC_IN_DOMAIN_SOURCES = frozenset({"cowrie_real", "cowrie", "cowrie_synth"})


def group_d_mode(session: Dict[str, Any]) -> str:
    """"live" or "zero-filled" for this session's semantic block (features 76-105).

    Phase 1b (DECISIONS.md 2026-11-04) decided to zero-fill Group D for every
    non-SSH source rather than push its text through the shell-fitted PCA. The
    measurements behind it:

      - the 30 shell-fitted axes keep 90.8% of shell-command variance but only
        73.6% of HTTP's, 64.1% of SQL's and 71.4% of credential text's;
      - a zero-fill, AFTER the frozen scaler, lands at mean 0.368 sigma with no
        dimension past 2 sigma -- nearer the centre of the training cloud than
        94.65% of real rows. It is in-distribution; off-domain text is not.

    Returning a mode rather than a bool so the result line can distinguish
    "DistilBERT missing" from "deliberately off for this source", which
    DECISIONS.md flagged as owed.
    """
    src = str(session.get("source", "") or "").strip().lower()
    return "live" if src in _SEMANTIC_IN_DOMAIN_SOURCES else "zero-filled"


def extract_features(session: Dict[str, Any], ti: ThreatIntelCache,
                     semantic: SemanticEncoder) -> np.ndarray:
    """One parsed session dict -> RAW 128-d feature vector (unscaled).

    Group D is zero-filled for out-of-domain sources; see group_d_mode().
    """
    ensure_paths()
    from src.extractors.pipeline import extract_all  # type: ignore

    cve = str(session.get("associated_cve", "") or "")
    if cve:
        ti.prefetch([cve])
    if group_d_mode(session) == "live":
        sem = semantic.encode(str(session.get("command_text", "") or ""))
    else:
        sem = np.zeros(30, dtype=np.float32)
    x = extract_all(session, ti.kev_set, ti.epss_data, sem)
    return np.clip(np.nan_to_num(x, nan=0.0, posinf=1e6, neginf=0.0), -100.0, 1e6)


def kcvr_valid(sequence: Any) -> Optional[bool]:
    """Kill-Chain Validity Rate: is every transition legal under KILL_CHAIN_DAG?

    Returns None for a sequence too short to have a transition (undefined, not
    False). MT3 was never trained on the DAG (DECISIONS.md) -- this measures the
    observed session, it does not constrain the prediction.
    """
    ensure_paths()
    from configs.schema import KILL_CHAIN_DAG  # type: ignore

    if isinstance(sequence, str):
        states = [s for s in sequence.split(",") if s]
    else:
        states = [s for s in (sequence or []) if s]
    # collapse self-repeats: "A,A,A" is one dwell, not two transitions
    collapsed: List[str] = []
    for s in states:
        if not collapsed or collapsed[-1] != s:
            collapsed.append(s)
    if len(collapsed) < 2:
        return None
    return all(
        collapsed[i + 1] in KILL_CHAIN_DAG.get(collapsed[i], set())
        for i in range(len(collapsed) - 1)
    )
