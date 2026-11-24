"""
src/extractors/semantic.py
Group D — 30 Semantic Features via DistilBERT + PCA
Pre-computes command-text embeddings once; stores 30-d projections.
"""
from __future__ import annotations
import logging
import numpy as np
from pathlib import Path

log = logging.getLogger(__name__)
PCA_PATH   = Path("data/processed/semantic_pca.pkl")
MODEL_NAME = "distilbert-base-uncased"
DIM_OUT    = 30
SEMANTIC_FEATURE_NAMES = [f"bert_proj_{i:02d}" for i in range(DIM_OUT)]


def _load_models():
    import torch
    from transformers import DistilBertModel, DistilBertTokenizerFast
    device = "cuda" if torch.cuda.is_available() else "cpu"
    tok   = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)
    model = DistilBertModel.from_pretrained(MODEL_NAME).to(device).eval()
    log.info("DistilBERT loaded on %s", device)
    return tok, model, device


def _encode_batch(texts, tok, model, device, batch_size=64) -> np.ndarray:
    import torch
    all_cls = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        enc   = tok(batch, padding=True, truncation=True,
                    max_length=128, return_tensors="pt").to(device)
        with torch.no_grad():
            out = model(**enc)
        all_cls.append(out.last_hidden_state[:, 0, :].cpu().numpy())
    return np.vstack(all_cls)


def fit_pca(texts: list[str], save_path: Path = PCA_PATH) -> "PCA":
    """Fit PCA on training corpus. Call ONCE on training split only."""
    import joblib
    from sklearn.decomposition import PCA
    tok, model, device = _load_models()
    emb = _encode_batch(texts, tok, model, device)
    pca = PCA(n_components=DIM_OUT, random_state=42).fit(emb)
    log.info("PCA variance explained: %.2f%%", pca.explained_variance_ratio_.sum()*100)
    save_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pca, save_path)
    return pca


def extract_semantic_batch(texts: list[str],
                           pca_path: Path = PCA_PATH,
                           chunk: int = 50_000) -> np.ndarray:
    """
    Encode a list of command texts -> (N, 30) float32 array.
    Loads cached PCA; call fit_pca() first on training data.

    **Each DISTINCT text is encoded exactly once** and the result is scattered
    back to every row that carries it, so two rows with the same command text
    get byte-identical embeddings. Before this, `padding=True` made a batch's
    padded length decide which GPU kernels ran, so the same string embedded
    ~3e-6 differently depending on which batch it landed in -- and because real
    rows spanned many batches while generated rows did not, that difference was
    a *provenance watermark* a classifier read at AUC 0.97 (DATA_INTEGRITY.md
    section 12c). Dedup removes the channel by construction, and on the
    1,749,809-row build it is also 2.3x less encoding (761,142 distinct texts).

    Encodes and projects in chunks of `chunk` distinct texts. `_encode_batch`
    keeps every 768-dim CLS vector until it vstacks them, so the full-corpus
    call needed N*768*4 bytes twice over -- 10.75 GB for that build, on a 15 GB
    machine. The notebook was OS-killed twice with no traceback before this was
    traced. Projecting each chunk to 30 dims immediately caps the 768-dim
    working set at one chunk (~150 MB).

    Still NOT bit-for-bit across different inputs: the padded length of a chunk
    depends on which distinct texts share it, so the same text in a different
    corpus can shift by ~3e-6 (values of scale ~0.44). That residual is now
    uncorrelated with row provenance, which is what mattered. The live path
    (`traffic_gateway.feature_bridge.SemanticEncoder`) encodes one text per
    batch and so sits at its own offset of that size -- pre-existing, and the
    reason not to treat group D as high-precision.
    """
    import joblib
    if not pca_path.exists():
        raise FileNotFoundError(
            f"PCA not found at {pca_path}. Run fit_pca() on training data first.")
    pca = joblib.load(pca_path)
    tok, model, device = _load_models()

    first_seen: dict[str, int] = {}
    for t in texts:
        first_seen.setdefault(t, len(first_seen))
    uniq = list(first_seen)
    inverse = np.fromiter((first_seen[t] for t in texts), dtype=np.int64,
                          count=len(texts))
    log.info("semantic: %d distinct texts of %d rows", len(uniq), len(texts))

    parts = []
    for i in range(0, len(uniq), chunk):
        emb768 = _encode_batch(uniq[i:i + chunk], tok, model, device)
        parts.append(pca.transform(emb768).astype(np.float32))
        del emb768
        log.info("semantic: %d / %d distinct texts", min(i + chunk, len(uniq)), len(uniq))
    if not parts:
        return np.zeros((0, DIM_OUT), dtype=np.float32)
    return np.vstack(parts)[inverse]


def extract_semantic_single(text: str, pca_path: Path = PCA_PATH) -> np.ndarray:
    """Single-session inference helper for the gateway pipeline."""
    return extract_semantic_batch([text], pca_path)[0]
