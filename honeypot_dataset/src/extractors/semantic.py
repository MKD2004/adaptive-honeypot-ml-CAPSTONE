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
                           pca_path: Path = PCA_PATH) -> np.ndarray:
    """
    Encode a list of command texts → (N, 30) float32 array.
    Loads cached PCA; call fit_pca() first on training data.
    """
    import joblib
    if not pca_path.exists():
        raise FileNotFoundError(
            f"PCA not found at {pca_path}. Run fit_pca() on training data first.")
    pca = joblib.load(pca_path)
    tok, model, device = _load_models()
    emb768 = _encode_batch(texts, tok, model, device)   # (N, 768)
    emb30  = pca.transform(emb768).astype(np.float32)   # (N, 30)
    return emb30


def extract_semantic_single(text: str, pca_path: Path = PCA_PATH) -> np.ndarray:
    """Single-session inference helper for the gateway pipeline."""
    return extract_semantic_batch([text], pca_path)[0]
