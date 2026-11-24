"""
honeypot_dataset/tests/test_semantic_dedup.py

`extract_semantic_batch` must encode each distinct command text ONCE. Two rows
carrying the same text then get byte-identical embeddings, which closes the
DistilBERT batch-padding watermark described in DATA_INTEGRITY.md section 12c --
a ~3e-6 difference that tracked row provenance and was readable at AUC 0.97.

DistilBERT is not loaded here. The fake encoder below returns a per-text value
plus noise that depends on the batch it landed in, i.e. exactly the defect: if
the function ever stops deduplicating, the duplicate rows diverge and the first
assertion fails.
"""
import sys
import unittest
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "honeypot_dataset"))

from src.extractors import semantic                                # noqa: E402


class _FakePCA:
    def transform(self, emb):
        return emb[:, :semantic.DIM_OUT]


class TestSemanticDedup(unittest.TestCase):
    def setUp(self):
        self.seen = []

        def fake_encode(texts, tok, model, device, batch_size=64):
            self.seen.extend(texts)
            # batch-shape-dependent perturbation, like padding=True produces
            noise = 3e-6 * len(texts)
            return np.array([[hash(t) % 1000 + noise] * 768 for t in texts],
                            dtype=np.float32)

        self._orig = (semantic._load_models, semantic._encode_batch)
        semantic._load_models = lambda: (None, None, "cpu")
        semantic._encode_batch = fake_encode

        import joblib
        self._orig_load = joblib.load
        joblib.load = lambda *a, **k: _FakePCA()
        self.joblib = joblib
        self.pca_path = Path(__file__)          # any existing file; load is faked

    def tearDown(self):
        semantic._load_models, semantic._encode_batch = self._orig
        self.joblib.load = self._orig_load

    def test_duplicate_texts_get_identical_rows(self):
        texts = ["uname -a", "cat /etc/passwd", "uname -a", "wget x"] * 3
        out = semantic.extract_semantic_batch(texts, pca_path=self.pca_path, chunk=2)

        self.assertEqual(out.shape, (12, semantic.DIM_OUT))
        for i, t in enumerate(texts):
            same = [j for j, u in enumerate(texts) if u == t]
            for j in same:
                np.testing.assert_array_equal(out[i], out[j])

    def test_each_distinct_text_encoded_once(self):
        texts = ["a", "b", "a", "c", "b", "a"]
        semantic.extract_semantic_batch(texts, pca_path=self.pca_path, chunk=50)
        self.assertEqual(sorted(self.seen), ["a", "b", "c"])

    def test_row_order_preserved(self):
        texts = ["z", "y", "z"]
        out = semantic.extract_semantic_batch(texts, pca_path=self.pca_path, chunk=50)
        self.assertFalse(np.array_equal(out[0], out[1]))
        np.testing.assert_array_equal(out[0], out[2])

    def test_empty_input(self):
        out = semantic.extract_semantic_batch([], pca_path=self.pca_path)
        self.assertEqual(out.shape, (0, semantic.DIM_OUT))


if __name__ == "__main__":
    unittest.main()
