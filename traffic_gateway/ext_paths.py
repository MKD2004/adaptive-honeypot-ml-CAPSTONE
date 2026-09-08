"""
traffic_gateway/ext_paths.py

Makes the sibling top-level packages importable from inside traffic_gateway.
`honeypot_dataset/` has no __init__.py anywhere (it relies on PEP-420 namespace
packages plus a sys.path entry, exactly like src/extractors/pipeline.py does),
so `configs.schema` / `src.extractors.*` only resolve once honeypot_dataset/ is
on sys.path; `ml_analytics` needs the repo root on sys.path.  Import-time
side-effect free apart from the two sys.path inserts.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_ROOT = REPO_ROOT / "honeypot_dataset"
DATA_PROCESSED = DATASET_ROOT / "data" / "processed"
DATA_FINAL = DATASET_ROOT / "data" / "final"

_done = False


def ensure_paths() -> None:
    """Idempotently put REPO_ROOT and honeypot_dataset/ on sys.path."""
    global _done
    if _done:
        return
    for p in (REPO_ROOT, DATASET_ROOT):
        s = str(p)
        if s not in sys.path:
            sys.path.insert(0, s)
    _done = True


def pin_ti_cache() -> None:
    """Repoint the threat-intel cache at the real file.

    src/extractors/threat_intel.py hardcodes a *relative* CACHE_PATH
    ("data/processed/ti_cache.json"), which resolves against the CWD -- so
    running the gateway from the repo root would miss the populated cache under
    honeypot_dataset/.  Rebinding the module-level singleton at runtime fixes
    that without editing the (off-limits) extractor.
    """
    ensure_paths()
    from src.extractors import threat_intel  # type: ignore

    target = DATA_PROCESSED / "ti_cache.json"
    if Path(getattr(threat_intel._cache, "path", "")).resolve() != target.resolve():
        threat_intel._cache = threat_intel.TICache(target)
