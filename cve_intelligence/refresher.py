"""
cve_intelligence/refresher.py

Keeps the live system's threat intelligence current.

`cve_intelligence/data/trending_profiles.json` is a committed snapshot (June
2026) -- fine for an offline demo, but it never changes. This module re-runs
the full CVE pipeline (NVD + CISA KEV + FIRST EPSS) in a background thread on
a fixed interval and writes the result to `data/live/` (gitignored), which the
adaptive_honeypot configurator prefers over the snapshot and re-reads as soon
as it changes.

A failed run never replaces good data: the pipeline only writes when it got
CVEs back, and the previous live file (or the snapshot) stays in use.

    from cve_intelligence.refresher import refresher
    refresher.start()            # background loop (run_pipeline does this)
    refresher.refresh_now()      # one synchronous run

    python -m cve_intelligence.refresher          # one-off refresh from the CLI
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cve_intelligence import config

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent / "data"
SNAPSHOT_PROFILES = DATA_DIR / "trending_profiles.json"
LIVE_DIR = DATA_DIR / "live"
LIVE_PROFILES = LIVE_DIR / "trending_profiles.json"
LIVE_META = LIVE_DIR / "trending_profiles.meta.json"
LIVE_CSV = LIVE_DIR / "cve_priority_results.csv"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return None


def active_profiles_path() -> Path:
    """The live file once a refresh has succeeded, else the committed snapshot."""
    return LIVE_PROFILES if LIVE_PROFILES.exists() else SNAPSHOT_PROFILES


def live_age_sec() -> Optional[float]:
    """Seconds since the live intel was generated, or None if there is none."""
    meta = read_json(LIVE_META) or {}
    ts = meta.get("generated_at")
    if not ts:
        return None
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(ts)).total_seconds()
    except ValueError:
        return None


class ThreatIntelRefresher:
    """Background loop around CVEIntelligencePipeline.run()."""

    def __init__(self, interval_hours: float = config.REFRESH_INTERVAL_HOURS) -> None:
        self.interval_sec = max(300.0, float(interval_hours) * 3600.0)
        self._lock = threading.Lock()          # one pipeline run at a time
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.running = False
        self.last_attempt: Optional[str] = None
        self.last_success: Optional[str] = None
        self.last_error: Optional[str] = None
        self.next_run: Optional[str] = None

    # -- one run -------------------------------------------------------------
    def refresh_now(self) -> Dict[str, Any]:
        """Run the pipeline once (blocking). Returns status()."""
        if not self._lock.acquire(blocking=False):
            return {**self.status(), "note": "a refresh is already running"}
        try:
            self.running = True
            self.last_attempt = _utcnow()
            from cve_intelligence.pipeline import CVEIntelligencePipeline

            pipe = CVEIntelligencePipeline(
                output_path=LIVE_PROFILES,
                csv_path=LIVE_CSV,
                include_mitre=False,      # descriptions only; not needed live
                include_exploitdb=False,  # ~50 MB CSV download per run
            )
            result = pipe.run()
            if result.get("profiles"):
                self.last_success = _utcnow()
                self.last_error = None
                logger.info("threat intel refreshed: %d profiles", len(result["profiles"]))
            else:
                self.last_error = "pipeline returned no CVEs (APIs unreachable?); kept previous intel"
                logger.warning(self.last_error)
        except Exception as exc:  # network, parsing, anything: keep old data
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.exception("threat intel refresh failed; keeping previous intel")
        finally:
            self.running = False
            self._lock.release()
        return self.status()

    # -- background loop ------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="threat_intel_refresher")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def trigger(self) -> None:
        """Ask the background loop to refresh now (non-blocking)."""
        self._wake.set()

    def _loop(self) -> None:
        # Refresh at startup only if the live intel is missing or stale.
        age = live_age_sec()
        wait = 0.0 if age is None or age >= self.interval_sec else self.interval_sec - age
        while not self._stop.is_set():
            self.next_run = datetime.fromtimestamp(time.time() + wait, tz=timezone.utc).isoformat()
            self._wake.wait(timeout=wait)
            self._wake.clear()
            if self._stop.is_set():
                break
            self.refresh_now()
            wait = self.interval_sec

    # -- reporting ------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        return {
            "loop_started": bool(self._thread and self._thread.is_alive()),
            "running": self.running,
            "interval_hours": round(self.interval_sec / 3600.0, 2),
            "last_attempt": self.last_attempt,
            "last_success": self.last_success,
            "last_error": self.last_error,
            "next_run": self.next_run,
        }


def snapshot() -> Dict[str, Any]:
    """Which intel is in use, how fresh it is, and what each source returned."""
    path = active_profiles_path()
    live = path == LIVE_PROFILES
    profiles: List[dict] = read_json(path) or []
    meta = read_json(LIVE_META) if live else None
    age = live_age_sec() if live else None
    return {
        "source": "live" if live else "snapshot",
        "profiles_path": str(path),
        "generated_at": (meta or {}).get("generated_at"),
        "age_sec": round(age, 1) if age is not None else None,
        "stale": (age is None) or age > refresher.interval_sec * 2,
        "meta": meta,
        "refresher": refresher.status(),
        "profile_count": len(profiles),
        "profiles": profiles,
    }


# Module-level singleton, shared by run_pipeline (starts the loop) and the API.
refresher = ThreatIntelRefresher()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s")
    st = refresher.refresh_now()
    print(json.dumps({k: v for k, v in snapshot().items() if k != "profiles"}, indent=2))
    raise SystemExit(0 if st.get("last_success") else 1)
