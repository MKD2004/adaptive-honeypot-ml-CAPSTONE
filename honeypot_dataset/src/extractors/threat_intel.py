"""
src/extractors/threat_intel.py
Group E — 14 Threat Intelligence Features (fed to CNN + LSTM)
Fuses live CVSS, EPSS, CISA KEV scores into session telemetry.
This is the defining novelty of the HoneySynth-1M dataset.
"""
from __future__ import annotations
import json, os, time, logging
import numpy as np
import requests
from pathlib import Path

log = logging.getLogger(__name__)
CACHE_PATH = Path("data/processed/ti_cache.json")

TI_FEATURE_NAMES = [
    "cvss_v3_base","cvss_v3_norm","cvss_exploitability","cvss_impact",  # 0-3
    "epss_score","epss_percentile","epss_7d_delta",                      # 4-6
    "is_cisa_kev","kev_days_since_added","cve_age_days",                 # 7-9
    "exploit_db_count","has_metasploit","has_nuclei","cve_refs_count",   # 10-13
]
assert len(TI_FEATURE_NAMES) == 14


class TICache:
    def __init__(self, path: Path = CACHE_PATH):
        self.path  = path
        self._data = {}
        if path.exists():
            with open(path) as f:
                self._data = json.load(f)
            log.info("TI cache: %d entries loaded", len(self._data))

    def get(self, key: str): return self._data.get(key)

    def set(self, key: str, val):
        self._data[key] = val
        if len(self._data) % 100 == 0:
            self._flush()

    def _flush(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(self._data, f)

    def flush(self): self._flush()


_cache = TICache()


def fetch_nvd(cve_id: str) -> dict:
    """Fetch CVSS v3 data from NVD API v2.0 with caching."""
    key = f"nvd_{cve_id}"
    if cached := _cache.get(key):
        return cached

    headers = {"Content-Type": "application/json"}
    if k := os.environ.get("NVD_API_KEY"):
        headers["apiKey"] = k

    try:
        r = requests.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve_id},
            headers=headers,
            timeout=15,
        )
        r.raise_for_status()
        vulns = r.json().get("vulnerabilities", [])
        if not vulns:
            return {}
        metrics = vulns[0]["cve"].get("metrics", {})
        result  = {"base": None, "exploit": None, "impact": None, "pub": None}
        for key2 in ("cvssMetricV31", "cvssMetricV30"):
            if ent := metrics.get(key2):
                d = ent[0].get("cvssData", {})
                result = {
                    "base":    d.get("baseScore"),
                    "exploit": d.get("exploitabilityScore"),
                    "impact":  d.get("impactScore"),
                    "pub":     vulns[0]["cve"].get("published",""),
                }
                break
        _cache.set(key, result)
        delay = 0.6 if os.environ.get("NVD_API_KEY") else 6.0
        time.sleep(delay)
        return result
    except Exception as e:
        log.warning("NVD fetch failed for %s: %s", cve_id, e)
        return {}


def fetch_epss(cve_ids: list[str]) -> dict[str, dict]:
    """Batch-fetch EPSS scores from FIRST.org API."""
    result = {}
    uncached = []
    for cid in cve_ids:
        if c := _cache.get(f"epss_{cid}"):
            result[cid] = c
        else:
            uncached.append(cid)

    for i in range(0, len(uncached), 100):
        batch = uncached[i:i+100]
        try:
            r = requests.get(
                "https://api.first.org/data/1.0/epss",
                params={"cve": ",".join(batch)},
                timeout=15,
            )
            r.raise_for_status()
            for entry in r.json().get("data", []):
                cid = entry["cve"]
                val = {"score": float(entry.get("epss",0)),
                       "pct":   float(entry.get("percentile",0))}
                result[cid] = val
                _cache.set(f"epss_{cid}", val)
        except Exception as e:
            log.warning("EPSS batch failed: %s", e)

    return result


def get_kev_set() -> set[str]:
    """Download CISA KEV catalog and return CVE ID set."""
    if cached := _cache.get("kev_ids"):
        return set(cached)
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json",
            timeout=30,
        )
        r.raise_for_status()
        ids = [v["cveID"] for v in r.json().get("vulnerabilities",[])]
        _cache.set("kev_ids", ids)
        _cache.flush()
        log.info("KEV catalog: %d entries", len(ids))
        return set(ids)
    except Exception as e:
        log.error("KEV fetch failed: %s", e)
        return set()


def extract_threat_intel(session: dict,
                         kev_set: set[str],
                         epss_data: dict) -> np.ndarray:
    """
    Extract 14 threat intelligence features for one session.

    Expected keys:
        associated_cve (str)    : best-matching CVE for this session
        kev_date_added (str)    : 'YYYY-MM-DD' when CVE entered KEV (optional)
        exploit_db_count (int)  : number of ExploitDB entries (optional)
        has_metasploit   (bool)
        has_nuclei       (bool)
    """
    from datetime import datetime, timezone
    eps   = 1e-9
    cve   = str(session.get("associated_cve","") or "")
    now   = datetime(2024,4,15, tzinfo=timezone.utc)   # Time-paradox anchor

    # NVD / CVSS
    nvd        = fetch_nvd(cve) if cve else {}
    cvss_base  = float(nvd.get("base")    or 0.0)
    cvss_norm  = cvss_base / 10.0
    cvss_exp   = float(nvd.get("exploit") or 0.0)
    cvss_imp   = float(nvd.get("impact")  or 0.0)

    # CVE age
    cve_age = 365.0
    if pub := nvd.get("pub",""):
        try:
            pub_dt  = datetime.fromisoformat(pub.replace("Z","+00:00"))
            cve_age = max(0.0, (now - pub_dt).days)
        except: pass

    # EPSS
    epss_score = 0.0; epss_pct = 0.0; epss_delta = 0.0
    if cve and (ep := epss_data.get(cve)):
        epss_score = float(ep.get("score",0))
        epss_pct   = float(ep.get("pct",  0))

    # KEV
    is_kev      = 1.0 if cve in kev_set else 0.0
    kev_days    = 0.0
    if is_kev:
        if kad := session.get("kev_date_added",""):
            try:
                kd = datetime.strptime(str(kad)[:10],"%Y-%m-%d").replace(tzinfo=timezone.utc)
                kev_days = max(0.0, (now - kd).days)
            except: pass

    # Exploit signals
    edb_count     = float(session.get("exploit_db_count", 0) or 0)
    has_msf       = float(bool(session.get("has_metasploit", False)))
    has_nuclei    = float(bool(session.get("has_nuclei",     False)))
    cve_refs      = float(session.get("cve_refs_count", 0) or 0)

    feat = np.array([
        cvss_base, cvss_norm, cvss_exp, cvss_imp,
        epss_score, epss_pct, epss_delta,
        is_kev, kev_days, cve_age,
        edb_count, has_msf, has_nuclei, cve_refs,
    ], dtype=np.float32)

    return np.nan_to_num(feat, nan=0.0, posinf=1e6, neginf=0.0)
