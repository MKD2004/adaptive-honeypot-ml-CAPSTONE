"""
cve_intelligence/clients/cveorg.py

CVE.org API Client (Fallback for NVD)
═════════════════════════════════════
The CVE Program (cve.org) runs its own REST API independently of NIST/NVD.
Since the NVD backlog crisis of early 2024, CVE.org is often the only source
with timely CVE records.

This client serves as a fallback when NVD returns 0 results.

API docs: https://cveawg.mitre.org/api-docs
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple

import requests

from cve_intelligence import config

logger = logging.getLogger(__name__)

_CVEORG_BASE = "https://cveawg.mitre.org/api/cve"


def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is None:
            return default
    return d


def _extract_cvss_from_cveorg(cve: dict) -> Tuple[Optional[float], Optional[str]]:
    metrics = _safe_get(cve, "containers", "cna", "metrics", default=[])
    if not isinstance(metrics, list):
        metrics = []
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            if key in m:
                score = m[key].get("baseScore")
                if score is not None:
                    ver = key.replace("cvssV", "").replace("_", ".")
                    return float(score), ver
    return None, None


def _extract_cwe_from_cveorg(cve: dict) -> Optional[str]:
    problem_types = _safe_get(cve, "containers", "cna", "problemTypes", default=[])
    if not isinstance(problem_types, list):
        return None
    for pt in problem_types:
        for desc in pt.get("descriptions", []):
            val = desc.get("cweId", "")
            if val.startswith("CWE-"):
                return val
    return None


def _extract_description_from_cveorg(cve: dict) -> str:
    descs = _safe_get(cve, "containers", "cna", "descriptions", default=[])
    if not isinstance(descs, list):
        return ""
    for d in descs:
        if d.get("lang", "en").startswith("en"):
            return d.get("value", "").strip()
    if descs:
        return descs[0].get("value", "").strip()
    return ""


class CVEOrgClient:
    """
    Fetches CVEs from the CVE.org (MITRE CVE Services) REST API.
    Used as a fallback when NVD is unreachable or returns empty results.
    """

    def __init__(self) -> None:
        self._base_url = _CVEORG_BASE
        self._delay = 1.0

    def fetch_recent(self, days: int = 7, max_results: int = 500) -> List[dict]:
        """
        Fetch recently modified CVEs from CVE.org.

        CVE.org API uses 'timeModified.gt' / 'timeModified.lt' params
        with ISO 8601 format. Falls back to fetching individual KEV CVEs
        if the bulk query fails.
        """
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=days)

        time_start = start.strftime("%Y-%m-%dT%H:%M:%S")
        time_end = end.strftime("%Y-%m-%dT%H:%M:%S")

        logger.info("CVE.org: fetching CVEs modified %s to %s", time_start[:10], time_end[:10])

        all_cves = []

        # Try the bulk query with correct param names
        for param_style in [
            {"timeModified.gt": time_start, "timeModified.lt": time_end},
            {"time_modified.gt": time_start, "time_modified.lt": time_end},
        ]:
            try:
                resp = requests.get(
                    self._base_url,
                    params=param_style,
                    timeout=config.REQUEST_TIMEOUT,
                    headers={"Accept": "application/json"},
                )

                if resp.status_code in (403, 429):
                    logger.warning("CVE.org rate-limited (%d). Waiting 10s.", resp.status_code)
                    time.sleep(10)
                    continue

                if resp.status_code == 400:
                    logger.debug("CVE.org param style %s returned 400, trying next.", list(param_style.keys()))
                    continue

                resp.raise_for_status()
                data = resp.json()

                cves = data.get("cveRecords", data.get("vulnerabilities", []))
                if not cves and isinstance(data, list):
                    cves = data

                if cves:
                    all_cves.extend(cves)
                    logger.info("CVE.org: fetched %d records.", len(all_cves))
                    break

            except requests.exceptions.RequestException as exc:
                logger.warning("CVE.org bulk query failed: %s", exc)
            except ValueError as exc:
                logger.warning("CVE.org JSON error: %s", exc)

        logger.info("CVE.org fetch complete: %d total records.", len(all_cves))
        return all_cves[:max_results]

    def fetch_by_ids(self, cve_ids: List[str]) -> List[dict]:
        """Fetch specific CVEs by ID from CVE.org."""
        results = []
        for cve_id in cve_ids:
            try:
                resp = requests.get(
                    f"{self._base_url}/{cve_id}",
                    timeout=config.REQUEST_TIMEOUT,
                    headers={"Accept": "application/json"},
                )
                if resp.status_code == 200:
                    results.append(resp.json())
                else:
                    logger.debug("CVE.org: %s returned %d", cve_id, resp.status_code)
                time.sleep(self._delay)
            except requests.exceptions.RequestException as exc:
                logger.warning("CVE.org fetch %s failed: %s", cve_id, exc)
        logger.info("CVE.org: fetched %d / %d individual CVEs.", len(results), len(cve_ids))
        return results

    def parse(self, raw_cves: List[dict]) -> List[dict]:
        """
        Parse CVE.org response format into the same schema as NVDClient.parse().
        This ensures downstream pipeline stages work unchanged.
        """
        records = []
        for item in raw_cves:
            cve_meta = item.get("cveMetadata", item.get("cve", {}))
            if not cve_meta and "cveId" not in item:
                continue

            cve_id = cve_meta.get("cveId", cve_meta.get("id", item.get("cveId", "UNKNOWN")))
            pub_date = cve_meta.get("datePublished", cve_meta.get("published", ""))
            mod_date = cve_meta.get("dateUpdated", cve_meta.get("lastModified", ""))
            state = cve_meta.get("state", "PUBLISHED")

            description = _extract_description_from_cveorg(item)
            cvss_score, cvss_ver = _extract_cvss_from_cveorg(item)
            cwe = _extract_cwe_from_cveorg(item)

            records.append({
                "cve_id": cve_id,
                "published": pub_date,
                "last_modified": mod_date,
                "vuln_status": state,
                "description": description,
                "cvss_score": cvss_score,
                "cvss_version": cvss_ver,
                "cwe": cwe,
                "references": [],
            })

        logger.info("CVE.org parse: extracted %d records.", len(records))
        return records

    def fetch_kev_details(self, kev_cve_ids: List[str]) -> List[dict]:
        """
        Fetch full CVE details for KEV-listed CVEs from CVE.org.
        This is the most valuable use case — KEV CVEs that NVD hasn't scored.
        """
        logger.info("CVE.org: fetching details for %d KEV CVEs.", len(kev_cve_ids))
        raw = self.fetch_by_ids(kev_cve_ids)
        return self.parse(raw)
