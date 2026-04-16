"""
cve_intelligence/clients/nvd.py

NVD API 2.0 Client
══════════════════
Responsible exclusively for fetching and parsing CVEs from the
National Vulnerability Database REST API v2.0.

Fixes applied vs. notebook:
  1. API key read from environment via config.NVD_API_KEY
  2. Date formatting uses strict UTC + Z designator (no hardcoded offsets)
  3. Rate-limit delay is keyed vs. un-keyed (0.6 s vs. 6 s)
  4. Separate helper functions for safe nested dict access and field extraction
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Tuple

import requests

from cve_intelligence import config

logger = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────
def _safe_get(d: Any, *keys: str, default: Any = None) -> Any:
    """Safely traverse a nested dict without raising KeyError."""
    for k in keys:
        if not isinstance(d, dict):
            return default
        d = d.get(k, default)
        if d is None:
            return default
    return d


def _extract_cvss_score(cve_item: dict) -> Tuple[Optional[float], Optional[str]]:
    """
    Extract the best available CVSS base score.
    Preference order: v3.1 > v3.0 > v2.0.

    Returns:
        (score, version_string) or (None, None) if unavailable.
    """
    metrics = _safe_get(cve_item, "cve", "metrics", default={})
    for key, ver in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2",  "2.0"),
    ]:
        entries = metrics.get(key, [])
        if entries:
            score = _safe_get(entries[0], "cvssData", "baseScore", default=None)
            if score is not None:
                return float(score), ver
    return None, None


def _extract_cwe(cve_item: dict) -> Optional[str]:
    """
    Extract the first CWE identifier from the weaknesses list.

    Returns:
        e.g. 'CWE-89', or None if not present.
    """
    weaknesses = _safe_get(cve_item, "cve", "weaknesses", default=[])
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                return val
    return None


def _extract_description(cve_item: dict) -> str:
    """Extract English-language description text."""
    descs = _safe_get(cve_item, "cve", "descriptions", default=[])
    for d in descs:
        if d.get("lang", "") == "en":
            return d.get("value", "").strip()
    return ""


def _extract_references(cve_item: dict, max_refs: int = 3) -> List[str]:
    """Extract up to *max_refs* reference URLs."""
    refs = _safe_get(cve_item, "cve", "references", default=[])
    return [r.get("url", "") for r in refs][:max_refs]


def _format_nvd_date(dt: datetime) -> str:
    """
    Format a datetime object into the NVD API date string.

    Fix: Uses strict UTC with the 'Z' designator instead of a
    hardcoded '-05:00' timezone offset.

    Example output: '2024-01-15T00:00:00.000Z'
    """
    utc_dt = dt.astimezone(timezone.utc)
    return utc_dt.strftime(config.NVD_DATE_FORMAT)


# ── Main client class ─────────────────────────────────────────────────────────
class NVDClient:
    """
    Fetches CVEs from the NVD REST API v2.0.

    Authentication:
        Set the NVD_API_KEY environment variable to authenticate.
        Authenticated requests allow significantly higher rate limits.

    Usage:
        client = NVDClient()
        raw_cves = client.fetch(start_date, end_date)
        records  = client.parse(raw_cves)
    """

    def __init__(self) -> None:
        self._api_key: Optional[str] = config.NVD_API_KEY
        self._base_url: str = config.NVD_BASE_URL
        self._delay: float = (
            config.NVD_DELAY_AUTHENTICATED
            if self._api_key
            else config.NVD_DELAY_UNAUTHENTICATED
        )
        if self._api_key:
            logger.info("NVDClient: authenticated (key found in environment).")
        else:
            logger.warning(
                "NVDClient: no API key found (NVD_API_KEY). "
                "Requests will be rate-limited to 1 per 6 seconds."
            )

    # ── Public interface ───────────────────────────────────────────────────────
    def fetch(
        self,
        start_date: datetime,
        end_date: datetime,
        results_per_page: int = config.NVD_RESULTS_PER_PAGE,
        max_total: int = config.NVD_MAX_TOTAL,
    ) -> List[dict]:
        """
        Fetch raw CVE items from NVD within the given UTC date range.

        Args:
            start_date: Start of the publication window (UTC-aware datetime).
            end_date:   End   of the publication window (UTC-aware datetime).
            results_per_page: Page size (NVD max is 2000; default 100).
            max_total:        Hard cap on total records fetched.

        Returns:
            List of raw CVE dicts as returned by the NVD API.
        """
        start_str = _format_nvd_date(start_date)
        end_str   = _format_nvd_date(end_date)

        logger.info(
            "Fetching CVEs from NVD: %s → %s (max %d)", start_str, end_str, max_total
        )

        headers: dict = {"Content-Type": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        all_cves: List[dict] = []
        start_index: int = 0

        while start_index < max_total:
            params = {
                "pubStartDate":   start_str,
                "pubEndDate":     end_str,
                "resultsPerPage": results_per_page,
                "startIndex":     start_index,
            }

            try:
                response = requests.get(
                    self._base_url,
                    params=params,
                    headers=headers,
                    timeout=config.REQUEST_TIMEOUT,
                )

                if response.status_code in (403, 429):
                    logger.warning(
                        "NVD rate-limit or auth error (%d). "
                        "Sleeping %.0f s before retry.",
                        response.status_code,
                        config.NVD_RETRY_SLEEP,
                    )
                    time.sleep(config.NVD_RETRY_SLEEP)
                    continue

                response.raise_for_status()
                data = response.json()

            except requests.exceptions.HTTPError as exc:
                logger.error("NVD HTTP error: %s", exc)
                break
            except requests.exceptions.ConnectionError as exc:
                logger.error("NVD connection error: %s", exc)
                break
            except requests.exceptions.Timeout:
                logger.error("NVD request timed out.")
                break
            except ValueError as exc:
                logger.error("NVD JSON decode error: %s", exc)
                break

            page = data.get("vulnerabilities", [])
            all_cves.extend(page)

            total_results = data.get("totalResults", 0)
            fetched_so_far = len(all_cves)
            logger.info(
                "NVD: fetched %d / %d records.",
                fetched_so_far,
                min(total_results, max_total),
            )

            if not page or fetched_so_far >= total_results:
                break

            start_index += results_per_page
            time.sleep(self._delay)

        logger.info("NVD fetch complete. Total raw records: %d.", len(all_cves))

        if not all_cves:
            logger.warning("NVD returned no data. Using fallback sample record.")
            all_cves = self._fallback_sample()

        return all_cves

    def fetch_last_n_days(self, days: int = config.DEFAULT_LOOKBACK_DAYS) -> List[dict]:
        """
        Convenience wrapper: fetch CVEs published in the last *days* days.

        Args:
            days: Number of days to look back from now (UTC).

        Returns:
            List of raw CVE dicts.
        """
        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        return self.fetch(start, end)

    def parse(self, raw_cves: List[dict]) -> List[dict]:
        """
        Extract structured fields from raw NVD API response items.

        Args:
            raw_cves: List returned by fetch().

        Returns:
            List of normalised record dicts with keys:
                cve_id, published, last_modified, vuln_status,
                description, cvss_score, cvss_version, cwe, references.
        """
        records: List[dict] = []
        for item in raw_cves:
            cve_id      = _safe_get(item, "cve", "id",           default="UNKNOWN")
            pub_date    = _safe_get(item, "cve", "published",    default="")
            mod_date    = _safe_get(item, "cve", "lastModified", default="")
            vuln_status = _safe_get(item, "cve", "vulnStatus",   default="Unknown")
            description = _extract_description(item)
            cvss_score, cvss_ver = _extract_cvss_score(item)
            cwe         = _extract_cwe(item)
            refs        = _extract_references(item)

            records.append({
                "cve_id":        cve_id,
                "published":     pub_date,
                "last_modified": mod_date,
                "vuln_status":   vuln_status,
                "description":   description,
                "cvss_score":    cvss_score,
                "cvss_version":  cvss_ver,
                "cwe":           cwe,
                "references":    refs,
            })

        logger.info("NVD parse complete. Extracted %d records.", len(records))
        return records

    # ── Fallback ───────────────────────────────────────────────────────────────
    @staticmethod
    def _fallback_sample() -> List[dict]:
        """Return a minimal sample record so the pipeline can run without live data."""
        return [
            {
                "cve": {
                    "id":           "CVE-2023-99999",
                    "published":    "2023-01-01T00:00:00.000Z",
                    "lastModified": "2023-01-01T00:00:00.000Z",
                    "vulnStatus":   "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "Sample SQL Injection for pipeline testing"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                    },
                    "weaknesses": [{"description": [{"value": "CWE-89"}]}],
                }
            }
        ]
