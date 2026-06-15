"""
cve_intelligence/clients/nvd.py

NVD API 2.0 Client
══════════════════
Responsible exclusively for fetching and parsing CVEs from the
National Vulnerability Database REST API v2.0.
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
    """Extract the first CWE identifier from the weaknesses list."""
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
    Format a datetime for the NVD API v2.0.

    NVD v2.0 accepts ISO 8601 with explicit UTC offset.
    Using +00:00 instead of Z avoids an edge case in some NVD
    proxy layers that reject the Z shorthand in query strings.

    Example output: '2024-01-15T00:00:00.000+00:00'
    """
    utc_dt = dt.astimezone(timezone.utc)
    # NVD v2.0 is more reliably parsed with +00:00 than Z in URL params
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"


# ── Main client class ─────────────────────────────────────────────────────────

class NVDClient:
    """
    Fetches CVEs from the NVD REST API v2.0.

    Authentication:
        Set NVD_API_KEY in your environment to authenticate.
        Without a key: max 5 requests / 30s rolling window.
        With a key:    max 50 requests / 30s rolling window.
    """

    # NVD v2.0 enforces a strict 30-day maximum window per request.
    # Larger ranges must be broken into ≤30-day chunks.
    _MAX_WINDOW_DAYS: int = 30

    def __init__(self) -> None:
        self._api_key: Optional[str] = config.NVD_API_KEY
        self._base_url: str = config.NVD_BASE_URL
        self._delay: float = (
            config.NVD_DELAY_AUTHENTICATED
            if self._api_key
            else config.NVD_DELAY_UNAUTHENTICATED
        )
        if self._api_key:
            logger.info("NVDClient: authenticated (API key loaded from environment).")
        else:
            logger.warning(
                "NVDClient: no NVD_API_KEY set. "
                "Unauthenticated rate limit applies (1 request / 6 s)."
            )

    # ── Public interface ──────────────────────────────────────────────────────

    def fetch(
        self,
        start_date: datetime,
        end_date: datetime,
        results_per_page: int = config.NVD_RESULTS_PER_PAGE,
        max_total: int = config.NVD_MAX_TOTAL,
    ) -> List[dict]:
        """
        Fetch raw CVE items from NVD for the given UTC date range.

        NVD v2.0 enforces a 120-day maximum window per request.
        This method automatically splits wider ranges into chunks.

        Args:
            start_date: Start of the publication window (UTC-aware datetime).
            end_date:   End of the publication window (UTC-aware datetime).
            results_per_page: Page size (NVD max is 2000; keep ≤ 100 for safety).
            max_total:  Hard cap on total records fetched across all pages.

        Returns:
            List of raw CVE dicts as returned by the NVD API.
        """
        # Ensure both datetimes are UTC-aware
        if start_date.tzinfo is None:
            start_date = start_date.replace(tzinfo=timezone.utc)
        if end_date.tzinfo is None:
            end_date = end_date.replace(tzinfo=timezone.utc)

        # NVD v2.0 hard limit: pubStartDate to pubEndDate ≤ 120 days.
        # We chunk at 30 days to stay well within the limit and avoid
        # result-set size issues that can produce unexpected 404s.
        chunks = self._build_date_chunks(start_date, end_date)
        logger.info(
            "Fetching CVEs for %s → %s across %d chunk(s) (max %d total).",
            _format_nvd_date(start_date),
            _format_nvd_date(end_date),
            len(chunks),
            max_total,
        )

        all_cves: List[dict] = []
        for chunk_start, chunk_end in chunks:
            if len(all_cves) >= max_total:
                break
            remaining = max_total - len(all_cves)
            fetched = self._fetch_chunk(
                chunk_start, chunk_end, results_per_page, remaining
            )
            all_cves.extend(fetched)

        logger.info("NVD fetch complete. Total raw records: %d.", len(all_cves))

        if not all_cves:
            logger.warning("NVD returned no data. Falling back to sample record.")
            all_cves = self._fallback_sample()

        return all_cves

    def fetch_last_n_days(self, days: int = config.DEFAULT_LOOKBACK_DAYS) -> List[dict]:
        """
        Fetch CVEs published in the last *days* days up to now (UTC).

        Args:
            days: Look-back window in days.
        """
        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        return self.fetch(start, end)

    def parse(self, raw_cves: List[dict]) -> List[dict]:
        """
        Extract structured fields from raw NVD API response items.

        Returns:
            List of normalised record dicts.
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

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_date_chunks(
        self,
        start: datetime,
        end: datetime,
    ) -> List[Tuple[datetime, datetime]]:
        """
        Split a date range into ≤30-day chunks.

        NVD v2.0 can return unexpected 404s or empty results for very
        wide windows, even when records exist. Chunking avoids this.
        """
        chunks: List[Tuple[datetime, datetime]] = []
        cursor = start
        delta  = timedelta(days=self._MAX_WINDOW_DAYS)
        while cursor < end:
            chunk_end = min(cursor + delta, end)
            chunks.append((cursor, chunk_end))
            cursor = chunk_end
        return chunks

    def _fetch_chunk(
        self,
        start_date: datetime,
        end_date: datetime,
        results_per_page: int,
        max_records: int,
    ) -> List[dict]:
        """
        Fetch a single ≤30-day window with full pagination.
        Handles rate-limit retries and surfaces errors clearly.
        """
        start_str = _format_nvd_date(start_date)
        end_str   = _format_nvd_date(end_date)
        logger.info("  NVD chunk: %s → %s", start_str, end_str)

        # Minimal, honest headers — no User-Agent spoofing.
        # NVD's documented access method is the API key; the key is
        # sufficient for authenticated access at the permitted rate.
        headers: dict = {"Content-Type": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        chunk_cves: List[dict] = []
        start_index: int = 0
        consecutive_errors: int = 0
        max_consecutive_errors: int = 3

        while start_index < max_records:
            params = {
                "pubStartDate":   start_str,
                "pubEndDate":     end_str,
                "resultsPerPage": min(results_per_page, max_records - len(chunk_cves)),
                "startIndex":     start_index,
            }

            try:
                response = requests.get(
                    self._base_url,
                    params=params,
                    headers=headers,
                    timeout=config.REQUEST_TIMEOUT,
                    # verify=True is the default — do NOT disable SSL verification.
                    # Disabling it makes your traffic vulnerable to interception
                    # and can itself trigger security controls on NIST's end.
                )

                if response.status_code in (403, 429):
                    wait = config.NVD_RETRY_SLEEP
                    logger.warning(
                        "NVD rate-limit (%d). Waiting %.0f s before retry.",
                        response.status_code, wait,
                    )
                    time.sleep(wait)
                    continue

                if response.status_code == 404:
                    # 404 from NVD v2.0 typically means the date window
                    # returned zero results, not a missing endpoint.
                    logger.info(
                        "NVD returned 404 for chunk %s → %s (no CVEs in window).",
                        start_str, end_str,
                    )
                    break

                response.raise_for_status()
                data = response.json()
                consecutive_errors = 0

            except requests.exceptions.HTTPError as exc:
                consecutive_errors += 1
                logger.error("NVD HTTP error: %s", exc)
                if consecutive_errors >= max_consecutive_errors:
                    logger.error("Too many consecutive errors — aborting chunk.")
                    break
                time.sleep(self._delay * 2)
                continue
            except requests.exceptions.ConnectionError as exc:
                logger.error("NVD connection error: %s", exc)
                break
            except requests.exceptions.Timeout:
                logger.error("NVD request timed out (timeout=%ds).", config.REQUEST_TIMEOUT)
                break
            except ValueError as exc:
                logger.error("NVD JSON decode error: %s", exc)
                break

            page          = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)
            chunk_cves.extend(page)

            logger.info(
                "  NVD page: got %d records (chunk total %d / %d available).",
                len(page), len(chunk_cves), total_results,
            )

            if not page or len(chunk_cves) >= total_results:
                break

            start_index += results_per_page
            time.sleep(self._delay)

        return chunk_cves

    # ── Fallback ──────────────────────────────────────────────────────────────

    @staticmethod
    def _fallback_sample() -> List[dict]:
        """
        Minimal sample record for pipeline testing when the API is unreachable.
        This is a clearly-labelled test fixture, not real CVE data.
        """
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