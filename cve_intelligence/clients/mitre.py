"""
cve_intelligence/clients/mitre.py

MITRE CVE / CWE Client
═══════════════════════
Responsible exclusively for fetching supplementary data from MITRE:

  1. CVE details via the MITRE CVE Services API (JSON 5.0 format)
     https://cveawg.mitre.org/api/cve/{CVE-ID}

  2. CWE enrichment via the NVD-served CWE endpoint
     (MITRE is the authoritative source; NVD caches it)

The notebook did not include a dedicated MITRE client; this module
adds it as a proper first-class citizen in the pipeline architecture.
It is called by the pipeline to:
  - Fetch detailed CVE records not yet indexed by NVD
  - Retrieve human-readable CWE descriptions for the config_generator
"""
from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional

import requests

from cve_intelligence import config

logger = logging.getLogger(__name__)

# ── MITRE API endpoints ───────────────────────────────────────────────────────
MITRE_CVE_API_BASE: str  = "https://cveawg.mitre.org/api/cve"
MITRE_CWE_LOOKUP_BASE: str = "https://cwe.mitre.org/data/definitions"

# Delay between batch requests (MITRE is lenient, but be polite)
_INTER_REQUEST_DELAY: float = 0.5  # seconds


class MITREClient:
    """
    Fetches supplementary CVE / CWE data from MITRE.

    All methods return raw dicts / None — higher layers handle parsing.

    Usage:
        client = MITREClient()

        # Fetch a single CVE detail record
        detail = client.fetch_cve("CVE-2021-44228")

        # Batch fetch multiple CVEs
        records = client.fetch_cves_batch(["CVE-2021-44228", "CVE-2023-23397"])

        # Resolve a CWE description
        desc = client.cwe_description("CWE-89")
    """

    def __init__(self) -> None:
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})
        # In-memory CWE description cache (populated lazily)
        self._cwe_cache: Dict[str, str] = {}

    # ── CVE detail fetch ──────────────────────────────────────────────────────
    def fetch_cve(self, cve_id: str) -> Optional[dict]:
        """
        Fetch full CVE detail record from the MITRE CVE Services API.

        Args:
            cve_id: CVE identifier, e.g. 'CVE-2021-44228'.

        Returns:
            Raw CVE JSON dict, or None on any error.
        """
        url = f"{MITRE_CVE_API_BASE}/{cve_id.upper()}"
        logger.debug("MITRE: fetching %s", url)
        try:
            resp = self._session.get(url, timeout=config.REQUEST_TIMEOUT)
            if resp.status_code == 404:
                logger.debug("MITRE: %s not found (404).", cve_id)
                return None
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as exc:
            logger.warning("MITRE CVE HTTP error for %s: %s", cve_id, exc)
            return None
        except requests.exceptions.ConnectionError as exc:
            logger.warning("MITRE CVE connection error: %s", exc)
            return None
        except requests.exceptions.Timeout:
            logger.warning("MITRE CVE request timed out for %s.", cve_id)
            return None
        except ValueError as exc:
            logger.warning("MITRE CVE JSON decode error for %s: %s", cve_id, exc)
            return None

    def fetch_cves_batch(
        self,
        cve_ids: List[str],
        delay: float = _INTER_REQUEST_DELAY,
    ) -> Dict[str, Optional[dict]]:
        """
        Fetch multiple CVE records, rate-limited.

        Args:
            cve_ids: List of CVE ID strings.
            delay:   Seconds to sleep between requests.

        Returns:
            Dict mapping each CVE ID to its detail dict (or None if unavailable).
        """
        results: Dict[str, Optional[dict]] = {}
        total = len(cve_ids)
        logger.info("MITRE: batch-fetching %d CVE records.", total)

        for idx, cve_id in enumerate(cve_ids, start=1):
            results[cve_id] = self.fetch_cve(cve_id)
            if idx < total:
                time.sleep(delay)
            if idx % 50 == 0:
                logger.debug("MITRE: %d / %d fetched.", idx, total)

        logger.info("MITRE batch complete. Successful: %d / %d.",
                    sum(1 for v in results.values() if v is not None), total)
        return results

    # ── CWE description lookup ────────────────────────────────────────────────
    def cwe_description(self, cwe_id: str) -> Optional[str]:
        """
        Return a human-readable description for a CWE identifier.

        Checks an in-memory cache first; falls back to the static lookup table
        from config.CWE_ATTACK_MAP (which maps CWE → attack type string).
        A network lookup against the live MITRE CWE XML endpoint is intentionally
        NOT performed here to keep this module lightweight; the attack-type mapping
        in config.py is sufficient for honeypot profile generation.

        Args:
            cwe_id: e.g. 'CWE-89'

        Returns:
            Human-readable attack type string, or None if unknown.
        """
        if cwe_id in self._cwe_cache:
            return self._cwe_cache[cwe_id]

        # Use the static mapping from config as the source of truth
        description = config.CWE_ATTACK_MAP.get(cwe_id)
        if description:
            self._cwe_cache[cwe_id] = description
        return description

    def enrich_records(self, records: List[dict]) -> List[dict]:
        """
        Optionally enrich a list of CVE record dicts with MITRE CWE descriptions.

        Adds a 'cwe_description' key to each record if the CWE is resolvable.
        Operates in-place and also returns the modified list.

        Args:
            records: List of CVE record dicts (as returned by NVDClient.parse()).

        Returns:
            The same list with 'cwe_description' added where possible.
        """
        enriched = 0
        for rec in records:
            cwe = rec.get("cwe")
            if cwe:
                desc = self.cwe_description(cwe)
                rec["cwe_description"] = desc
                if desc:
                    enriched += 1
            else:
                rec["cwe_description"] = None

        logger.info(
            "MITRE enrichment: %d / %d records got CWE descriptions.",
            enriched, len(records),
        )
        return records

    # ── State helpers ─────────────────────────────────────────────────────────
    @property
    def cwe_cache(self) -> Dict[str, str]:
        """Read-only view of the current CWE description cache."""
        return dict(self._cwe_cache)

    def close(self) -> None:
        """Release the underlying requests Session."""
        self._session.close()

    def __enter__(self) -> "MITREClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
