"""
cve_intelligence/clients/cisa.py

CISA KEV Catalog Client
════════════════════════
Responsible exclusively for downloading and normalising the CISA
Known Exploited Vulnerabilities (KEV) catalog.

The KEV catalog provides a ground-truth list of CVEs that have been
confirmed as actively exploited in the wild — the most reliable
signal available for prioritising honeypot deployments.

Reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import logging
from typing import List, Optional, Set

import requests

from cve_intelligence import config

logger = logging.getLogger(__name__)

# Columns we care about from the raw KEV JSON
_KEV_RENAME: dict = {
    "cveID":             "cve_id",
    "vulnerabilityName": "kev_name",
    "dateAdded":         "kev_date_added",
    "requiredAction":    "kev_action",
    "dueDate":           "kev_due_date",
    "shortDescription":  "kev_description",
    "product":           "kev_product",
    "vendorProject":     "kev_vendor",
}

_REQUIRED_OUT_COLS: List[str] = [
    "cve_id",
    "kev_name",
    "kev_date_added",
    "kev_action",
    "kev_due_date",
]


class CISAClient:
    """
    Downloads and normalises the CISA KEV JSON catalog.

    Usage:
        client = CISAClient()
        df     = client.fetch_dataframe()   # returns pandas DataFrame
        ids    = client.fetch_id_set()      # returns set of CVE ID strings
    """

    def __init__(self, url: str = config.CISA_KEV_URL) -> None:
        self._url = url

    # ── Public interface ───────────────────────────────────────────────────────
    def fetch_raw(self) -> List[dict]:
        """
        Download the KEV catalog and return the raw list of vulnerability dicts.

        Returns:
            List of vulnerability dicts as returned by the CISA JSON endpoint.
            Returns an empty list on any network or parse error.
        """
        logger.info("Fetching CISA KEV catalog from %s", self._url)
        try:
            resp = requests.get(self._url, timeout=config.REQUEST_TIMEOUT, verify=False)
            resp.raise_for_status()
            data = resp.json()
        except requests.exceptions.HTTPError as exc:
            logger.error("CISA KEV HTTP error: %s", exc)
            return []
        except requests.exceptions.ConnectionError as exc:
            logger.error("CISA KEV connection error: %s", exc)
            return []
        except requests.exceptions.Timeout:
            logger.error("CISA KEV request timed out.")
            return []
        except ValueError as exc:
            logger.error("CISA KEV JSON parse error: %s", exc)
            return []

        vulnerabilities = data.get("vulnerabilities", [])
        logger.info("CISA KEV: loaded %d entries.", len(vulnerabilities))
        return vulnerabilities

    def fetch_dataframe(self):  # type: ignore[return]
        """
        Fetch and normalise the KEV catalog into a pandas DataFrame.

        Returns:
            pandas.DataFrame with columns defined in _REQUIRED_OUT_COLS,
            plus any additional columns available in the catalog.
            Returns an empty DataFrame on failure.
        """
        try:
            import pandas as pd
        except ImportError as exc:
            logger.error("pandas is required: pip install pandas (%s)", exc)
            raise

        raw = self.fetch_raw()
        if not raw:
            logger.warning("CISA KEV: returning empty DataFrame (no data).")
            return pd.DataFrame(columns=_REQUIRED_OUT_COLS)

        df = pd.DataFrame(raw)

        # Rename only columns that exist in the response
        rename_available = {k: v for k, v in _KEV_RENAME.items() if k in df.columns}
        df = df.rename(columns=rename_available)

        # Ensure required columns exist (fill missing with empty string)
        for col in _REQUIRED_OUT_COLS:
            if col not in df.columns:
                df[col] = ""

        logger.info(
            "CISA KEV DataFrame: %d rows, %d columns.", len(df), len(df.columns)
        )
        return df

    def fetch_id_set(self) -> Set[str]:
        """
        Return a set of KEV CVE ID strings for O(1) membership testing.

        Returns:
            Set of strings like {'CVE-2021-44228', 'CVE-2023-23397', ...}
        """
        raw = self.fetch_raw()
        ids = {entry.get("cveID", "") for entry in raw if entry.get("cveID")}
        logger.info("CISA KEV ID set: %d unique CVE IDs.", len(ids))
        return ids

    def fetch_id_list(self) -> List[str]:
        """
        Return a sorted list of KEV CVE ID strings.

        Convenience wrapper around fetch_id_set() for callers that need
        a deterministic ordered sequence.
        """
        return sorted(self.fetch_id_set())
