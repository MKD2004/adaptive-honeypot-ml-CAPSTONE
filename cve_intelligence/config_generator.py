"""
cve_intelligence/config_generator.py

Honeypot Configuration Generator
══════════════════════════════════
Maps a prioritised CVE DataFrame to structured honeypot deployment
configurations.  Each config dict is directly consumable by the
Adaptive Honeypot Emulator module.

Responsibilities:
  - Look up service template from config.HONEYPOT_TEMPLATES
  - Escalate interaction level for KEV / Critical CVEs
  - Attach the emulator config_string
  - Build the final trending_profiles list for JSON export

No external I/O is performed here — input is always a pandas DataFrame,
output is always Python dicts / lists ready for json.dumps().
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from cve_intelligence import config

logger = logging.getLogger(__name__)


# ── Native-type serialisation helper ─────────────────────────────────────────
def _to_native(obj: Any) -> Any:
    """Convert numpy scalar types to native Python types for JSON serialisation."""
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return obj


def _clean_record(record: dict) -> dict:
    """Apply _to_native() to every value in a flat dict."""
    return {k: _to_native(v) for k, v in record.items()}


class HoneypotConfigGenerator:
    """
    Generates honeypot deployment configurations from a CVE DataFrame.

    Attack type classification is purely keyword/CWE-based (see analyzers.py).
    No NLP libraries (spacy / sklearn) are required or imported.

    Usage:
        gen = HoneypotConfigGenerator()
        configs = gen.generate_all(df_sorted)
        trending = gen.build_trending_profiles(df_sorted, df_trending)
        gen.save_to_disk(trending, output_path)
    """

    # ── Per-CVE config builder ────────────────────────────────────────────────
    def build_config(self, row: pd.Series) -> Dict[str, Any]:
        """
        Build a single honeypot configuration dict for one CVE row.

        Escalation rules:
          - KEV = 1 or severity = "Critical"  → interaction_level = "high"
          - severity = "High" and level = "low" → interaction_level = "medium"

        Args:
            row: A single row from a CVE DataFrame (as pd.Series).

        Returns:
            Config dict containing service, ports, endpoint, emulation,
            detection, interaction_level, config_string, and all CVE metadata.
        """
        attack_type = row.get("attack_type", "Other / Unknown") or "Other / Unknown"
        severity    = row.get("severity",    "Medium")           or "Medium"
        is_kev      = int(row.get("is_kev", 0) or 0)

        # Retrieve template (deep-copy to avoid mutating the module-level dict)
        template: Dict[str, Any] = dict(
            config.HONEYPOT_TEMPLATES.get(
                attack_type, config.HONEYPOT_TEMPLATES["Other / Unknown"]
            )
        )

        # ── Interaction-level escalation ──────────────────────────────────────
        if is_kev == 1 or severity == "Critical":
            template["interaction_level"] = "high"
        elif severity == "High" and template.get("interaction_level") == "low":
            template["interaction_level"] = "medium"

        # ── Emulator config string ─────────────────────────────────────────────
        template["config_string"] = config.CONFIG_STRING_TEMPLATES.get(
            attack_type, config.CONFIG_STRING_TEMPLATES["Other / Unknown"]
        )

        # ── CVE metadata ──────────────────────────────────────────────────────
        template.update({
            "cve_id":          str(row.get("cve_id", "")),
            "attack_type":     attack_type,
            "severity":        severity,
            "cvss_score":      _to_native(row.get("cvss_score")),
            "epss_score":      _to_native(row.get("epss_score")),
            "is_kev":          is_kev,
            "priority_score":  _to_native(row.get("priority_score")),
            "priority_tier":   str(row.get("priority_tier", "")),
            "logging_enabled": True,
            "alert_threshold": "high" if (is_kev or severity == "Critical") else "medium",
        })

        return _clean_record(template)

    # ── Batch generation ──────────────────────────────────────────────────────
    def generate_all(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Add a 'honeypot_config' column to df with a config dict per row.

        Args:
            df: CVE DataFrame (with attack_type, severity, is_kev columns).

        Returns:
            df with 'honeypot_config' column added.
        """
        df = df.copy()
        df["honeypot_config"] = df.apply(self.build_config, axis=1)

        n_unique = df["attack_type"].nunique()
        logger.info(
            "Config generation complete: %d configs across %d unique attack types.",
            len(df), n_unique,
        )
        return df

    # ── Trending profiles builder ─────────────────────────────────────────────
    def build_trending_profiles(
        self,
        df_sorted: pd.DataFrame,
        df_trending: Optional[pd.DataFrame] = None,
    ) -> List[dict]:
        """
        Build the trending_profiles list for JSON export.

        If df_trending is non-empty, use it as the source.
        Otherwise fall back to all CVEs in df_sorted (ensures the file
        is always written, even when no KEV entries are recent).

        Args:
            df_sorted:   Full prioritised CVE DataFrame (with honeypot_config).
            df_trending: Subset of df_sorted where is_trending == True.

        Returns:
            List of profile dicts ready for json.dumps().
        """
        source = (
            df_trending
            if df_trending is not None and not df_trending.empty
            else df_sorted
        )

        profiles: List[dict] = []
        for _, row in source.iterrows():
            cfg = row.get("honeypot_config") or {}
            if not isinstance(cfg, dict):
                cfg = {}

            profiles.append({
                "cve_id":          str(row.get("cve_id", "")),
                "attack_type":     str(row.get("attack_type", "Unknown")),
                "severity":        str(row.get("severity", "Unknown")),
                "cvss_score":      _to_native(row.get("cvss_score")),
                "epss_score":      _to_native(row.get("epss_score")),
                "is_kev":          int(row.get("is_kev", 0) or 0),
                "priority_score":  _to_native(row.get("priority_score")),
                "priority_tier":   str(row.get("priority_tier", "")),
                "kev_date_added":  str(row.get("kev_date_added", "") or ""),
                "config_string":   cfg.get("config_string", ""),
                "honeypot_config": _clean_record(cfg),
            })

        label = "trending" if (df_trending is not None and not df_trending.empty) else "all"
        logger.info(
            "Built %d %s profiles for export.", len(profiles), label
        )
        return profiles

    # ── Disk persistence ──────────────────────────────────────────────────────
    def save_to_disk(
        self,
        profiles: List[dict],
        output_path: Path,
    ) -> None:
        """
        Serialise profiles to a JSON file.

        Creates parent directories automatically.

        Args:
            profiles:    List of profile dicts from build_trending_profiles().
            output_path: Destination Path object.

        Raises:
            OSError: If the file cannot be written.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(profiles, fh, indent=2, default=str)

        size_kb = output_path.stat().st_size / 1024
        logger.info(
            "Profiles saved -> %s  (%.1f KB, %d entries)",
            output_path, size_kb, len(profiles),
        )

    def save_csv(
        self,
        df: pd.DataFrame,
        output_path: Path,
        columns: Optional[List[str]] = None,
    ) -> None:
        """
        Export selected columns of the CVE DataFrame to CSV.

        Args:
            df:          CVE DataFrame.
            output_path: Destination Path.
            columns:     Column subset to export; None = all columns
                         except 'honeypot_config'.
        """
        if columns is None:
            columns = [
                c for c in df.columns if c != "honeypot_config"
            ]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        # Convert Timestamp columns to strings for CSV compatibility
        export_df = df[columns].copy()
        for col in export_df.select_dtypes(include=["datetimetz"]).columns:
            export_df[col] = export_df[col].astype(str)

        export_df.to_csv(output_path, index=False)
        logger.info(
            "CSV saved -> %s  (%d rows, %d columns)",
            output_path, len(export_df), len(columns),
        )
