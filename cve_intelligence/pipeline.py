"""
cve_intelligence/pipeline.py

CVE Intelligence Pipeline — Orchestrator
═════════════════════════════════════════
Glues together the four API clients, the analytics layer, and the
config generator into a single, reproducible execution flow.

Pipeline stages
───────────────
  1. Fetch    — NVD (raw CVEs) + CISA KEV (exploited list)
  2. Parse    — NVD raw → structured records → DataFrame
  3. Enrich   — Mark KEV, fetch/simulate EPSS, MITRE CWE descriptions
  4. Preprocess — dates, fill nulls, severity labels, normalisation
  5. Classify — attack type per CVE (CWE → keyword fallback)
  6. Score    — composite priority score + tier labels
  7. Generate — honeypot config per CVE
  8. Filter   — extract trending (KEV ≤ N days old)
  9. Export   — write trending_profiles.json (and optionally CSV)

Usage (module):
    from cve_intelligence.pipeline import CVEIntelligencePipeline
    p = CVEIntelligencePipeline()
    p.run()

Usage (CLI):
    python -m cve_intelligence.pipeline
    python -m cve_intelligence.pipeline --days 14 --out data/custom_profiles.json
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

# ── Internal imports ──────────────────────────────────────────────────────────
from cve_intelligence import config
from cve_intelligence import analyzers
from cve_intelligence.clients.nvd       import NVDClient
from cve_intelligence.clients.cisa      import CISAClient
from cve_intelligence.clients.exploitdb import ExploitDBClient
from cve_intelligence.clients.mitre     import MITREClient
from cve_intelligence.config_generator  import HoneypotConfigGenerator

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)

# ── Default output path ───────────────────────────────────────────────────────
_DEFAULT_OUTPUT = Path(__file__).parent / "data" / "trending_profiles.json"
_DEFAULT_CSV    = Path(__file__).parent / "data" / "cve_priority_results.csv"


class CVEIntelligencePipeline:
    """
    End-to-end CVE intelligence pipeline for the Adaptive Honeypot Framework.

    Args:
        lookback_days:    How many days of NVD CVEs to fetch.
        trending_window:  How many days defines "recently exploited" in KEV.
        output_path:      Where to write trending_profiles.json.
        csv_path:         Where to write the full CSV results (None = skip).
        include_exploitdb: Whether to fetch the ExploitDB index (slower; adds
                           edb_exploit_count column).
        include_mitre:    Whether to enrich records with MITRE CWE descriptions.
        top_n:            Cap on rows in the final sorted output.
    """

    def __init__(
        self,
        lookback_days: int        = config.DEFAULT_LOOKBACK_DAYS,
        trending_window: int      = config.TRENDING_WINDOW_DAYS,
        output_path: Path         = _DEFAULT_OUTPUT,
        csv_path: Optional[Path]  = _DEFAULT_CSV,
        include_exploitdb: bool   = False,
        include_mitre: bool       = True,
        top_n: int                = config.TOP_N_RESULTS,
    ) -> None:
        self.lookback_days     = lookback_days
        self.trending_window   = trending_window
        self.output_path       = Path(output_path)
        self.csv_path          = Path(csv_path) if csv_path else None
        self.include_exploitdb = include_exploitdb
        self.include_mitre     = include_mitre
        self.top_n             = top_n

        # Instantiate clients and generator
        self._nvd      = NVDClient()
        self._cisa     = CISAClient()
        self._mitre    = MITREClient() if include_mitre else None
        self._exploitdb = ExploitDBClient() if include_exploitdb else None
        self._generator = HoneypotConfigGenerator()

    # ══════════════════════════════════════════════════════════════════════════
    # Stage runners (each returns the DataFrame it produces/enriches)
    # ══════════════════════════════════════════════════════════════════════════
    def _stage_fetch(self) -> pd.DataFrame:
        """Stage 1 & 2: Fetch from NVD + CISA, parse into DataFrame."""
        logger.info("── Stage 1/2: Fetch & Parse ─────────────────────────────")

        raw_cves = self._nvd.fetch_last_n_days(days=self.lookback_days)
        records  = self._nvd.parse(raw_cves)
        df       = pd.DataFrame(records)

        if df.empty:
            logger.warning("NVD returned no records after parsing.")
            return df

        logger.info("NVD: %d CVEs loaded into DataFrame.", len(df))
        return df

    def _stage_enrich_kev(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 3a: Mark KEV status and merge KEV metadata."""
        logger.info("── Stage 3a: CISA KEV Enrichment ──────────────────────")

        kev_df  = self._cisa.fetch_dataframe()
        kev_ids = set(kev_df["cve_id"].tolist()) if not kev_df.empty else set()

        df = df.copy()
        df["is_kev"] = df["cve_id"].apply(lambda x: 1 if x in kev_ids else 0)

        if not kev_df.empty:
            kev_meta = kev_df[["cve_id", "kev_name", "kev_date_added", "kev_action"]]
            df = df.merge(kev_meta, on="cve_id", how="left")
        else:
            for col in ("kev_name", "kev_date_added", "kev_action"):
                df[col] = None

        kev_count = int(df["is_kev"].sum())
        logger.info("KEV flagged: %d / %d CVEs.", kev_count, len(df))
        return df

    def _stage_enrich_epss(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 3b: Fetch real EPSS scores, fill gaps with simulation."""
        logger.info("── Stage 3b: EPSS Enrichment ──────────────────────────")
        return analyzers.enrich_epss(df)

    def _stage_enrich_mitre(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 3c: Enrich with MITRE CWE descriptions (optional)."""
        if self._mitre is None:
            return df
        logger.info("── Stage 3c: MITRE CWE Enrichment ─────────────────────")
        records = df.to_dict(orient="records")
        records = self._mitre.enrich_records(records)
        return pd.DataFrame(records)

    def _stage_enrich_exploitdb(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 3d: Add ExploitDB exploit count column (optional)."""
        if self._exploitdb is None:
            return df
        logger.info("── Stage 3d: ExploitDB Enrichment ─────────────────────")
        edb_ids = self._exploitdb.cve_ids_with_exploits()
        df = df.copy()
        df["edb_exploit_count"] = df["cve_id"].apply(
            lambda cid: self._exploitdb.exploit_count(cid) if cid in edb_ids else 0
        )
        in_edb = (df["edb_exploit_count"] > 0).sum()
        logger.info("ExploitDB: %d CVEs have known exploits.", in_edb)
        return df

    def _stage_preprocess(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 4: Normalise types, fill nulls, derive features."""
        logger.info("── Stage 4: Preprocessing ──────────────────────────────")
        return analyzers.preprocess(df)

    def _stage_classify(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 5: Attack-type classification."""
        logger.info("── Stage 5: Attack Classification ──────────────────────")
        return analyzers.apply_attack_classification(df)

    def _stage_score(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 6: Priority scoring and sorting."""
        logger.info("── Stage 6: Priority Scoring ───────────────────────────")
        df = analyzers.compute_priority(df)
        return analyzers.sort_by_priority(df)

    def _stage_generate_configs(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 7: Generate honeypot configs."""
        logger.info("── Stage 7: Config Generation ──────────────────────────")
        return self._generator.generate_all(df)

    def _stage_filter_trending(self, df: pd.DataFrame) -> pd.DataFrame:
        """Stage 8: Filter to trending CVEs."""
        logger.info("── Stage 8: Trending Filter ────────────────────────────")
        return analyzers.filter_trending(df, window_days=self.trending_window)

    def _stage_export(
        self,
        df_sorted: pd.DataFrame,
        df_trending: pd.DataFrame,
    ) -> List[dict]:
        """Stage 9: Write JSON (and optionally CSV) to disk."""
        logger.info("── Stage 9: Export ─────────────────────────────────────")

        profiles = self._generator.build_trending_profiles(df_sorted, df_trending)
        self._generator.save_to_disk(profiles, self.output_path)

        if self.csv_path:
            self._generator.save_csv(df_sorted, self.csv_path)

        return profiles

    # ══════════════════════════════════════════════════════════════════════════
    # Summary printer
    # ══════════════════════════════════════════════════════════════════════════
    def _print_summary(
        self,
        df_sorted: pd.DataFrame,
        df_trending: pd.DataFrame,
        profiles: List[dict],
    ) -> None:
        divider = "═" * 60
        thin    = "─" * 60
        logger.info("\n%s", divider)
        logger.info("  CVE Intelligence Pipeline — Summary")
        logger.info(divider)
        logger.info("  Total CVEs processed       : %d", len(df_sorted))
        logger.info(
            "  KEV (confirmed exploited)  : %d",
            int(df_sorted.get("is_kev", pd.Series(0, dtype=int)).sum()),
        )
        logger.info(
            "  Critical severity          : %d",
            int((df_sorted["severity"] == "Critical").sum()),
        )
        logger.info(
            "  High severity              : %d",
            int((df_sorted["severity"] == "High").sum()),
        )
        logger.info(
            "  Unique attack types        : %d",
            int(df_sorted["attack_type"].nunique()),
        )
        logger.info("  Trending CVEs (≤%d days)   : %d", self.trending_window, len(df_trending))
        logger.info("  Profiles exported          : %d", len(profiles))
        logger.info("  Output path                : %s", self.output_path)
        logger.info(thin)

        # Print top-5 priority CVEs
        logger.info("  Top-5 Priority CVEs:")
        logger.info("  %-20s %-22s %-8s %-8s %s",
                    "CVE ID", "Attack Type", "CVSS", "Priority", "Tier")
        logger.info("  %s", "─" * 56)
        for _, row in df_sorted.head(5).iterrows():
            logger.info(
                "  %-20s %-22s %-8.1f %-8.4f %s",
                row["cve_id"],
                str(row["attack_type"])[:20],
                row["cvss_score"],
                row["priority_score"],
                row["priority_tier"],
            )
        logger.info("%s\n", divider)

    # ══════════════════════════════════════════════════════════════════════════
    # Main entry point
    # ══════════════════════════════════════════════════════════════════════════
    def run(self) -> Dict[str, Any]:
        """
        Execute the complete pipeline end-to-end.

        Returns:
            Dict with keys:
              'df_sorted'    — full prioritised DataFrame
              'df_trending'  — trending subset (may be empty)
              'profiles'     — list of profile dicts written to JSON
        """
        logger.info("══════════════════════════════════════════════════════════")
        logger.info("  CVE Intelligence Pipeline — Starting")
        logger.info("  Lookback: %d days | Trending window: %d days",
                    self.lookback_days, self.trending_window)
        logger.info("══════════════════════════════════════════════════════════")

        # Stages
        df = self._stage_fetch()
        if df.empty:
            logger.error("Pipeline aborted: no CVE data available.")
            return {"df_sorted": df, "df_trending": pd.DataFrame(), "profiles": []}

        df = self._stage_enrich_kev(df)
        df = self._stage_enrich_epss(df)
        df = self._stage_enrich_mitre(df)
        df = self._stage_enrich_exploitdb(df)
        df = self._stage_preprocess(df)
        df = self._stage_classify(df)
        df = self._stage_score(df)
        df = self._stage_generate_configs(df)

        df_trending = self._stage_filter_trending(df)
        profiles    = self._stage_export(df, df_trending)

        self._print_summary(df, df_trending, profiles)

        return {
            "df_sorted":   df,
            "df_trending": df_trending,
            "profiles":    profiles,
        }


# ══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════════════════
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CVE Intelligence Pipeline — generates honeypot configs from live threat feeds.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--days", type=int, default=config.DEFAULT_LOOKBACK_DAYS,
        help="Number of days of NVD CVEs to fetch.",
    )
    parser.add_argument(
        "--trending-window", type=int, default=config.TRENDING_WINDOW_DAYS,
        help="Days that define a 'recently exploited' KEV entry.",
    )
    parser.add_argument(
        "--out", type=Path, default=_DEFAULT_OUTPUT,
        help="Output path for trending_profiles.json.",
    )
    parser.add_argument(
        "--csv", type=Path, default=_DEFAULT_CSV,
        help="Output path for full CSV results. Use 'none' to skip.",
    )
    parser.add_argument(
        "--no-csv", action="store_true",
        help="Skip CSV export.",
    )
    parser.add_argument(
        "--exploitdb", action="store_true",
        help="Also fetch ExploitDB index (slower; adds exploit count column).",
    )
    parser.add_argument(
        "--no-mitre", action="store_true",
        help="Skip MITRE CWE enrichment.",
    )
    parser.add_argument(
        "--top-n", type=int, default=config.TOP_N_RESULTS,
        help="Maximum rows in the prioritised output.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    csv_path = None if args.no_csv else args.csv

    pipeline = CVEIntelligencePipeline(
        lookback_days     = args.days,
        trending_window   = args.trending_window,
        output_path       = args.out,
        csv_path          = csv_path,
        include_exploitdb = args.exploitdb,
        include_mitre     = not args.no_mitre,
        top_n             = args.top_n,
    )
    result = pipeline.run()

    n_profiles = len(result.get("profiles", []))
    n_trending = len(result.get("df_trending", pd.DataFrame()))
    sys.exit(0 if n_profiles > 0 else 1)
