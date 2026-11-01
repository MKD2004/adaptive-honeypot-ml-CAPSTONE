"""
traffic_gateway/tests/test_config_env.py

Unit tests for the environment overrides in traffic_gateway.config: the
MT3 auto-blacklist thresholds and the data/log directories. Defaults must be
unchanged when nothing is set, and a bad value must raise rather than be
silently ignored. Data/log dirs always point at a temp folder here, so no
tracked file under traffic_gateway/data is touched.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from traffic_gateway.config import GatewayConfig

_MT3_VARS = (
    "GATEWAY_MT3_AUTO_BLACKLIST",
    "GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE",
    "GATEWAY_MT3_AUTO_BLACKLIST_CONF",
)


class TestConfigEnv(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)

    def _config(self, **env) -> GatewayConfig:
        """Fresh GatewayConfig with only `env` set for the MT3 variables."""
        base = {"GATEWAY_DATA_DIR": str(self.tmp / "data"),
                "GATEWAY_LOG_DIR": str(self.tmp / "logs")}
        with patch.dict(os.environ, {**base, **env}, clear=False):
            for var in _MT3_VARS:
                if var not in env:
                    os.environ.pop(var, None)
            return GatewayConfig()

    # ── defaults ──────────────────────────────────────────────────────────
    def test_defaults_are_unchanged(self):
        cfg = self._config()
        self.assertIs(cfg.MT3_AUTO_BLACKLIST, True)
        self.assertEqual(cfg.MT3_AUTO_BLACKLIST_MIN_PHASE, 1)
        self.assertEqual(cfg.MT3_AUTO_BLACKLIST_CONF, 0.5)

    def test_empty_value_means_default(self):
        cfg = self._config(GATEWAY_MT3_AUTO_BLACKLIST="",
                           GATEWAY_MT3_AUTO_BLACKLIST_CONF="  ")
        self.assertIs(cfg.MT3_AUTO_BLACKLIST, True)
        self.assertEqual(cfg.MT3_AUTO_BLACKLIST_CONF, 0.5)

    # ── overrides ─────────────────────────────────────────────────────────
    def test_switch_can_be_turned_off(self):
        for word in ("0", "false", "No", "OFF"):
            with self.subTest(word=word):
                cfg = self._config(GATEWAY_MT3_AUTO_BLACKLIST=word)
                self.assertIs(cfg.MT3_AUTO_BLACKLIST, False)

    def test_switch_can_be_turned_on(self):
        for word in ("1", "true", "Yes", "ON"):
            with self.subTest(word=word):
                cfg = self._config(GATEWAY_MT3_AUTO_BLACKLIST=word)
                self.assertIs(cfg.MT3_AUTO_BLACKLIST, True)

    def test_thresholds_can_be_changed(self):
        cfg = self._config(GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE="3",
                           GATEWAY_MT3_AUTO_BLACKLIST_CONF="0.85")
        self.assertEqual(cfg.MT3_AUTO_BLACKLIST_MIN_PHASE, 3)
        self.assertEqual(cfg.MT3_AUTO_BLACKLIST_CONF, 0.85)

    # ── bad values stop start-up ──────────────────────────────────────────
    def test_unrecognised_switch_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self._config(GATEWAY_MT3_AUTO_BLACKLIST="maybe")
        self.assertIn("GATEWAY_MT3_AUTO_BLACKLIST", str(ctx.exception))

    def test_non_numeric_threshold_raises(self):
        with self.assertRaises(ValueError):
            self._config(GATEWAY_MT3_AUTO_BLACKLIST_CONF="0,7")
        with self.assertRaises(ValueError):
            self._config(GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE="one")

    def test_out_of_range_threshold_raises(self):
        for name, value in (("GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE", "9"),
                            ("GATEWAY_MT3_AUTO_BLACKLIST_MIN_PHASE", "-1"),
                            ("GATEWAY_MT3_AUTO_BLACKLIST_CONF", "1.5"),
                            ("GATEWAY_MT3_AUTO_BLACKLIST_CONF", "-0.1")):
            with self.subTest(name=name, value=value):
                with self.assertRaises(ValueError):
                    self._config(**{name: value})

    # ── directories ───────────────────────────────────────────────────────
    def test_data_and_log_dirs_come_from_env_and_are_created(self):
        cfg = self._config()
        self.assertEqual(cfg.DATA_DIR, self.tmp / "data")
        self.assertEqual(cfg.LOG_DIR, self.tmp / "logs")
        self.assertTrue(cfg.DATA_DIR.is_dir())
        self.assertTrue(cfg.LOG_DIR.is_dir())

    def test_dirs_default_to_the_package_folders(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("GATEWAY_DATA_DIR", None)
            os.environ.pop("GATEWAY_LOG_DIR", None)
            cfg = GatewayConfig()
        self.assertEqual(cfg.DATA_DIR.name, "data")
        self.assertEqual(cfg.DATA_DIR.parent.name, "traffic_gateway")
        self.assertEqual(cfg.LOG_DIR.name, "logs")


if __name__ == "__main__":
    unittest.main()
