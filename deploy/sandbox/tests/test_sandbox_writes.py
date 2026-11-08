"""
deploy/sandbox/tests/test_sandbox_writes.py

honeypot-pipeline.service gets a read-only filesystem except the folders in ReadWritePaths.
This runs the real pipeline over a made-up Cowrie log (tools/record_pipeline_writes.py), using the
settings from pipeline.env.example and the paths from the unit file, and checks:

  * every file the pipeline writes is inside a folder the unit allows
  * the allowed folders are not wildly more than needed (a stale allowance is a hole)
  * the sessions are processed and the repeat offender reaches the firewall block list

If this fails after a code change, the change added a new output path. Either send it to a folder the
unit already allows, or add the folder to ReadWritePaths AND to the runbook's `install -d` list.
"""
import importlib.util
import re
import shutil
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
SANDBOX = REPO_ROOT / "deploy" / "sandbox"
APP = "/opt/honeypot/app"

_spec = importlib.util.spec_from_file_location("record_pipeline_writes", SANDBOX / "tools" / "record_pipeline_writes.py")
rec = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rec)

try:
    import numpy, pandas, requests, joblib   # noqa: F401  (what the pipeline imports at run time)
    HAVE_LIBS = True
except ImportError:
    HAVE_LIBS = False


def unit_lines(key: str):
    text = re.sub(r"\\\n\s*", " ", (SANDBOX / "systemd" / "honeypot-pipeline.service").read_text(encoding="utf-8"))
    return [m.group(1).strip() for m in re.finditer(rf"^{key}=(.*)$", text, re.M)]


@unittest.skipUnless(HAVE_LIBS, "needs numpy, pandas, requests, joblib")
class TestWhatThePipelineWrites(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.work = Path(tempfile.mkdtemp(prefix="rec-writes-"))
        cls.addClassCleanup(shutil.rmtree, cls.work, ignore_errors=True)
        app, state = cls.work / "app", cls.work / "state"

        def to_local(path: str) -> str:
            """A server path -> the same place inside the temporary folder."""
            if path.startswith(APP):
                return str(app) + path[len(APP):]
            if path.startswith("/var/lib/honeypot-guard"):
                return str(state / "guard") + path[len("/var/lib/honeypot-guard"):]
            if path.startswith("/var/lib/honeypot"):
                return str(state / "honeypot") + path[len("/var/lib/honeypot"):]
            return path

        # The settings the server will use, with only the paths moved into the temporary folder.
        env = {}
        for line in (SANDBOX / "pipeline.env.example").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                env[key.strip()] = to_local(value.strip())
        env.update(MITIGATION_MODE="enforce", MITIGATION_FIREWALL="1")      # so the block-list path is exercised

        exec_line = unit_lines("ExecStart")[0]
        results = re.search(r"--results (\S+)", exec_line).group(1)
        logs = re.search(r"--cowrie-log-dir (\S+)", exec_line).group(1)
        cls.allowed = [Path(to_local(p)) for line in unit_lines("ReadWritePaths") for p in line.split()]
        cls.app, cls.state = app, state
        cls.result = rec.record(work_dir=cls.work, env=env, results_path=Path(to_local(results)),
                                cowrie_log_dir=Path(to_local(logs)))

    def written(self):
        return [Path(p) for _, p in self.result["writes"]]

    def inside(self, path: Path, folder: Path) -> bool:
        return path == folder or folder in path.parents

    def test_the_sessions_were_processed(self):
        sessions = self.result["sessions"]
        self.assertEqual([s["ip"] for s in sessions],
                         [rec.SOURCE_IP] * 3 + [rec.OTHER_IP])

    def test_the_repeat_offender_reached_the_block_list(self):
        third = self.result["sessions"][2]["decisions"]
        self.assertIn(["deny", "applied"], third)
        self.assertTrue((self.state / "guard" / "blocklist.json").exists())

    def test_every_write_is_inside_a_folder_the_unit_allows(self):
        # Two things in the temporary folder are the test's own, not the pipeline's: the recorder's
        # result file, and `state/`, which stands in for /var/lib (it already exists on a server).
        harness = {self.work / "writes.json", self.state}
        outside = sorted({str(p) for p in self.written()
                          if p.is_relative_to(self.work) and p not in harness
                          and not any(self.inside(p, a) for a in self.allowed)})
        self.assertEqual(outside, [], "the pipeline wrote outside ReadWritePaths in honeypot-pipeline.service")

    def test_it_never_writes_next_to_the_code(self):
        code_dirs = [self.app / d for d in ("traffic_gateway", "response_mitigation", "ml_analytics",
                                           "cve_intelligence", "honeypot_dataset/src", "honeypot_dataset/configs")]
        hits = [str(p) for p in self.written() for d in code_dirs if self.inside(p, d)]
        self.assertEqual(hits, [])

    def test_adaptive_honeypot_gets_only_its_two_data_files(self):
        in_code_dir = {p.name for p in self.written() if p.parent == self.app / "adaptive_honeypot"}
        self.assertEqual(in_code_dir, {"active_config.json", "active_config.json.tmp"})

    def test_the_allowed_folders_are_used_not_just_listed(self):
        """A folder that is allowed but never written is a hole for nothing. Two are exempt because this run
        cannot reach them: the threat-intel cache (the download is a stand-in) and the model cache."""
        exempt = {self.app / "honeypot_dataset" / "data" / "processed"}
        for folder in self.allowed:
            if folder in exempt:
                continue
            with self.subTest(folder=str(folder.relative_to(self.work))):
                self.assertTrue(any(self.inside(p, folder) for p in self.written()))

    def test_the_bait_is_planted_in_the_folder_cowrie_reads(self):
        honeyfs = self.app / "honeypot_dataset" / "cowrie" / "honeyfs"
        self.assertTrue((honeyfs / "etc" / "shadow").exists())


if __name__ == "__main__":
    unittest.main()
