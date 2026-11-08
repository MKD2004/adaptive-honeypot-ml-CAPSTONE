"""
deploy/sandbox/tests/test_sandbox_bundle.py

The sandbox bundle is a set of files that each name the others' paths, ports and users.
These tests keep them consistent with each other and with the code they deploy, so a
change in one place cannot quietly break the server. They read the files as text and
run on any OS. Nothing here starts Docker or touches a firewall.
"""
import configparser
import re
import shutil
import subprocess
import unittest
from pathlib import Path

from adaptive_honeypot import configurator
from response_mitigation.config import load_config
from traffic_gateway import post_session_pipeline as psp
from traffic_gateway.ext_paths import DATA_PROCESSED, REPO_ROOT

SANDBOX = REPO_ROOT / "deploy" / "sandbox"
HOST = REPO_ROOT / "response_mitigation" / "host"
APP = "/opt/honeypot/app"           # where the runbook clones the repo on the server


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def env_file(path: Path):
    """KEY=value lines, comments and blanks skipped."""
    out = {}
    for line in text(path).splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip()
    return out


def unit_values(path: Path, key: str):
    """Every value of `key=` in a systemd unit, with line continuations joined."""
    joined = re.sub(r"\\\n\s*", " ", text(path))
    return [m.group(1).strip() for m in re.finditer(rf"^{key}=(.*)$", joined, re.M)]


def app_relative(path: Path) -> str:
    """A repo path as it will be on the server."""
    return f"{APP}/{path.resolve().relative_to(REPO_ROOT.resolve()).as_posix()}"


COMPOSE = text(SANDBOX / "docker-compose.yml")
README = text(SANDBOX / "README.md")
PIPELINE_UNIT = SANDBOX / "systemd" / "honeypot-pipeline.service"
EGRESS_UNIT = SANDBOX / "systemd" / "honeypot-egress.service"
GUARD_UNIT = HOST / "honeypot-guard.service"


class TestComposeMatchesTheCode(unittest.TestCase):
    """The compose file mounts folders. The pipeline and the configurator must use those same folders."""

    def mounts(self):
        found = {}
        for m in re.finditer(r"^\s*-\s+(\S+?):(/\S+?)(?::ro)?\s*(?:#.*)?$", COMPOSE, re.M):
            found[m.group(2)] = m.group(1)
        return found

    def host_path(self, container_path: str) -> Path:
        return (SANDBOX / self.mounts()[container_path]).resolve()

    def test_cowrie_log_folder_is_the_one_the_pipeline_reads(self):
        self.assertEqual(self.host_path("/cowrie/cowrie-git/var/log/cowrie"),
                         psp.DEFAULT_COWRIE_LOG_DIR.resolve())

    def test_bait_folder_is_the_one_the_configurator_writes(self):
        self.assertEqual(self.host_path("/cowrie/honeyfs"), configurator.HONEYFS_PATH.resolve())

    def test_the_bait_folder_is_read_only_for_cowrie(self):
        self.assertRegex(COMPOSE, r"/cowrie/honeyfs:ro")

    def test_cowrie_cannot_change_its_own_config(self):
        self.assertRegex(COMPOSE, r"cowrie\.cfg:/cowrie/cowrie-git/etc/cowrie\.cfg:ro")


class TestComposeSafetySettings(unittest.TestCase):

    def test_the_port_is_published_on_ipv4_only(self):
        ports = re.findall(r'^\s*-\s+"([^"]*:2222)"', COMPOSE, re.M)
        self.assertEqual(len(ports), 1)
        self.assertNotIn("[", ports[0])
        self.assertNotIn("::", ports[0])
        self.assertIn("COWRIE_BIND_IP:-0.0.0.0", ports[0])

    def test_it_starts_on_the_safe_port_unless_told_otherwise(self):
        self.assertIn("COWRIE_PUBLIC_PORT:-2222", COMPOSE)
        self.assertEqual(env_file(SANDBOX / "cowrie.env.example")["COWRIE_PUBLIC_PORT"], "2222")

    def test_no_extra_powers(self):
        self.assertRegex(COMPOSE, r"cap_drop:\s*\[ALL\]")
        self.assertIn("no-new-privileges:true", COMPOSE)
        for limit in ("pids_limit", "mem_limit", "cpus"):
            self.assertIn(limit, COMPOSE)
        self.assertNotRegex(COMPOSE, r"privileged:\s*true")
        self.assertNotRegex(COMPOSE, r"network_mode:\s*host")
        self.assertNotRegex(COMPOSE, r"/var/run/docker\.sock")

    def test_the_network_name_and_subnet_are_the_ones_the_outbound_rule_expects(self):
        egress = text(SANDBOX / "egress.nft")
        bridge = re.search(r"com\.docker\.network\.bridge\.name:\s*(\S+)", COMPOSE).group(1)
        self.assertEqual(bridge, "br-honeypot")
        self.assertEqual(re.findall(r'iifname "([^"]+)"', egress), [bridge, bridge])   # forward + input
        self.assertIn("172.28.0.0/24", COMPOSE)

    def test_the_outbound_rule_covers_both_ways_out(self):
        egress = text(SANDBOX / "egress.nft")
        self.assertIn("hook forward", egress)      # honeypot -> internet
        self.assertIn("hook input", egress)        # honeypot -> this host
        self.assertEqual(egress.count("ct state new"), 2)


class TestCowrieConfig(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.cfg = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
        cls.cfg.read_string(text(SANDBOX / "cowrie.cfg"))

    def test_nothing_can_be_forwarded_or_proxied_out(self):
        for key in ("forwarding", "forward_redirect", "forward_tunnel"):
            self.assertFalse(self.cfg.getboolean("ssh", key), key)

    def test_attackers_can_get_in_after_a_few_tries(self):
        self.assertEqual(self.cfg["honeypot"]["auth_class"], "AuthRandom")
        low, high, cache = (int(x) for x in self.cfg["honeypot"]["auth_class_parameters"].split(","))
        self.assertTrue(1 <= low < high and cache >= 1)

    def test_it_listens_where_the_compose_file_publishes(self):
        port = re.search(r"tcp:(\d+)", self.cfg["ssh"]["listen_endpoints"]).group(1)
        self.assertEqual(port, "2222")
        self.assertIn(":2222", COMPOSE)

    def test_the_bait_folder_and_log_file_match_the_mounts(self):
        self.assertEqual(self.cfg["honeypot"]["contents_path"], "/cowrie/honeyfs")
        self.assertTrue(self.cfg.getboolean("output_jsonlog", "enabled"))
        # Cowrie's working folder is /cowrie/cowrie-git; the log path is relative to it.
        logfile = self.cfg["output_jsonlog"]["logfile"]
        self.assertEqual(logfile, "var/log/cowrie/cowrie.json")
        self.assertIn("/cowrie/cowrie-git/" + logfile.rsplit("/", 1)[0] + ":", "/cowrie/cowrie-git/var/log/cowrie:")

    def test_the_log_file_name_is_one_the_pipeline_picks_up(self):
        import fnmatch
        self.assertTrue(fnmatch.fnmatch("cowrie.json", psp.COWRIE_LOG_GLOB))

    def test_the_honeypot_names_itself(self):
        self.assertTrue(self.cfg["honeypot"]["sensor_name"])

    def test_no_telnet_and_no_backend(self):
        self.assertFalse(self.cfg.getboolean("telnet", "enabled"))
        self.assertFalse(self.cfg.getboolean("backend_pool", "enabled"))
        self.assertFalse(self.cfg.getboolean("honeypot", "interact_enabled"))


class TestPipelineSettings(unittest.TestCase):

    def setUp(self):
        self.env = env_file(SANDBOX / "pipeline.env.example")

    def test_every_setting_is_one_the_code_actually_reads(self):
        sources = "\n".join(text(p) for d in ("traffic_gateway", "response_mitigation", "adaptive_honeypot")
                            for p in (REPO_ROOT / d).rglob("*.py") if "tests" not in p.parts)
        external = {"HF_HOME", "HF_HUB_OFFLINE"}       # read by the Hugging Face library
        for key in self.env:
            if key not in external:
                with self.subTest(key=key):
                    self.assertIn(f'"{key}"', sources)

    def test_the_example_loads_and_starts_in_stage_zero(self):
        cfg = load_config(self.env)
        self.assertEqual(cfg.mode.value, "observe")
        self.assertFalse(cfg.firewall)

    def test_blocking_is_off_in_the_example(self):
        self.assertEqual(self.env["MITIGATION_MODE"], "observe")
        self.assertEqual(self.env["MITIGATION_FIREWALL"], "0")

    def test_the_block_list_and_kill_file_are_the_ones_the_root_script_uses(self):
        cfg = load_config(self.env)
        exec_line = unit_values(GUARD_UNIT, "ExecStart")[0]
        self.assertIn(f"--blocklist {cfg.blocklist_path.as_posix()}", exec_line)
        self.assertIn(f"--kill-file {cfg.kill_file.as_posix()}", exec_line)

    def test_state_lives_under_the_one_folder_the_service_may_write(self):
        for key in ("GATEWAY_DATA_DIR", "GATEWAY_LOG_DIR", "HF_HOME", "MITIGATION_AUDIT_PATH"):
            with self.subTest(key=key):
                self.assertTrue(self.env[key].startswith("/var/lib/honeypot/"), self.env[key])

    def test_the_never_block_hint_is_in_both_example_files(self):
        self.assertIn("MITIGATION_NEVER_BLOCK", text(SANDBOX / "pipeline.env.example"))
        self.assertIn("HONEYPOT_GUARD_NEVER_BLOCK", text(SANDBOX / "guard.env.example"))


class TestPipelineService(unittest.TestCase):

    def rw_paths(self):
        return [p for line in unit_values(PIPELINE_UNIT, "ReadWritePaths") for p in line.split()]

    def test_it_runs_as_an_unprivileged_user_with_the_safety_switches_on(self):
        self.assertEqual(unit_values(PIPELINE_UNIT, "User"), ["honeypot"])
        for key in ("NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp"):
            with self.subTest(key=key):
                self.assertTrue(unit_values(PIPELINE_UNIT, key))
        self.assertEqual(unit_values(PIPELINE_UNIT, "ProtectSystem"), ["strict"])
        self.assertEqual(unit_values(PIPELINE_UNIT, "CapabilityBoundingSet"), [""])

    def test_it_may_write_exactly_where_the_code_writes(self):
        """The list came from recording every file write during a run (tools/record_pipeline_writes.py;
        test_sandbox_writes.py repeats that run). Here it is checked against the paths in the code, so a
        move in the code is caught even where that run does not reach."""
        wanted = {
            "/var/lib/honeypot", "/var/lib/honeypot-guard",
            app_relative(configurator.HONEYFS_PATH),                      # bait files
            app_relative(configurator.ACTIVE_CONFIG_PATH.parent),         # active_config.json
            app_relative(configurator.CONFIG_LOG_PATH.parent),            # honeypot_config_changes.jsonl
            app_relative(DATA_PROCESSED),                                 # threat-intel cache
        }
        self.assertEqual(set(self.rw_paths()), wanted)

    def test_it_reads_the_same_cowrie_folder_as_the_code_default(self):
        exec_line = unit_values(PIPELINE_UNIT, "ExecStart")[0]
        self.assertIn(f"--cowrie-log-dir {app_relative(psp.DEFAULT_COWRIE_LOG_DIR)}", exec_line)

    def test_results_go_under_the_writable_state_folder(self):
        exec_line = unit_values(PIPELINE_UNIT, "ExecStart")[0]
        self.assertRegex(exec_line, r"--results /var/lib/honeypot/pipeline/pipeline_results\.jsonl")

    def test_it_restarts_where_it_stopped_without_losing_or_repeating_sessions(self):
        self.assertIn("--from-start", unit_values(PIPELINE_UNIT, "ExecStart")[0])

    def test_the_runbook_creates_every_folder_the_service_may_write(self):
        creates = "\n".join(l for l in README.splitlines() if "install -d" in l)
        for path in self.rw_paths():
            rel = path[len(APP) + 1:] if path.startswith(APP + "/") else path
            with self.subTest(path=path):
                if rel == "adaptive_honeypot":
                    # CODE: it comes from the git clone. The runbook does not create it, it locks it down.
                    self.assertIn(f"chmod 1775 {rel}", README)
                else:
                    self.assertIn(rel, creates)
        for sub in ("gateway", "pipeline", "mitigation", "hf"):        # the brace list in step A2
            self.assertIn(sub, creates)

    def test_the_runbook_installs_the_settings_where_the_unit_reads_them(self):
        target = unit_values(PIPELINE_UNIT, "EnvironmentFile")[0]
        self.assertIn(f"{target}", README)
        self.assertTrue(re.search(r"install .*pipeline\.env\.example " + re.escape(target), README))

    def test_the_python_path_in_the_unit_is_the_venv_the_runbook_makes(self):
        exec_line = unit_values(PIPELINE_UNIT, "ExecStart")[0]
        self.assertTrue(exec_line.startswith("/opt/honeypot/venv/bin/python"))
        self.assertIn("python3 -m venv /opt/honeypot/venv", README)

    def test_the_config_dir_is_sticky_so_the_service_cannot_replace_code(self):
        self.assertIn("chmod 1775 adaptive_honeypot", README)


class TestRunbookAndUnitsAgree(unittest.TestCase):

    def test_the_egress_unit_loads_the_file_the_runbook_installs(self):
        exec_line = unit_values(EGRESS_UNIT, "ExecStart")[0]
        path = exec_line.split()[-1]
        self.assertEqual(path, "/opt/honeypot-guard/egress.nft")
        self.assertIn(f"deploy/sandbox/egress.nft {path.rsplit('/', 1)[0]}/", README)

    def test_the_egress_unit_is_up_before_docker_can_start_anything(self):
        self.assertIn("docker.service", unit_values(EGRESS_UNIT, "Before")[0])

    def test_the_guard_unit_runs_the_script_the_runbook_installs(self):
        script = unit_values(GUARD_UNIT, "ExecStart")[0].split()[1]
        self.assertEqual(script, "/opt/honeypot-guard/apply_blocklist.py")
        self.assertIn("apply_blocklist.py /opt/honeypot-guard/", README)

    def test_the_guard_reads_its_settings_from_the_file_the_runbook_installs(self):
        target = unit_values(GUARD_UNIT, "EnvironmentFile")[0].lstrip("-")
        self.assertRegex(README, r"guard\.env\.example " + re.escape(target))

    def test_every_unit_and_file_in_the_folder_is_in_the_runbook(self):
        for path in SANDBOX.rglob("*"):
            if path.is_file() and "tests" not in path.parts and path.name not in {".gitattributes", "README.md"}:
                with self.subTest(file=path.name):
                    self.assertIn(path.name, README)

    def test_the_files_the_runbook_tells_you_to_edit_have_the_never_block_line(self):
        for name in ("pipeline.env", "guard.env"):
            self.assertIn(f"sudoedit /etc/honeypot", README)
            self.assertIn(name, README)

    def test_the_container_name_is_the_same_everywhere(self):
        name = re.search(r"container_name:\s*(\S+)", COMPOSE).group(1)
        self.assertIn(f'CONTAINER="${{COWRIE_CONTAINER:-{name}}}"', text(SANDBOX / "verify_sandbox.sh"))


class TestVerifyScript(unittest.TestCase):

    SCRIPT = SANDBOX / "verify_sandbox.sh"

    def test_it_is_valid_shell(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("no bash on this machine")
        done = subprocess.run([bash, "-n", str(self.SCRIPT)], capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)

    CHANGING = (r"rm|mv|cp|chmod|chown|touch|tee|nft\s+(?:add|delete|flush|insert|replace|-f)|"
                r"systemctl\s+(?:start|stop|restart|enable|disable|reload|kill)|"
                r"docker\s+(?:rm|stop|kill|restart|run|compose\s+(?:up|down|restart))|"
                r"ip\s+(?:link|addr|route)\s+(?:add|del|set)|apt(?:-get)?\s+install|pip\s+install")
    # A command starts at the beginning of a line, or after ; & | { ` $( then do else.
    COMMAND_POSITION = re.compile(
        r"(?:^|[;&|{`]|\$\(|\bthen\b|\bdo\b|\belse\b)\s*(?:sudo\s+)?(?:" + CHANGING + r")\b", re.M)

    def changing_commands(self, body: str):
        code = "\n".join(re.sub(r"(^|\s)#.*$", "", line) for line in body.splitlines())
        # A hint inside a quoted message is advice to the reader, not a command to run.
        code = re.sub(r'"(?:[^"\\$`]|\\.)*"', '""', code)
        return self.COMMAND_POSITION.findall(code)

    def test_it_changes_nothing(self):
        self.assertEqual(self.changing_commands(text(self.SCRIPT)), [])

    def test_the_changing_command_check_itself_works(self):
        for bad in ("rm -f /tmp/x", "echo hi && rm x", "if true; then systemctl restart ssh; fi",
                    "x=$(nft flush ruleset)", "sudo nft add rule x", "docker compose up -d", "touch /tmp/f"):
            with self.subTest(bad=bad):
                self.assertTrue(self.changing_commands(bad), bad)
        for fine in ('fail "container missing (docker compose --env-file x up -d)"',
                     'fail "not active (systemctl status $unit)"',
                     'warn "start it with systemctl start x"',
                     "# rm -rf / would be bad",
                     "docker inspect x", "nft list table inet t", "docker exec c python3 -c 'x'"):
            with self.subTest(fine=fine):
                self.assertEqual(self.changing_commands(fine), [], fine)

    def test_the_paths_it_checks_are_the_ones_the_units_use(self):
        body = text(self.SCRIPT)
        for token in ("/var/lib/honeypot-guard/blocklist.json", "/var/lib/honeypot-guard/MITIGATION_DISABLED",
                      "/etc/honeypot/pipeline.env", "/etc/honeypot-guard/guard.env",
                      "/opt/honeypot-guard/apply_blocklist.py", "honeypot-egress.service",
                      "honeypot-guard.timer", "honeypot-pipeline.service", "honeypot_dataset/cowrie/logs",
                      "mt3_full_d256/best.pt", "semantic_pca.pkl", "feature_scaler.pkl"):
            with self.subTest(token=token):
                self.assertIn(token, body)

    def test_the_model_paths_it_checks_are_the_ones_the_code_loads(self):
        from traffic_gateway import feature_bridge as fb
        body = text(self.SCRIPT)
        for path in (fb.MT3_CKPT, fb.SEMANTIC_PCA):
            self.assertIn(path.resolve().relative_to(REPO_ROOT.resolve()).as_posix(), body)


class TestPackageList(unittest.TestCase):

    REQ = text(SANDBOX / "requirements-pipeline.txt")

    def pinned(self, name):
        return re.search(rf"^{re.escape(name)}==(\S+)", self.REQ, re.M)

    def test_the_packages_that_decide_the_result_are_pinned(self):
        for name in ("numpy", "scikit-learn", "joblib", "pandas"):
            with self.subTest(name=name):
                self.assertIsNotNone(self.pinned(name))

    def test_transformers_is_listed_because_group_d_needs_it(self):
        self.assertRegex(self.REQ, r"(?m)^transformers")

    def test_torch_is_not_in_the_list_because_it_needs_the_cpu_index(self):
        self.assertIsNone(re.search(r"^torch", self.REQ, re.M))
        self.assertIn("--index-url https://download.pytorch.org/whl/cpu", self.REQ)

    def test_the_scaler_here_was_written_by_the_pinned_scikit_learn(self):
        scaler = REPO_ROOT / "honeypot_dataset" / "data" / "final" / "feature_scaler.pkl"
        if not scaler.exists():
            self.skipTest("feature_scaler.pkl is not on this machine")
        import warnings
        import joblib
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            written_by = joblib.load(scaler).__getstate__().get("_sklearn_version")
        self.assertEqual(self.pinned("scikit-learn").group(1), written_by)


if __name__ == "__main__":
    unittest.main()
