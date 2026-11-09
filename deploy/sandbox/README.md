# Sandbox: Cowrie on the real internet, with the pipeline watching

This folder puts the honeypot on a public server, in a way that is safe to leave running.

```
attacker on the internet
        |  SSH
        v
 [cloud firewall]  -->  [host firewall: honeypot_guard]  -->  [Docker: Cowrie]  -->  cowrie.json
   (manual)              drops IPs on the block list           can NOT start any        |
                                 ^                              outbound connection      v
                                 |                                                [pipeline: MT3]
                                 +----- blocklist.json <---- [mitigation engine] <--------+
```

**Status (2026-11-01).** Written and tested on this project's laptop and on Ubuntu 24.04 (WSL2): the
firewall pieces, the outbound block, the systemd units, the settings files, the verify script's logic, and
the pipeline's file writes. **Not yet run on a real server** with the real Cowrie image, the trained
MT3 model, or the cloud. Treat part A as the first real test. See "Known limits" at the end.

| File | What it is |
|---|---|
| `docker-compose.yml`, `cowrie.cfg`, `cowrie.env.example` | Cowrie, on its own network, IPv4 only, with no spare powers |
| `egress.nft`, `systemd/honeypot-egress.service` | Stops the honeypot starting any outbound connection |
| `systemd/honeypot-pipeline.service`, `pipeline.env.example` | Runs the pipeline as an unprivileged user. **Set `PIPELINE_SOURCE=internet`** -- unset, every real capture is filed as "unspecified" and can never be separated from demo data afterwards |
| `guard.env.example` | Settings for the firewall script in `response_mitigation/host/` |
| `requirements-pipeline.txt` | The Python packages the pipeline really needs |
| `verify_sandbox.sh`, `check_cowrie_ips.py` | Checks after install. Change nothing |
| `tools/record_pipeline_writes.py` | Runs the pipeline on a copy and lists every file it writes (see "If the pipeline changes") |
| `tests/` | Keep these files consistent with each other and with the code. Some need Linux and root |

## The rules this setup keeps

1. **Watch first.** The first week is stage 0: decisions are only written to a log. Nothing is blocked.
2. **The honeypot cannot call out.** Cowrie's fake `wget` and `curl` make *real* requests to wherever the attacker points
   them. Without `egress.nft`, your server's address would be the source of someone else's attack
   ([Cowrie advisory GHSA-83jg-m2pm-4jxj](https://osv.dev/vulnerability/GHSA-83jg-m2pm-4jxj)).
3. **Never test a block on your own address.** A block drops *all* traffic from that IP, including your SSH.
4. **Your own SSH moves off port 22 before Cowrie takes port 22.** Part A avoids the problem by using port 2222 first.
5. **The pipeline reads attacker-controlled text, so it runs with almost no powers.** It is an unprivileged user on a
   read-only filesystem, and may write to six folders only.

## Before you start

- A cloud VM: Ubuntu 22.04 or 24.04, at least 2 CPUs, 4 GB RAM, 30 GB disk. (DistilBERT plus MT3 on CPU need about 2 GB.)
- **Cloud firewall (the provider's, in its console).** Allow your admin SSH port from *your* address only. Open the Cowrie port
  to the world only when part B says so. This is manual on purpose; we do not automate it.
- **Read your provider's acceptable-use policy** about running a honeypot and receiving scans. Check with your advisor about
  keeping logs that contain other people's IP addresses, passwords and commands.
- **Three model files**, copied by hand because they are not in git:

  | File | Where it came from | Goes to (on the server) |
  |---|---|---|
  | `best.pt` (the trained MT3) | the DGX training run | `ml_analytics/artifacts/mt3_full_d256/best.pt` |
  | `semantic_pca.pkl` | the dataset pipeline | `honeypot_dataset/data/processed/semantic_pca.pkl` |
  | `feature_scaler.pkl` | `honeypot_dataset/data/final/` | `honeypot_dataset/data/final/feature_scaler.pkl` |

  Only copy files you made yourself. `.pkl` files can run code when loaded.

All commands below are for the server. `sudo` is assumed.

---

## Part A: install and test privately (Cowrie on port 2222)

Nothing here touches your own SSH, so you cannot lock yourself out. In the cloud firewall, allow
**2222/tcp from your own address and from the second machine you will test with**, and nobody else.

### A1. Packages

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv python3-pip nftables ca-certificates
```

Install Docker Engine from Docker's own repository, following <https://docs.docker.com/engine/install/ubuntu/>.
(Avoid the snap version: it cannot see the folders we mount.)

### A2. The service user and folders

```bash
sudo useradd --system --home-dir /var/lib/honeypot --no-create-home --shell /usr/sbin/nologin honeypot
sudo install -d -o honeypot -g honeypot -m 755 /var/lib/honeypot /var/lib/honeypot/{gateway,pipeline,mitigation,hf}
sudo install -d -o honeypot -g honeypot -m 755 /var/lib/honeypot-guard
sudo install -d -m 755 /opt/honeypot /opt/honeypot-guard /etc/honeypot /etc/honeypot-guard
```

`/var/lib/honeypot-guard` is where the pipeline writes `blocklist.json` and where the root script reads it.

### A3. The code and the model files

```bash
sudo git clone --branch <BRANCH> <REPO_URL> /opt/honeypot/app      # use the way you normally reach the repo
cd /opt/honeypot/app

# folders the services write to (git does not create them)
sudo install -d -o honeypot -g honeypot -m 755 logs honeypot_dataset/cowrie/honeyfs honeypot_dataset/data/processed
sudo install -d -o 999 -g 999 -m 755 honeypot_dataset/cowrie/logs          # Cowrie's user inside the container is 999
sudo install -d -m 755 honeypot_dataset/data/final ml_analytics/artifacts/mt3_full_d256

# adaptive_honeypot/ is CODE, but the configurator writes active_config.json into it. Group-writable with the
# sticky bit: the service can add and replace its own files, but cannot touch the root-owned .py files.
sudo chgrp honeypot adaptive_honeypot && sudo chmod 1775 adaptive_honeypot
```

Copy the three model files. From **your machine**:

```bash
scp best.pt semantic_pca.pkl feature_scaler.pkl <you>@<SERVER>:/tmp/
sha256sum best.pt semantic_pca.pkl feature_scaler.pkl         # note these
```

On the **server**, then compare the checksums:

```bash
cd /opt/honeypot/app
sudo install -m 644 /tmp/best.pt            ml_analytics/artifacts/mt3_full_d256/best.pt
sudo install -m 644 /tmp/semantic_pca.pkl   honeypot_dataset/data/processed/semantic_pca.pkl
sudo install -m 644 /tmp/feature_scaler.pkl honeypot_dataset/data/final/feature_scaler.pkl
sha256sum ml_analytics/artifacts/mt3_full_d256/best.pt honeypot_dataset/data/processed/semantic_pca.pkl honeypot_dataset/data/final/feature_scaler.pkl
rm /tmp/best.pt /tmp/semantic_pca.pkl /tmp/feature_scaler.pkl
```

### A4. Python environment

```bash
sudo python3 -m venv /opt/honeypot/venv
sudo /opt/honeypot/venv/bin/pip install --upgrade pip
sudo /opt/honeypot/venv/bin/pip install torch==2.13.0 --index-url https://download.pytorch.org/whl/cpu
sudo /opt/honeypot/venv/bin/pip install -r /opt/honeypot/app/deploy/sandbox/requirements-pipeline.txt
```

Check the scikit-learn version matches the one that wrote the pickles (see `requirements-pipeline.txt`).

### A5. Settings

Find the address you are logging in from (the server tells you, no outside service needed):

```bash
echo "$SSH_CONNECTION" | cut -d' ' -f1
```

```bash
cd /opt/honeypot/app/deploy/sandbox
sudo install -m 640 -o root -g honeypot pipeline.env.example /etc/honeypot/pipeline.env
sudo install -m 644 guard.env.example /etc/honeypot-guard/guard.env
cp cowrie.env.example cowrie.env
sudoedit /etc/honeypot/pipeline.env         # un-comment MITIGATION_NEVER_BLOCK and put your address in it
sudoedit /etc/honeypot-guard/guard.env      # un-comment HONEYPOT_GUARD_NEVER_BLOCK, same address
```

Leave `MITIGATION_MODE=observe` and `MITIGATION_FIREWALL=0`. That is stage 0.

### A6. Firewall pieces

```bash
cd /opt/honeypot/app
sudo install -m 755 response_mitigation/host/apply_blocklist.py /opt/honeypot-guard/
sudo install -m 644 deploy/sandbox/egress.nft /opt/honeypot-guard/
sudo install -m 644 response_mitigation/host/honeypot-guard.service response_mitigation/host/honeypot-guard.timer \
                    deploy/sandbox/systemd/honeypot-egress.service deploy/sandbox/systemd/honeypot-pipeline.service \
                    /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-egress.service honeypot-guard.timer
```

### A7. Start Cowrie

```bash
cd /opt/honeypot/app/deploy/sandbox
sudo docker compose --env-file ./cowrie.env up -d
sudo docker compose --env-file ./cowrie.env ps
```

The first start downloads the Cowrie image. If the container keeps restarting, run
`sudo docker compose --env-file ./cowrie.env logs cowrie`. One thing to try: this file drops all Linux
capabilities from the container (`cap_drop: [ALL]`). That is expected to work (Cowrie only needs port 2222 and no
special rights) but has not been run against the real image yet. If the log points at permissions, remove that line, start again,
and tell us.

### A8. Start the pipeline

```bash
sudo systemctl enable --now honeypot-pipeline.service
journalctl -u honeypot-pipeline -f           # Ctrl-C to leave
```

The first start downloads DistilBERT (needs internet). Wait for `semantic encoder ready`. Then, so the server never
contacts the model hub again, set `HF_HUB_OFFLINE=1` in `/etc/honeypot/pipeline.env` and
`sudo systemctl restart honeypot-pipeline`.

### A9. Check

```bash
cd /opt/honeypot/app/deploy/sandbox
sudo ./verify_sandbox.sh
```

Fix every `FAIL`. A `WARN` about "no connections yet" is expected until A10.

### A10. Prove that Cowrie sees real attacker addresses

This is the Docker risk from the design: if the connection reaches the container through a proxy, **every attacker looks like
Docker's own address**, and a firewall block would hit the wrong IP. It cannot be tested from the server itself.

From a **second machine with a public address** (a laptop at home, a phone hotspot):

```bash
ssh -p 2222 root@<SERVER>        # any password; keep trying until you get a shell, run a few commands, then exit
```

Back on the server, with that machine's public address:

```bash
sudo ./verify_sandbox.sh --client-ip <ADDRESS_OF_THE_SECOND_MACHINE>
```

You want `PASS real addresses are visible` and `the client you used was seen with its real address`. If it shows `172.x.x.x`,
**stop**: do not go to part B, and do not turn on blocking.

Then, within about a minute, check the pipeline classified the session:

```bash
tail -n 1 /var/lib/honeypot/pipeline/pipeline_results.jsonl
tail -n 3 /var/lib/honeypot/mitigation/mitigation_audit.jsonl
```

### A11. Prove that a block really stops traffic (the Docker path)

The tests on Linux used plain network namespaces. This is the check with Docker's real port forwarding in the way.
Use the **second machine's** address as `X`. **Never your own admin address.**

```bash
sudo -u honeypot /opt/honeypot/venv/bin/python - <<'EOF'
import sys; sys.path.insert(0, "/opt/honeypot/app")
from pathlib import Path
from response_mitigation.blocklist import BlocklistFile
X = "PUT.THE.SECOND.MACHINE.ADDRESS.HERE"
BlocklistFile(Path("/var/lib/honeypot-guard/blocklist.json")).add(X, ttl_s=180, reason="manual block test", rule="manual")
print("blocked", X, "for 3 minutes")
EOF
sleep 20; sudo nft list set inet honeypot_guard blocked_v4        # X should be listed
```

From the second machine: `ssh -p 2222 -o ConnectTimeout=8 root@<SERVER>` should **hang and time out**. "Connection refused" would
mean something else is answering. Your own admin session must keep working. After 3 minutes the block ends by itself, and the second
machine can connect again. To end it sooner: `sudo touch /var/lib/honeypot-guard/MITIGATION_DISABLED`, wait 20 s, then
`sudo rm /var/lib/honeypot-guard/MITIGATION_DISABLED` (the entry has expired by then, so it will not come back).

If A9, A10 and A11 all pass, part A is done. Let it run on port 2222 for a day if you like.

---

## Part B: go public on port 22

Port 22 gets the real internet noise. Do this only after part A passes.

1. **Keep a way back in.** Know how to open your provider's web console or serial console. It is your recovery if SSH breaks.
2. **Cloud firewall:** allow your *new* admin port (these steps use **2200**) from your address only.
3. **Move your own SSH.** Ubuntu may start sshd through a socket, which ignores `Port` in `sshd_config`. Check:
   ```bash
   systemctl is-active ssh.socket
   ```
   - `inactive`: `sudo sed -i 's/^#\?Port .*/Port 2200/' /etc/ssh/sshd_config && sudo systemctl restart ssh`
   - `active`: `sudo systemctl edit ssh.socket`, add the two lines below, save, then
     `sudo systemctl daemon-reload && sudo systemctl restart ssh.socket`
     ```
     [Socket]
     ListenStream=
     ListenStream=2200
     ```
4. **From a new terminal**, check you can log in: `ssh -p 2200 <you>@<SERVER>`. **Only then** close the old session.
5. **Cloud firewall:** allow `22/tcp` from anywhere (IPv4). Remove 2222 if you no longer need it.
6. In `deploy/sandbox/cowrie.env` set `COWRIE_PUBLIC_PORT=22`, then:
   ```bash
   cd /opt/honeypot/app/deploy/sandbox
   sudo docker compose --env-file ./cowrie.env up -d
   sudo ./verify_sandbox.sh
   ```
7. Within minutes you should see real scans in `/opt/honeypot/app/honeypot_dataset/cowrie/logs/cowrie.json`.

**Back out:** set `COWRIE_PUBLIC_PORT=2222` and run the `up -d` command again, or `sudo docker compose --env-file ./cowrie.env down`.

---

## Running it

| Stage | What runs | Move on when |
|---|---|---|
| 0 (first week) | `MITIGATION_MODE=observe`. Decisions are logged as `would_apply`. | You read the audit log by hand and see no wrong calls. |
| 3 | Real blocks for abuse rules only, the same in every arm of the study | A week with no surprises. See `MITIGATION_DESIGN.md` section 13. |

To change the stage, edit `/etc/honeypot/pipeline.env` (`MITIGATION_MODE=enforce` *and* `MITIGATION_FIREWALL=1`
are both needed) and `sudo systemctl restart honeypot-pipeline`.

**Every day:** `sudo ./verify_sandbox.sh`, `df -h /var/lib`, `journalctl -u honeypot-pipeline --since yesterday | grep -i -E "error|traceback"`.

**Kill switch** (stops new decisions *and* removes every block within about 20 s):

```bash
sudo touch /var/lib/honeypot-guard/MITIGATION_DISABLED
sudo rm    /var/lib/honeypot-guard/MITIGATION_DISABLED      # resume; blocks that have not expired come back
```

**Collect data** (from your machine). These files hold other people's IPs, passwords and commands: keep them out of git and
out of shared folders.

```bash
rsync -a <you>@<SERVER>:/opt/honeypot/app/honeypot_dataset/cowrie/logs/ ./sandbox-data/cowrie/
rsync -a <you>@<SERVER>:/var/lib/honeypot/pipeline/ ./sandbox-data/pipeline/
rsync -a <you>@<SERVER>:/var/lib/honeypot/mitigation/ ./sandbox-data/mitigation/
rsync -a <you>@<SERVER>:/opt/honeypot/app/logs/honeypot_config_changes.jsonl ./sandbox-data/
```

Keep the output of `verify_sandbox.sh` (versions, image digest) with the data: it is the provenance for the paper.

**Stop everything:**

```bash
sudo systemctl disable --now honeypot-pipeline.service honeypot-guard.timer honeypot-egress.service
cd /opt/honeypot/app/deploy/sandbox && sudo docker compose --env-file ./cowrie.env down
```

---

## Where things live

| Thing | Path |
|---|---|
| Cowrie log (raw) | `/opt/honeypot/app/honeypot_dataset/cowrie/logs/cowrie.json*` |
| MT3 results (one line per session) | `/var/lib/honeypot/pipeline/pipeline_results.jsonl` |
| Decision log | `/var/lib/honeypot/mitigation/mitigation_audit.jsonl` |
| Block list (written by pipeline, read by root script) | `/var/lib/honeypot-guard/blocklist.json` |
| Kill-switch file | `/var/lib/honeypot-guard/MITIGATION_DISABLED` |
| Honeypot config changes | `/opt/honeypot/app/logs/honeypot_config_changes.jsonl` |
| Bait files the configurator plants | `/opt/honeypot/app/honeypot_dataset/cowrie/honeyfs/` |
| Settings | `/etc/honeypot/pipeline.env`, `/etc/honeypot-guard/guard.env`, `deploy/sandbox/cowrie.env` |

What leaves the server: threat-intel look-ups (NVD, EPSS, CISA) when a session mentions a CVE, and the one-time DistilBERT download.
Nothing from attacker sessions is sent anywhere.

## If the pipeline changes

The pipeline service may write to six folders only (`ReadWritePaths` in `systemd/honeypot-pipeline.service`). That list
came from recording every file the pipeline writes while it processes sessions. If someone adds a new output file in a new
place, the service would fail on the server. `tests/test_sandbox_writes.py` re-runs the recording and fails first:

```bash
pytest deploy/sandbox/tests                       # all consistency checks (needs the project venv)
python deploy/sandbox/tools/record_pipeline_writes.py    # shows the list by hand
sudo python3 -m unittest deploy.sandbox.tests.test_sandbox_egress_linux -v     # real firewall, Linux + root
```

## Known limits

- **Not run on a real server yet.** Tested here: the firewall and outbound block with real network traffic on Ubuntu 24.04;
  the systemd units under real systemd; the pipeline processing a Cowrie-format log with the real feature code, scaler,
  configurator and mitigation engine (only the trained model was a stand-in); the compose file's syntax. **Not tested:** the real
  Cowrie image (including `cap_drop`), Docker's port forwarding (A10, A11), the trained MT3 and DistilBERT, the package list on
  Python 3.12, the cloud.
- **IPv4 only.** IPv6 attackers cannot reach the honeypot. Publishing IPv6 through Docker would hide their real addresses.
- **Logins are `AuthRandom`** (in 2-5 tries). It is a study setting; keep it the same in every arm.
- **One honeypot.** `sensor_name` is in Cowrie's own log, but the pipeline does not copy it into `pipeline_results.jsonl`. A fleet needs that.
- **The hourly cap on new blocks resets when the pipeline restarts.**
- **After a restart the pipeline re-reads the whole Cowrie log** (it skips what it has already done). That is slow when the log is large.
- **No "unblock" command yet.** Remove the entry from `blocklist.json` or use the kill switch.
