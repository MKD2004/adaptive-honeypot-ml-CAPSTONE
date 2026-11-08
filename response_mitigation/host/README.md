# Host firewall script (Linux only)

This folder is the only part of the project that touches the firewall.

**How it works.** The pipeline never runs a firewall command. It writes a list of IPs to
`blocklist.json`. A small script on the host reads that list and updates the Linux firewall
(`nftables`). A systemd timer runs the script every 15 seconds.

```
pipeline (no root)  --writes-->  blocklist.json  --read by-->  apply_blocklist.py (root)  -->  nftables
```

| File | What it is |
|---|---|
| `apply_blocklist.py` | The script. Python standard library only, so it can be copied to the host on its own. |
| `honeypot-guard.service` | Runs the script once, as root, with very few powers. |
| `honeypot-guard.timer` | Runs the service 20 s after boot, then 15 s after each run finishes. |

## Install (Ubuntu, as root or with sudo)

Run these from this folder. They are the same steps used in the WSL test.

```bash
sudo install -d -m 755 /opt/honeypot-guard /var/lib/honeypot-guard /etc/honeypot-guard
sudo install -m 755 apply_blocklist.py /opt/honeypot-guard/
sudo install -m 644 honeypot-guard.service honeypot-guard.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-guard.timer
```

Then do three things:

1. **Let the pipeline write the list.** Make `/var/lib/honeypot-guard` writable by the user that runs
   the pipeline (in Docker, the user inside the container, through a bind mount).
2. **Point the pipeline at the same files.** In the pipeline's environment:
   ```
   MITIGATION_BLOCKLIST_PATH=/var/lib/honeypot-guard/blocklist.json
   MITIGATION_KILL_FILE=/var/lib/honeypot-guard/MITIGATION_DISABLED
   ```
   If these two do not match the paths in the `.service` file, the script will not see the list
   and the kill switch will only stop one half.
3. **Protect your own address.** Put the address you log in from on the never-block list, in both places:
   ```
   # /etc/honeypot-guard/guard.env      (read by the script)
   HONEYPOT_GUARD_NEVER_BLOCK=203.0.113.9
   # pipeline environment               (read by the engine)
   MITIGATION_NEVER_BLOCK=203.0.113.9
   ```

Blocking stays off until the pipeline is switched on too: `MITIGATION_MODE=enforce` **and**
`MITIGATION_FIREWALL=1`. Until then DENY decisions are only logged as `would_apply`.

## Check it

```bash
sudo python3 /opt/honeypot-guard/apply_blocklist.py \
    --blocklist /var/lib/honeypot-guard/blocklist.json --dry-run     # shows changes, makes none
sudo nft list set inet honeypot_guard blocked_v4                      # what is blocked right now
journalctl -u honeypot-guard.service -n 20 -o cat                    # what the script said
```

## What the script will and will not do

- It blocks an IP only if it is a **public** address. Private, loopback, Docker-bridge, multicast and
  reserved ranges are always refused, whatever the file says.
- It refuses the host's own addresses and anything on the never-block list.
- Every block has an end time. The firewall removes it by itself; no second run is needed.
- If `blocklist.json` is broken (not JSON, too big, too many entries), the script refuses to run
  and leaves the firewall **as it is**. Blocks already in force stay.
- If the table is deleted or its drop rules disappear (for example the system reloads its firewall
  config), the next run rebuilds it.

## Kill switch

```bash
sudo touch /var/lib/honeypot-guard/MITIGATION_DISABLED     # within ~15 s every block is removed
sudo rm    /var/lib/honeypot-guard/MITIGATION_DISABLED     # resume
```

The same file also stops the pipeline from making new decisions. **Careful:** removing the file
brings back every block that has not expired. If a block was a mistake, delete its entry from
`blocklist.json` first. (A command for this arrives with the dashboard step.)

## Tests

- Any OS: `pytest response_mitigation/tests` (the Linux-only tests skip themselves).
- Real firewall, real TCP connections (Linux, root, `nftables` installed). It builds two throwaway
  network namespaces and does not touch the host's own firewall:
  ```bash
  sudo python3 -m unittest response_mitigation.tests.test_host_linux_integration -v
  ```

## Not covered yet

- **Docker.** The test uses plain network namespaces. It does not yet prove that a block applies to
  traffic that reaches Cowrie through a Docker-published port, or that Cowrie sees the attacker's real
  address (not Docker's `172.17.0.1`). Both must be checked on the real host before the sandbox goes live.
- **The cloud provider's own firewall** is a second layer and is not automated.
