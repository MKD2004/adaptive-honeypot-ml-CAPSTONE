# Heralding deployment — status update

**From:** Anusha Shrivastava
**Date:** 15 Nov 2026
**Status:** ✅ Live and capturing real attack traffic since **2026-11-14 19:07 UTC**

---

## Summary

Heralding is running on the Oracle Cloud VM alongside Cowrie, which was left untouched. All 8 required services are up. The config file is being read; the default config is not in use. Logs are written to `~/heralding/` on the VM, and source IPs are real public addresses. The first real attacker appeared 51 minutes after start. About 150 sessions were recorded in the first hour.

**Go-ahead condition met:** non-local source IPs confirmed (e.g. `195.178.110.78` trying `root` / `solokey` over Telnet at 19:58 UTC).

---

## Deployment details

| Item | Value |
|---|---|
| VM provider | Oracle Cloud |
| VM shape | VM.Standard.E2.1.Micro |
| Region | ap-hyderabad-1 |
| Public IP | 129.225.126.161 |
| Heralding image | `sha256:8330d9b6b7003fdcddecfec3dc388e0315cf5ddd82efd67a7b5fd1abec445f48` (`heralding:local`) |
| Heralding source | github.com/johnnykv/heralding, commit `ac12724ab38c4e2fe78f07d1bc35e6e586ba69c0` |
| Started | 2026-11-14 19:07 UTC |
| Planned stop | on or after 2026-11-29 (2 weeks minimum) |
| Ports enabled | 21 (ftp), 23 (telnet), 25 (smtp), 80 (http), 110 (pop3), 143 (imap), 443 (https), 5900 (vnc) |
| Disabled | ssh, mysql, postgresql, mssql, rdp, socks5, pop3s, imaps, smtps; hash cracker off |
| Log location on VM | `~/heralding/log_session.json`, `log_session.csv`, `log_auth.csv` (plus `heralding.log`) |
| Restart policy | `unless-stopped` (survives VM reboot) |
| Capture notes | `~/heralding/CAPTURE_NOTES.txt` (filled in; "stopped" to be added at the end) |

---

## Steps completed

1. **Safety check:** Cowrie confirmed up (13 days) and still logging. All 8 Heralding ports confirmed free. Admin SSH on 22222 still works.
2. **Oracle security list:** 8 TCP ingress rules added from 0.0.0.0/0. The existing rules for 22 and 22222 are unchanged.
3. **VM firewall (iptables):** 8 ACCEPT rules added and saved with `netfilter-persistent`.
4. **Image built from source** on the VM, with two Dockerfile fixes (see below).
5. **Config written** using Heralding's real key names (see below).
6. **Container started** with the folder mounted as its working directory (`-v ~/heralding:/work -w /work`), publishing only the 8 ports.
7. **Verified:**
   - No `Using default config file` warning, so our config is being read.
   - Exactly 8 `Started ... capability` lines: ftp, telnet, smtp, http, pop3, imap, https, vnc.
   - `Test-NetConnection` from outside succeeded on ports 21 and 23.
   - Own FTP / Telnet tests appeared in `log_session.json` with the correct public source IP (171.76.81.68).
   - A test login (`test` / `test123` via curl) appeared in `log_auth.csv`.
   - Real attacker traffic appeared within an hour.
8. **CAPTURE_NOTES.txt** was created at the start of the capture, not at the end.

---

## ⚠️ Corrections needed in `docs/ANUSHA_HERALDING.md`

The runbook did not work as written. Anushka, please update the repo copy:

| Runbook said | Actually needed | Why |
|---|---|---|
| `logging:` → `session_json:` / `filename:` and `activate_sensors:` | `activity_logging:` → `file:` → `session_json_log_file`, `session_csv_log_file`, `authentication_log_file` | Heralding has no `logging:` or `activate_sensors:` keys, so those settings would be silently ignored. |
| Mount config to `/etc/heralding/heralding.yml` | Mount the folder as the working directory: `-v ~/heralding:/work -w /work` | Heralding reads `heralding.yml` from its current working directory and writes logs there. If it doesn't find the file, it falls back to the default config, which enables 16 services, including ssh, mysql and postgresql. |
| `honeynet/heralding:latest` image | Build from source: `git clone https://github.com/johnnykv/heralding.git` then `docker build -t heralding:local .` | The `honeynet/heralding` image isn't documented anywhere; the README only shows building from source. |
| Dockerfile used as-is | Change `python:3.9-slim-bullseye` to `python:3.9-slim-bookworm` | Debian 11 (bullseye) security packages now return 404, so the build fails. |
| Dockerfile used as-is | Add `WORKDIR /src` after `FROM base as build` | Without it, `COPY . .` copies the repo's `bin/` folder onto `/bin`, which is a symlink in bookworm, so the build fails. |
| `https:` with only `banner` | `https:` needs a `cert:` block under `protocol_specific_data` | Heralding reads the cert settings to generate `https.pem` and crashes on startup without them. |
| `nc -vz` from laptop | On Windows: `Test-NetConnection <IP> -Port 21` | `nc` isn't available on Windows. |

The corrected `heralding.yml` used on the VM is in `~/heralding/heralding.yml` and will be included in the final archive.

---

## Notes on the data

- **`destination_ip` in the logs is `172.17.0.2`** (the container's internal address), not the VM's public IP. `source_ip` is the real client address, verified against my own IP.
- **Sessions from `171.76.81.68` between 19:07 and 19:58 UTC are our own tests** and should be excluded from analysis.
- Some test sessions have `num_auth_attempts: 0`, because Windows' ftp client sends `OPTS UTF8 ON` first, which Heralding's fake FTP server rejects. Real bots log credentials normally (confirmed in `log_auth.csv`).
- Cowrie ran alongside throughout, unchanged (container `cowrie-honeypot`, port 22 → 2222).
- Both containers use restart policy `unless-stopped` (checked for Cowrie on 15 Nov), so both come back automatically after a VM reboot.

---

## Next steps

| When | Who | What |
|---|---|---|
| Now | Anushka | Update `docs/ANUSHA_HERALDING.md` with the corrections above |
| Every few days | Anusha | Health check: `docker ps \| grep heralding` and `wc -l ~/heralding/log_session.csv` |
| During capture | Anusha | Record any restarts, downtime or changes in the "anything odd" field of CAPTURE_NOTES.txt. Don't reboot the VM. |
| On/after 29 Nov 2026 | Anusha | Stop Heralding, fill in the "stopped" time, pack `~/heralding/` (logs + config + CAPTURE_NOTES.txt) and send it raw, unfiltered |
| After receiving logs | Team | Run the Heralding parser and add the second protocol to the dataset |
