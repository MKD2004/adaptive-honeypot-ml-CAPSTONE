# Heralding deployment — collection runbook

**For Anusha.** You already did the hard version of this: Cowrie in Docker on your
Oracle Cloud VM, 13 days, 114,490 sessions, zero malformed lines. This is the same
shape of job for a second honeypot, on the **same VM**, and it should take an
afternoon.

> ## ✅ DEPLOYED 2026-11-14 19:07 UTC — and this runbook was wrong in 7 places
>
> Anusha deployed it, hit seven errors in the instructions below, fixed them all
> on the VM, and wrote them up in `Heralding_deployment_update.md`. The steps here
> are corrected from her report and marked **CORRECTED**. The authoritative config
> is the one on the VM at `~/heralding/heralding.yml`, which comes with the final
> archive.
>
> **The dangerous one:** I told her to mount the config at
> `/etc/heralding/heralding.yml`. Heralding actually reads `heralding.yml` from
> its **working directory**, and when it does not find a config it **silently
> falls back to a default that enables 16 services, including ssh, mysql and
> postgresql** — the exact three this runbook says must never be on. Following my
> instructions would have produced the taxonomy-corrupting capture the runbook
> exists to prevent, with a reassuring-looking container running the whole time.
> She caught it by checking for the absence of the `Using default config file`
> warning, which is a better verification than anything I wrote.
>
> Status: live since 2026-11-14 19:07 UTC, 8 services, first real attacker 51
> minutes in, ~150 sessions in the first hour. Our parser reads her session format
> correctly — verified against the exact Telnet session she reported.

> Two people with similar names work on this project and an earlier draft of this
> file credited the wrong one. To be precise: **Anusha Shrivastava** runs the
> Oracle VM and produced the Cowrie capture; **Anushka Singh** wrote
> `deploy/sandbox`, the internet-facing Cowrie kit and runbook, plus the
> `response_mitigation` package. So if this runbook itself needs changing, ask
> Anushka. If it needs *running*, that is Anusha, because the VM is hers.

**Why we need it, in one line:** going from 8 days to 13 days of Cowrie produced
**2.5× the data and zero new attack classes**. Only a second protocol broadens
what the model can learn. That is measured, not assumed — `DATA_INTEGRITY.md`
section 3d.

**What Heralding is:** a credential-catching honeypot. It answers on FTP, Telnet,
HTTP, SMTP, POP3, IMAP, VNC and SOCKS5, accepts *any* login, and records every
username/password pair tried. No shell, no filesystem — it is much lower risk
than Cowrie.

---

## Ground rules

1. **Collection only.** Do not run the ML pipeline on the VM. Heralding writes
   logs, you send them to us, we run everything else on a laptop. Same as Cowrie.
2. **Leave Cowrie running.** Do not stop it, do not change its ports. We want
   both sensors on the same box at the same time so the data is comparable.
3. **Do not touch port 22 or 2222.** Cowrie owns those. Heralding gets its own
   ports, listed below.
4. **Keep your own SSH admin access on a separate high port, and confirm you can
   still log in on it BEFORE you add anything.** If you lock yourself out of the
   VM we lose the Cowrie capture too.
5. **MySQL, Postgres and MSSQL must stay OFF.** Explained in step 3 — this is not
   optional, it is a data-correctness requirement.

---

## Step 1 — pick the ports

Heralding can listen on many ports. Enable these eight and nothing else:

| protocol | port | why |
|---|---|---|
| ftp | 21 | heavily scanned, good credential volume |
| telnet | 23 | the classic IoT botnet target |
| smtp | 25 | credential stuffing against mail |
| http | 80 | web login brute force |
| pop3 | 110 | mail credentials |
| imap | 143 | mail credentials |
| https | 443 | web login brute force over TLS |
| vnc | 5900 | remote-desktop brute force |

All eight are protocols our parser already understands. **Do not add 3306
(MySQL), 5432 (Postgres) or 1433 (MSSQL)** — see step 3.

## Step 2 — open the ports, and remember Oracle has TWO firewalls

This is the step that costs people a day. **Opening the Oracle security list is
not enough.** Oracle's Ubuntu images also ship a local `iptables` rule that drops
almost everything, so the honeypot looks dead even though it is running fine.

**a) VCN security list** (Oracle web console):
Networking → Virtual Cloud Networks → your VCN → Security Lists → default →
Add Ingress Rules. One rule per port, source `0.0.0.0/0`, protocol TCP.

**b) The VM's own firewall** (over SSH, on the box):

```bash
# check what is there now
sudo iptables -L INPUT -n --line-numbers

# allow the eight honeypot ports
for p in 21 23 25 80 110 143 443 5900; do
  sudo iptables -I INPUT -p tcp --dport $p -j ACCEPT
done

# make it survive a reboot
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

**c) Verify from OUTSIDE the VM** — from your laptop, not from the VM:

```bash
nc -vz <VM_PUBLIC_IP> 21
nc -vz <VM_PUBLIC_IP> 23
```

If those do not connect, stop here and fix it. Everything after this depends on
traffic actually arriving.

## Step 3 — the config  **CORRECTED**

**The key names below are not the ones I originally wrote.** Heralding has no
`logging:` block and no `activate_sensors:` list — those settings would have been
read as unknown keys and silently ignored. The real structure is
`activity_logging:` → `file:` → `*_log_file`.

Create `~/heralding/heralding.yml` on the VM:

```yaml
# Heralding -- collection only. Credentials, no shell, no filesystem.
activity_logging:
  file:
    enabled: true
    session_csv_log_file: log_session.csv
    session_json_log_file: log_session.json
    authentication_log_file: log_auth.csv

# Enabling a capability is done by listing it here. There is no separate
# activate_sensors key. Anything NOT listed is off.
capabilities:
  ftp:    { enabled: true, port: 21,   timeout: 30, protocol_specific_data: { max_attempts: 3, banner: "220 FTP server ready", syst_type: "Unix" } }
  telnet: { enabled: true, port: 23,   timeout: 30, protocol_specific_data: { max_attempts: 3 } }
  smtp:   { enabled: true, port: 25,   timeout: 30, protocol_specific_data: { max_attempts: 3, banner: "220 smtp.local ESMTP" } }
  http:   { enabled: true, port: 80,   timeout: 30, protocol_specific_data: { banner: "", max_attempts: 3 } }
  pop3:   { enabled: true, port: 110,  timeout: 30, protocol_specific_data: { max_attempts: 3 } }
  imap:   { enabled: true, port: 143,  timeout: 30, protocol_specific_data: { max_attempts: 3 } }
  vnc:    { enabled: true, port: 5900, timeout: 30 }
  https:
    enabled: true
    port: 443
    timeout: 30
    protocol_specific_data:
      banner: ""
      max_attempts: 3
      # REQUIRED. Without a cert block Heralding crashes at startup trying to
      # generate https.pem.
      cert:
        common_name: "*"
        country: "US"
        state: "None"
        locality: "None"
        organization: "None"
        organizational_unit: "None"
        valid_days: 365
        serial_number: 0
```

### Why MySQL, Postgres and MSSQL must stay off

Our 45-class attack taxonomy has **no database-authentication class and no
SQL-injection class** — of 45 labels exactly one mentions web or HTTP. A captured
MySQL login attempt cannot be labelled honestly; it would have to be mapped to a
neighbouring class that does not fit, which quietly corrupts the training data.

**This is also the failure mode of getting the config path wrong**, which is why
step 4 insists on the working-directory mount and step 5 checks for the
default-config warning. A Heralding that cannot find its config turns these three
on by itself.

## Step 4 — build and run  **CORRECTED**

**Build from source.** The `honeynet/heralding` image I originally pointed at is
not documented anywhere; Heralding's own README only describes building from the
repo.

```bash
git clone https://github.com/johnnykv/heralding.git
cd heralding
```

**Two Dockerfile fixes are needed before it will build:**

```
1. python:3.9-slim-bullseye  ->  python:3.9-slim-bookworm
   Debian 11 security packages now 404, so the build fails partway.

2. Add `WORKDIR /src` immediately after `FROM base as build`
   Without it, `COPY . .` copies the repo's bin/ folder onto /bin, which is a
   symlink in bookworm, and the build fails.
```

Then:

```bash
docker build -t heralding:local .

mkdir -p ~/heralding          # put heralding.yml here first
cd ~/heralding

docker run -d \
  --name heralding \
  --restart unless-stopped \
  -v ~/heralding:/work -w /work \
  -p 21:21 -p 23:23 -p 25:25 -p 80:80 \
  -p 110:110 -p 143:143 -p 443:443 -p 5900:5900 \
  heralding:local
```

**`-v ~/heralding:/work -w /work` is the important part.** Heralding reads
`heralding.yml` from its working directory and writes its logs there too. Mounting
a single file at `/etc/heralding/heralding.yml` — which is what I originally said —
does not work, and the failure is silent.

Record the image digest now, while you have it:

```bash
docker inspect heralding --format '{{.Image}}'
```

## Step 5 — verify it is capturing REAL traffic

**The single best check, and it is not one I thought of.** Anusha's:

```bash
docker logs heralding 2>&1 | grep -i "default config"
```

**Any output here means your config was NOT read** and Heralding is running its
own 16-service default — including ssh, mysql and postgresql. Silence is what you
want. Then confirm exactly eight capabilities started:

```bash
docker logs heralding 2>&1 | grep -c "capability"     # expect 8
docker logs heralding 2>&1 | grep "capability"        # and check the names
```

On Windows, test reachability with PowerShell rather than `nc`, which is not
available there:

```powershell
Test-NetConnection <VM_PUBLIC_IP> -Port 21
Test-NetConnection <VM_PUBLIC_IP> -Port 23
```

Give it 30–60 minutes, then:

```bash
wc -l /var/log/heralding/log_session.csv
tail -3 /var/log/heralding/log_session.json
```

**The thing to check is the source addresses.** You should see real public IPs
from all over the world. If every address is `127.0.0.1` or starts with `172.`,
something is proxying and the capture is worthless — that is exactly the check
that proved the Cowrie data was genuine.

```bash
# how many distinct real sources so far
grep -oE '"source_ip": *"[^"]+"' /var/log/heralding/log_session.json \
  | sort -u | wc -l
```

A sanity check on your own, from your laptop — this should appear in the log
within seconds:

```bash
ftp <VM_PUBLIC_IP>        # try any username/password, it accepts everything
```

**Tell us the first time you see non-local source IPs.** That is the green light.

## Step 6 — send us the logs

Let it run **at least two weeks**. Longer is better; it costs nothing.

```bash
cd /var/log
sudo tar czf ~/heralding_$(date +%Y%m%d).tar.gz heralding/
ls -lh ~/heralding_*.tar.gz
```

Send that archive. **The file we actually need is `log_session.json`** — that is
what our parser reads. The CSVs are useful for cross-checking, so include them.

### One field we need you to record by hand

Please put a short text file in the archive, `CAPTURE_NOTES.txt`:

```
VM provider      : Oracle Cloud
VM shape         : (e.g. VM.Standard.A1.Flex, 4 OCPU / 24 GB)
region           : (e.g. ap-mumbai-1)
public IP        : (the VM's address during capture)
heralding image  : (output of: docker inspect heralding --format '{{.Image}}')
started          : (UTC date and time)
stopped          : (UTC date and time)
ports enabled    : 21 23 25 80 110 143 443 5900
anything odd     : restarts, config changes, downtime, anything you changed
```

This sounds bureaucratic and it is the thing we most regret not having for the
Cowrie capture. Without it we cannot say in the paper which software version
produced the data or over exactly what window, and we cannot reproduce it.

---

## Things we must know about this capture when we analyse it

From Anusha's deployment report. These are recorded here so they are not lost
between now and the archive arriving:

- **`destination_ip` is `172.17.0.2`**, the container's internal address, not the
  VM's public IP. Expected, and the same situation as Cowrie's `172.18.0.2`.
  `source_ip` is the real client address.
- **Sessions from `171.76.81.68` between 19:07 and 19:58 UTC on 2026-11-14 are
  Anusha's own tests and must be excluded from analysis.** This is the kind of
  thing that silently becomes a "finding" if nobody writes it down.
- **Some test sessions show `num_auth_attempts: 0`** because the Windows `ftp`
  client sends `OPTS UTF8 ON` first and Heralding's fake FTP server rejects it.
  Real bots log credentials normally. Our parser handles a zero-attempt session
  already — it labels it `RECON_IP_SCAN`, a bare connect — so this needs no code
  change, but a cluster of them at the start of the capture is explained.
- **Admin SSH is on port 22222** and was confirmed working before anything was
  changed. Cowrie still owns 22 → 2222 and was left untouched.
- Both containers use `restart unless-stopped`, so both survive a VM reboot.

**Our side is ready.** The parser was verified against the exact session she
reported — `root` / `solokey` over Telnet from `195.178.110.78` — and it produces
a contract-valid record labelled `ACCESS_BRUTE_SSH` with the naive-UTC timestamp
converted correctly. Nothing needs writing before the logs arrive.

---

## What NOT to do

- **Do not enable MySQL / Postgres / MSSQL.** Step 3 explains why.
- **Do not run the ML pipeline, MT3, or the traffic gateway on the VM.** Logs
  only.
- **Do not put real credentials anywhere on this box.** It is deliberately
  exposed to the internet. Treat the whole VM as compromised-by-design: no
  personal SSH keys you use elsewhere, no cloud API tokens, nothing reused.
- **Do not stop or reconfigure Cowrie.** We need both sensors running together.
- **Do not clean up or filter the logs before sending.** Send them raw, including
  anything that looks like junk. The junk is data — 45% of the Cowrie commands
  matched none of our rules, and those are some of the most interesting sessions.

## If something goes wrong

| symptom | almost certainly |
|---|---|
| No traffic at all after an hour | The second firewall. Re-read step 2b and test with `nc` from outside. |
| Container keeps restarting | A port is already taken — `sudo ss -tlnp \| grep -E ':(21\|23\|25\|80\|110\|143\|443\|5900)'`. Something else on the VM may own 80 or 443. |
| `log_session.json` stays empty but the CSV fills | The `session_json` logging block is not enabled or the path is wrong. Check step 3. |
| All source IPs are `172.x` | Docker is NATing. Tell us before collecting more — the data will not be usable. |
| Permission errors writing logs | `sudo chmod 755 /var/log/heralding` and restart the container. |

Anything else, send us `docker logs heralding --tail 100` and the output of
`sudo iptables -L INPUT -n` and we will work it out.

---

## Why this matters, so it is clear the work is worth it

Right now the project has **one** real sensor. Every one of 114,490 real sessions
maps to just 8 of our 45 attack classes, and 4 of those carry 99.7% of the
traffic. We cannot evaluate a 45-class model on 4 observed classes.

Heralding is the cheapest way to change that: it covers **authentication
behaviour across eight protocols** that Cowrie never sees, and our parser for it
is already written and tested (36 tests). Two weeks of your VM's time turns a
one-protocol dataset into a two-protocol one.

Thank you — the Cowrie capture was clean enough to use immediately, which is
rarer than it sounds.
