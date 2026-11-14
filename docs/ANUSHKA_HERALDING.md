# Heralding deployment — collection runbook

**For Anushka.** You already did the hard version of this: Cowrie in Docker on an
Oracle Cloud VM, 13 days, 114,490 sessions, zero malformed lines. This is the same
shape of job for a second honeypot, on the **same VM**, and it should take an
afternoon.

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

## Step 3 — the config

Create `~/heralding/heralding.yml` on the VM:

```yaml
# Heralding — collection only. No shell, no filesystem, credentials only.
logging:
  # These three files are what we need. log_session.json is the one our parser
  # reads; the CSVs are a convenient cross-check.
  session_csv:
    enabled: true
    filename: /var/log/heralding/log_session.csv
  session_json:
    enabled: true
    filename: /var/log/heralding/log_session.json
  auth_csv:
    enabled: true
    filename: /var/log/heralding/log_auth.csv

activate_sensors: [ftp, telnet, smtp, http, pop3, imap, https, vnc]

capabilities:
  ftp:    { enabled: true, port: 21,   timeout: 30, protocol_specific_data: { max_attempts: 3, banner: "220 FTP server ready" } }
  telnet: { enabled: true, port: 23,   timeout: 30, protocol_specific_data: { max_attempts: 3 } }
  smtp:   { enabled: true, port: 25,   timeout: 30, protocol_specific_data: { max_attempts: 3, banner: "220 smtp.local ESMTP" } }
  http:   { enabled: true, port: 80,   timeout: 30, protocol_specific_data: { banner: "", max_attempts: 3 } }
  pop3:   { enabled: true, port: 110,  timeout: 30, protocol_specific_data: { max_attempts: 3 } }
  imap:   { enabled: true, port: 143,  timeout: 30, protocol_specific_data: { max_attempts: 3 } }
  https:  { enabled: true, port: 443,  timeout: 30, protocol_specific_data: { banner: "", max_attempts: 3 } }
  vnc:    { enabled: true, port: 5900, timeout: 30 }
```

### Why MySQL, Postgres and MSSQL must stay off

Our 45-class attack taxonomy has **no database-authentication class and no
SQL-injection class** — I checked: of 45 labels exactly one mentions web or HTTP.
So a captured MySQL login attempt cannot be labelled honestly. It would have to be
mapped to a neighbouring class that does not fit, which quietly corrupts the
training data.

We would rather have no database data than mislabelled database data. If you turn
those sensors on by accident, tell us — we can filter them out, but only if we
know.

## Step 4 — run it

```bash
sudo mkdir -p /var/log/heralding
sudo chmod 755 /var/log/heralding

docker run -d \
  --name heralding \
  --restart unless-stopped \
  -v ~/heralding/heralding.yml:/etc/heralding/heralding.yml:ro \
  -v /var/log/heralding:/var/log/heralding \
  -p 21:21 -p 23:23 -p 25:25 -p 80:80 \
  -p 110:110 -p 143:143 -p 443:443 -p 5900:5900 \
  honeynet/heralding:latest
```

Pin the version once it works (`docker image ls` to get the digest, then use it
instead of `latest`). We got caught by a Cowrie version drift already: your
capture came from a newer Cowrie than our docs recorded, and its close event
carries `duration_ms`, which the documented version does not emit. Nothing broke,
but we could not tell which version produced the data.

Check it started:

```bash
docker logs heralding --tail 30
docker ps | grep heralding
```

## Step 5 — verify it is capturing REAL traffic

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
