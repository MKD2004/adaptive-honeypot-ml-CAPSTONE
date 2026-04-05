# Adaptive Honeypot Gateway — Live Dashboard

Real-time cybersecurity monitoring dashboard for the UE23CS320A capstone project.

---

## Quick Start

### 1. Install dependencies
```bash
pip install -r dashboard/requirements.txt
```

### 2. Run the dashboard

**With your live gateway running:**
```bash
python dashboard/backend.py
```

**Demo mode (no gateway needed — great for panel presentations):**
```bash
python dashboard/backend.py --demo
```

**Custom log file path:**
```bash
python dashboard/backend.py --log-file /path/to/traffic_gateway/data/sessions.jsonl
```

---

## LAN Setup (Two Laptops → Gateway Machine)

```
Laptop A (Attacker 1)  ──┐
                         ├──► Gateway Machine (this machine, port 8080) ──► Dashboard :5000
Laptop B (Attacker 2)  ──┘
```

### Step 1 — Start the gateway
```bash
python -m traffic_gateway.inspection_gateway
```

### Step 2 — Start the dashboard
```bash
python dashboard/backend.py --host 0.0.0.0 --port 5000
```
The terminal will print:
```
  ▶  Dashboard:  http://192.168.x.x:5000
  ▶  LAN access: http://192.168.x.x:5000
```

### Step 3 — Connect attacker laptops
On **Laptop A** and **Laptop B**, run any of these to generate traffic:
```bash
# HTTP traffic to gateway
curl http://<gateway-ip>:8080/

# SSH attempt (Cowrie honeypot)
ssh user@<gateway-ip> -p 2222

# Rapid requests (triggers rate limiter)
for i in {1..30}; do curl -s http://<gateway-ip>:8080/ & done

# Brute force simulation
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<gateway-ip>:2222
```

### Step 4 — Open dashboard on any device
Open `http://<gateway-ip>:5000` in a browser.
Works on mobile too — share the URL with the panel.

---

## Dashboard Features

| Feature | Description |
|---|---|
| Live Event Feed | Every gateway event streams in with color-coded entries |
| IP Status Cards | One card per IP — status, risk score, byte counters |
| Connection Rate Chart | 40-second rolling window of connections/second |
| Status Distribution | Donut chart of unknown/suspicious/blocked/probation/whitelisted |
| Threat Level Bar | Aggregate threat score across all active IPs |
| Alert Banner | Flashes on blacklist, rate-limit, and whitelist events |
| Particle Background | Animated network topology (purely visual) |
| Demo Mode | Full attack scenario auto-plays if `--demo` is set |

---

## Event Colors

| Color | Meaning |
|---|---|
| Cyan | New connection received |
| Yellow | Routed to honeypot / suspicious |
| Green | Routed to backend / promoted to whitelist |
| Orange | Rate limit triggered / probation |
| Red | IP blacklisted / blocked |
| Purple | ML model assessment |

---

## File Structure

```
dashboard/
├── backend.py          ← FastAPI server + WebSocket + log tailer
├── requirements.txt
├── README.md
└── static/
    └── index.html      ← All frontend (HTML + CSS + JS, self-contained)
```
