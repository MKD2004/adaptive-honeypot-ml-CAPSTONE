# Adaptive Honeypot Gateway — Dashboard (frontend)

Real-time monitoring UI for the capstone. **This is the frontend reference** —
what the pages are, how they are served, and the API contract they consume.

Updated 2026-09-29 to match the live pipeline.

---

## The three pages (`dashboard/static/`)

All self-contained HTML+CSS+JS, no build step, no npm. They share one SOC/terminal
design system (CSS variables: `--bg-*`, `--neon-*`, Orbitron + JetBrains Mono).
They poll the API with `fetch()` on a timer (2–5 s); `index.html` also uses SSE.

| Page | Route | Shows | Endpoints it calls |
|---|---|---|---|
| `index.html` | `/` | Legacy gateway-event feed: live events, IP status cards, rate chart, status donut, threat bar | `/events` (SSE), `/api/state` |
| `pipeline.html` | `/pipeline` | MT3 feed: classified sessions, kill-chain phase distribution, active honeypot config, blacklist/whitelist controls | `/api/mt3-results`, `/api/stats`, `/api/active-config`, `/api/blacklist` (GET/POST/DELETE), `/api/whitelist` (GET/POST/DELETE) |
| `live.html` | `/live` | Live access control (the two-laptop demo): routing decisions with verdict+signals, connected-peers table with BLOCK/TRUST/RESET, honeypot footprints, MT3 classifications, active config | `/api/live-access`, `/api/footprints`, `/api/mt3-results`, `/api/active-config`, `/api/health`, `/api/blacklist` + `/api/whitelist` (GET/POST/DELETE) |

---

## How they are served (READ THIS FIRST)

**The real server is `traffic_gateway/api.py`** (Flask, port 5000). It serves all
three pages AND every `/api/*` endpoint AND the `/events` SSE stream. Start it via:

```bash
python -m traffic_gateway.run_pipeline      # loads MT3 too; serves the dashboard on :5000
# or, API only (no MT3 watcher):
python -m traffic_gateway.api --port 5000
```

`dashboard/backend.py` is **legacy**: it serves only `index.html` + `/events` (SSE
tailing the gateway log) and has **no `/api/*` endpoints**. It predates
`pipeline.html`/`live.html`. Use it only for the standalone legacy event view; the
full dashboard needs `traffic_gateway/api.py`. Its `--demo` mode still works for a
gateway-events-only presentation.

Interpreter: `honeypot_dataset/venv` (has Flask, flask-cors, watchdog, paramiko).

---

## API contract (what the frontend consumes)

CORS is enabled. All responses are JSON. Response shapes below are the keys the
pages rely on; see `traffic_gateway/api.py` for the authoritative full shape.

| Method + route | Returns (top-level keys) |
|---|---|
| `GET /api/live-feed?limit=50` | `count`, `results[]` (full pipeline records), `source` |
| `GET /api/mt3-results?limit=50` | `count`, `predictions[]`: `session_id, src_ip, timestamp, micro_state, phase, phase_name, honeypot_target, confidence, top3[], rule_label, gateway_score, kcvr_valid, config_changed` |
| `GET /api/stats` | `total_sessions, blocked_ips, whitelisted_ips, unique_attackers, ip_status_totals, phase_distribution[], micro_state_distribution[], honeypot_targets, mean_confidence, config_changes, alerts_fired, …` |
| `GET /api/live-access?limit=40` | `count`, `decisions[]` (`ts, ip, verdict, score, signals[], reason, target_type, destination, ip_status, is_blacklisted, is_whitelisted`), `peers[]`, `classifier_routing`, `real_backend`, `honeypots[]` |
| `GET /api/footprints?limit=60&ip=` | `count`, `footprints[]` (`ts, ip, observed_ip, session, kind, detail`), `log` |
| `GET /api/active-config` | `active_config{}` (interaction_level, phase, banner, fake_sensitive_files, fake_ssh_keys, alert, cve_profile, reason, …), `recent_changes[]`, `changes_this_run` |
| `GET /api/blacklist` / `GET /api/whitelist` | `count`, `blacklist[]` / `whitelist[]` (`ip, reason, risk_score, total_connections, last_seen`) |
| `POST /api/blacklist` / `POST /api/whitelist` | body `{ip, reason?}` → `{ok, ip, reason, status}` (201) |
| `DELETE /api/blacklist/<ip>` / `DELETE /api/whitelist/<ip>` | `{ok, ip, status}` (200) |
| `GET /api/active-config`, `GET /api/config-changes?limit=25` | honeypot config + change log |
| `GET /api/health` | `ok, time, lan_ip, gateway_port, classifier_routing, results_exist, pipeline_started, mt3` |
| `GET /events` (SSE), `GET /api/state`, `GET /api/demo` | legacy gateway-event stream (index.html) |

Verified 2026-09-29: every endpoint the three pages call exists in `api.py` — no
broken references.

---

## Frontend dev loop

1. `python -m traffic_gateway.api --port 5000` (serve pages + API without loading MT3).
2. To see data, either run `demo/simulate_attack.py` (writes pipeline results) or
   the full `demo/live_demo.py`.
3. Edit the HTML in `dashboard/static/`, refresh the browser — no build.

To change what data is available, edit endpoints in `traffic_gateway/api.py`; keep
the response keys in the table above in sync.

---

## File structure

```
dashboard/
├── backend.py          ← LEGACY Flask+SSE server (index.html only, no /api/*)
├── requirements.txt
├── README.md           ← this file
└── static/
    ├── index.html      ← gateway events (SSE)
    ├── pipeline.html   ← MT3 pipeline feed
    └── live.html       ← live access control (two-laptop demo)
```
