# Adaptive Honeypot Gateway — React Dashboard (`frontend/`)

A React + Vite + Tailwind dashboard for the pipeline. It is a **separate app**
that reads from the existing Flask API in `traffic_gateway/api.py` — no backend
code was changed to add it. The original HTML pages in `dashboard/static/`
(`/`, `/pipeline`, `/live` on port 5000) still work exactly as before.

| Piece | Port | Started by |
|---|---|---|
| Traffic gateway (attacker-facing) | 8080 | `demo/live_demo.py` / `run_pipeline` |
| Flask API + old HTML dashboard | 5000 | `traffic_gateway.api` / `run_pipeline` |
| **This React dashboard** | **5173** | `npm run dev` (below) |

No port clashes — this app only *calls* port 5000, it never listens on it.

## Requirements

Node.js 18 or newer (`node -v`). Nothing else; npm comes with Node.

## Run it

**Terminal 1 — start the API** (from the repo root, same as the README):

```powershell
.\honeypot_dataset\venv\Scripts\python.exe -m traffic_gateway.api --port 5000
# or the full pipeline, which also serves the API on :5000:
.\honeypot_dataset\venv\Scripts\python.exe -m traffic_gateway.run_pipeline
```

**Terminal 2 — start the dashboard:**

```powershell
cd frontend
npm install        # first time only
npm run dev
```

Open <http://localhost:5173>.

Do not also start `dashboard/backend.py` on port 5000 — it would collide with the API
(same rule as in the main README).

## Pointing it at a different API address

The API base URL defaults to `http://localhost:5000`. To change it (e.g. the
pipeline runs on another laptop in the two-laptop demo), copy `.env.example`
to `.env.local` and edit it:

```
VITE_API_BASE_URL=http://192.168.0.110:5000
```

Restart `npm run dev` after changing it. To open the dashboard from *another*
device on the LAN, run `npm run dev -- --host` and browse to
`http://<this-laptop's-LAN-IP>:5173` — and set `VITE_API_BASE_URL` to the LAN IP
too, since `localhost` would point at the viewer's own machine.

## Which pages show live data

| Page | Route | Data source |
|---|---|---|
| Dashboard | `/` | **Live** — `/api/live-feed` |
| Live Sessions, Session Details | `/sessions` | **Live** — `/api/live-feed` |
| Threat Analytics | `/analytics` | **Live** — `/api/live-feed` |
| MITRE Analysis | `/mitre` | **Live** — `/api/live-feed` |
| Logs | `/logs` | **Live** — `/api/live-access`, `/api/footprints` |
| Honeypot Configuration | `/adaptive` | **Live** — `/api/active-config`, `/api/config-changes` |
| CVE Intelligence, CVE Details | `/cve` | Mock data (`src/data/mockCves.js`) — `api.py` has no CVE endpoint |

Everything except the CVE pages reads the real pipeline. `/api/live-feed` is used
for the session pages rather than `/api/mt3-results` because it returns the whole
`pipeline_results.jsonl` row, which carries the duration, commands, login
attempts and the configurator's before/after config that the detail view needs.

`src/services/sessions.js` maps one of those rows to the shape the session
components expect. Three fields the API cannot supply — destination address,
source port, destination port — are reported as `null` and render as a dash
rather than being invented; see `UNAVAILABLE_FIELDS` in that file.

**"Active Sessions" always reads 0, by design.** MT3 classifies a session only
when it closes, because it needs the whole session for the temporal features, so
every row the pipeline emits is a finished session.

If the API isn't running, every live page shows a "disconnected" state rather
than breaking; start Terminal 1 and they recover. There is no longer a mock
fallback for the session pages — an empty dashboard means the pipeline has
genuinely classified nothing yet.

## Production build (optional)

```powershell
npm run build      # outputs to frontend/dist/ (gitignored)
npm run preview    # serves the built app on http://localhost:4173
```

## Layout

```
frontend/
├── src/
│   ├── services/api.js        ← every call to traffic_gateway/api.py lives here
│   ├── services/sessions.js   ← /api/live-feed row → session shape
│   ├── services/analytics.js  ← per-micro-state aggregates over those sessions
│   ├── hooks/                 ← useApiResource (loading/empty/error/unreachable)
│   ├── pages/                 ← one file per route
│   ├── components/            ← grouped by page; common/DataSection renders the
│   │                            five useApiResource states
│   └── data/mockCves.js       ← the one page with no endpoint behind it
├── .env.example            ← copy to .env.local to change the API URL
└── package.json
```
