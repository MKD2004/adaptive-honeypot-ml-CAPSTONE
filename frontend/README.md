# Adaptive Honeypot Gateway — React Dashboard (`frontend/`)

React + Vite + Tailwind dashboard for the live pipeline. Every page reads the
real Flask API in `traffic_gateway/api.py`; there is no mock data. The original
HTML pages (`/`, `/pipeline`, `/live` on port 5000) still work unchanged.

| Piece | Port | Started by |
|---|---|---|
| Traffic gateway (attacker-facing) | 8080 | `demo/live_demo.py` / `run_pipeline` |
| Flask API + old HTML dashboard | 5000 | `traffic_gateway.api` / `run_pipeline` |
| **This dashboard** | **5173** (dev) / 4173 (preview) | `npm run dev` / `npm run preview` |

## Run it

Node.js 18+ required.

```powershell
# Terminal 1 — the API (the full pipeline also serves it, and loads MT3)
.\honeypot_dataset\venv\Scripts\python.exe -m traffic_gateway.run_pipeline
# or API only:  .\honeypot_dataset\venv\Scripts\python.exe -m traffic_gateway.api --port 5000

# Terminal 2 — the dashboard
cd frontend
npm install        # first time only
npm run dev
```

Open <http://localhost:5173>. Don't also start `dashboard/backend.py` (it takes port 5000).

## How it talks to the API

The browser calls `/api/*` on the dashboard's own origin, and Vite's dev/preview
proxy forwards it to `http://localhost:5000`. So there's no CORS setup and no
hardcoded `localhost`. To show the dashboard on another laptop, run
`npm run dev -- --host` and open `http://<this-laptop's-LAN-IP>:5173`.

Copy `.env.example` to `.env.local` to change it:

- `VITE_API_PROXY_TARGET` — where the proxy forwards (default `http://localhost:5000`).
- `VITE_API_BASE_URL` — optional; call the API directly instead of through the proxy.

If the API is down, the top bar says **API offline** and each panel says how to
start it. Pages recover on their own when it comes back.

## Pages

| Page | Route | Endpoints | Refresh |
|---|---|---|---|
| Overview | `/` | `/api/stats`, `/api/live-feed`, `/api/active-config`, `/api/health` | 5 s |
| Live Access | `/access` | `/api/live-access`, `/api/footprints`, POST/DELETE `/api/blacklist` + `/api/whitelist` | 2 s |
| Classified Sessions | `/sessions` | `/api/live-feed?limit=500` | 5 s |
| Session Details | `/sessions/:id` | `/api/live-feed?limit=1000`, `/api/blacklist`, `/api/whitelist` | on open |
| Adaptive Honeypot | `/adaptive` | `/api/active-config`, `/api/config-changes`, `/api/threat-intel`, POST `/api/threat-intel/refresh` | 5–10 s |
| Threat Analytics | `/analytics` | `/api/live-feed?limit=1000`, `/api/stats` | 10 s |
| Access Lists | `/lists` | GET/POST/DELETE `/api/blacklist`, `/api/whitelist` | 5 s |
| MITRE Taxonomy | `/mitre` | `/api/live-feed?limit=1000` (counts only) | 10 s |
| Model & Dataset | `/model` | `/api/health` (loaded MT3 checkpoint) | 15 s |

The top bar polls `/api/health` every 5 s (API up, MT3 loaded, routing mode, and
the `ssh root@<lan-ip> -p 8080` command peers use).

Two pages also show reference data from the repo, not from the API. Both are in
`src/lib/schema.js`:

- the 45-state taxonomy (mirrors `honeypot_dataset/configs/schema.py`; 13 states
  are flagged real-anchored, per `DECISIONS.md` 2026-08-28);
- the offline model comparison from `STATUS.md`.

## Layout

```
frontend/src/
├── services/api.js       every call to traffic_gateway/api.py
├── hooks/useApiResource  loading / empty / error / unreachable + polling
├── lib/                  schema constants, formatters
├── pages/                one file per route
└── components/           common/, layout/, dashboard/, sessions/, adaptive/,
                          analytics/, mitre/
```

## Build

```powershell
npm run lint
npm run build      # -> frontend/dist/ (gitignored)
npm run preview    # serves dist/ on :4173, with the same /api proxy
```
