"""
traffic_gateway/run_pipeline.py

Single command that brings the whole post-session system up: Flask API in a
background thread, KEV/EPSS pre-fetched, MT3 loaded into memory, then blocks on
the Cowrie log watcher. The gateway proxy itself (inspection_gateway) is a
separate long-running process and is NOT started here.

    python -m traffic_gateway.run_pipeline
"""
from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
from pathlib import Path

from . import api as gw_api
from .ext_paths import REPO_ROOT
from .post_session_pipeline import (
    DEFAULT_COWRIE_LOG_DIR,
    DEFAULT_POLL_SEC,
    DEFAULT_RESULTS_PATH,
    PostSessionPipeline,
)

log = logging.getLogger("traffic_gateway.run_pipeline")

DASHBOARD_URL = "http://localhost:3000"   # dev React server, if one is running


def _banner(pipe: PostSessionPipeline, info: dict, host: str, port: int,
            gateway_up: bool) -> None:
    api_host = "localhost" if host in ("0.0.0.0", "") else host
    mt3 = info.get("mt3", {})
    sem = "yes" if info.get("semantic_available") else "NO (Group D zero-filled)"
    n_logs = info.get("cowrie_logs_found", 0)
    print()
    print("  " + "=" * 62)
    print("  Pipeline ready:")
    print(f"    Gateway:    {'running (started separately)' if gateway_up else 'NOT DETECTED - start inspection_gateway separately'}")
    print(f"    MT3 model:  loaded ({mt3.get('n_params', 0):,} params, "
          f"{mt3.get('device', '?')}, val macro-F1 "
          f"{float(mt3.get('best_val_macro_f1') or 0):.4f})")
    print(f"    Semantic:   {sem}")
    print(f"    KEV cache:  {info.get('kev_count', 0):,} CVEs loaded")
    print(f"    Watching:   {info.get('cowrie_log_dir')}  "
          f"({n_logs} log file{'' if n_logs == 1 else 's'}, poll {pipe.poll_interval:.0f}s)")
    print(f"    Results:    {info.get('results_path')} "
          f"({info.get('already_processed', 0)} already processed)")
    print(f"    Configurator: {info.get('configurator')}")
    print(f"    Dashboard:  http://{api_host}:{port}/pipeline   (legacy view: /)")
    print(f"    React dev:  {DASHBOARD_URL}  (if running)")
    print(f"    API:        http://{api_host}:{port}/api/live-feed")
    print("  " + "=" * 62)
    if n_logs == 0:
        print(f"  NOTE: no {DEFAULT_COWRIE_LOG_DIR.name}/cowrie.json* files yet -- the watcher is")
        print("        idle until Cowrie writes one. Use demo/simulate_attack.py to")
        print("        drive the pipeline without a live honeypot.")
    print("  Ctrl-C to stop.\n", flush=True)


def _gateway_running(host: str = "127.0.0.1", port: int | None = None) -> bool:
    """Is something already listening on the gateway's proxy port?"""
    import socket

    from .config import CONFIG

    port = port or CONFIG.GATEWAY_PORT
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.35)
        return s.connect_ex((host, int(port))) == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Run the adaptive honeypot ML pipeline")
    ap.add_argument("--cowrie-log-dir", default=str(DEFAULT_COWRIE_LOG_DIR))
    ap.add_argument("--results", default=str(DEFAULT_RESULTS_PATH))
    ap.add_argument("--poll", type=float, default=DEFAULT_POLL_SEC)
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--from-start", action="store_true",
                    help="process the existing Cowrie backlog instead of tailing from EOF")
    ap.add_argument("--no-api", action="store_true", help="skip the Flask API")
    ap.add_argument("--no-watch", action="store_true",
                    help="start everything, then exit instead of blocking (smoke test)")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    # gateway_logger attaches its own stdout handler to the "traffic_gateway"
    # logger; without this every gateway line is printed twice (once by that
    # handler, once by root's).
    logging.getLogger("traffic_gateway").propagate = False

    # 3 + 4. Pre-fetch KEV/EPSS and load MT3 (both happen inside startup()).
    print("  loading MT3 + threat intel ...", flush=True)
    t0 = time.time()
    pipe = PostSessionPipeline(
        Path(args.cowrie_log_dir), Path(args.results), args.poll,
        from_start=args.from_start,
    )
    info = pipe.startup()
    log.info("startup complete in %.1fs", time.time() - t0)

    # 1. Flask API in a background thread.
    if not args.no_api:
        gw_api.configure(results_path=Path(args.results), pipeline=pipe)
        gw_api.start_event_stream()
        threading.Thread(
            target=lambda: gw_api.app.run(host=args.host, port=args.port,
                                          threaded=True, use_reloader=False),
            daemon=True, name="flask_api",
        ).start()
        time.sleep(0.6)   # let the socket bind before we print its URL

    _banner(pipe, info, args.host, args.port, _gateway_running())

    if args.no_watch:
        print("  --no-watch: everything started; exiting.")
        return 0

    # 2 + 6. Block on the watcher.
    try:
        pipe.watch()
    except KeyboardInterrupt:
        pass
    finally:
        pipe.stop()
        print("\n  pipeline stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
