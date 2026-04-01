"""
traffic_gateway
═══════════════

ML-Based Adaptive Honeypot Framework — Traffic Gateway Module

Public API:

    from traffic_gateway import InspectionGateway, blacklist_manager, promoter

    gw = InspectionGateway()
    asyncio.run(gw.serve_forever())

Submodule responsibilities:

    config              → All tunable parameters (edit here, not in logic files)
    gateway_logger      → Structured JSON event logging
    ip_classifier       → IP state machine (UNKNOWN/SUSPICIOUS/BLACKLISTED/PROBATION/WHITELISTED)
    blacklist_manager   → CRUD for blacklist + whitelist files
    session_tracker     → Per-session byte/payload/entropy tracking
    reputation_scorer   → Heuristic risk scoring (stub for CNN-LSTM)
    rate_limiter        → Per-IP sliding-window connection throttle
    proxy_handler       → Async transparent TCP proxy
    traffic_router      → Route each connection to honeypot or backend
    whitelist_promoter  → Background pipeline: BLACKLISTED → PROBATION → WHITELISTED
    inspection_gateway  → Main asyncio server (entry point)
"""
from .config            import CONFIG, GatewayConfig, Target
from .ip_classifier     import IPStatus, IPRecord, classifier
from .blacklist_manager import blacklist_manager
from .session_tracker   import session_tracker
from .rate_limiter      import rate_limiter
from .traffic_router    import router
from .whitelist_promoter import promoter
from .inspection_gateway import InspectionGateway

__all__ = [
    "CONFIG",
    "GatewayConfig",
    "Target",
    "IPStatus",
    "IPRecord",
    "classifier",
    "blacklist_manager",
    "session_tracker",
    "rate_limiter",
    "router",
    "promoter",
    "InspectionGateway",
]
