"""
src/extractors/network.py
Group B — 28 Network Flow Features (fed to CNN branch)
Spatial packet-level statistics for protocol-level attack signature detection.
"""
from __future__ import annotations
import math, numpy as np

NETWORK_FEATURE_NAMES = [
    "bytes_in","bytes_out","log_bytes_in","log_bytes_out",             # 0-3
    "bytes_ratio","bytes_asymmetry",                                    # 4-5
    "packets_in","packets_out","log_pkts_in","log_pkts_out",           # 6-9
    "mean_pkt_size_in","std_pkt_size_in","max_pkt_size_in",           # 10-12
    "mean_pkt_size_out","pkt_size_entropy_in",                        # 13-14
    "dst_port_norm","src_is_ephemeral","is_wellknown_port",           # 15-17
    "is_ssh_port","is_http_port","is_db_port","protocol_enc",         # 18-21
    "tcp_syn","tcp_ack","tcp_fin","tcp_rst",                          # 22-25
    "login_attempts","unique_dst_ports",                               # 26-27
]
assert len(NETWORK_FEATURE_NAMES) == 28

_PROTO_ENC = {"tcp":0.2,"udp":0.3,"ssh":0.5,"http":0.6,"https":0.7,"icmp":0.1}
_SSH_PORTS  = {22, 2222, 2022}
_HTTP_PORTS = {80, 443, 8080, 8000, 8443, 8888}
_DB_PORTS   = {3306, 5432, 1521, 27017, 6379, 5984}


def _byte_entropy(sizes: list) -> float:
    if not sizes: return 0.0
    arr = np.array(sizes, dtype=np.float64)
    arr = arr / (arr.sum() + 1e-9)
    arr = arr[arr > 0]
    return float(-np.sum(arr * np.log2(arr)))


def extract_network(session: dict) -> np.ndarray:
    """
    Extract 28 network features.

    Expected keys (all optional — defaults to 0):
        bytes_in, bytes_out, packets_in, packets_out,
        pkt_sizes_in (List[int]), pkt_sizes_out (List[int]),
        dst_port (int), src_port (int), protocol (str),
        tcp_flags (str),  login_attempts (int),
        unique_dst_ports (int)
    """
    eps = 1e-9
    bi  = float(session.get("bytes_in",    0) or 0)
    bo  = float(session.get("bytes_out",   0) or 0)
    pi  = float(session.get("packets_in",  max(1, int(bi / 512 + 1))) or 1)
    po  = float(session.get("packets_out", max(1, int(bo / 512 + 1))) or 1)

    total    = bi + bo + eps
    log_bi   = math.log1p(bi)
    log_bo   = math.log1p(bo)
    ratio    = bo / total
    asym     = abs(bi - bo) / total

    pkt_sizes_in  = session.get("pkt_sizes_in",  [])
    pkt_sizes_out = session.get("pkt_sizes_out", [])
    mps_in   = float(np.mean(pkt_sizes_in))  if pkt_sizes_in  else bi  / pi
    std_in   = float(np.std(pkt_sizes_in))   if pkt_sizes_in  else 0.0
    max_in   = float(np.max(pkt_sizes_in))   if pkt_sizes_in  else bi
    mps_out  = float(np.mean(pkt_sizes_out)) if pkt_sizes_out else bo  / po
    pse_in   = _byte_entropy(pkt_sizes_in)

    dst_port = int(session.get("dst_port", 22) or 22)
    src_port = int(session.get("src_port", 0)  or 0)
    protocol = str(session.get("protocol","ssh") or "ssh").lower()
    flags    = str(session.get("tcp_flags","") or "").upper()

    dst_norm      = dst_port / 65535.0
    src_ephemeral = float(src_port > 49151)
    is_wk         = float(0 < dst_port < 1024)
    is_ssh        = float(dst_port in _SSH_PORTS  or protocol == "ssh")
    is_http       = float(dst_port in _HTTP_PORTS or protocol in ("http","https"))
    is_db         = float(dst_port in _DB_PORTS)
    proto_enc     = _PROTO_ENC.get(protocol, 0.0)

    has_syn = float("SYN" in flags)
    has_ack = float("ACK" in flags)
    has_fin = float("FIN" in flags)
    has_rst = float("RST" in flags)

    login_attempts  = float(session.get("login_attempts", 0) or 0)
    unique_dst_ports = float(session.get("unique_dst_ports", 1) or 1)

    feat = np.array([
        bi, bo, log_bi, log_bo,
        ratio, asym,
        pi, po, math.log1p(pi), math.log1p(po),
        mps_in, std_in, max_in,
        mps_out, pse_in,
        dst_norm, src_ephemeral, is_wk,
        is_ssh, is_http, is_db, proto_enc,
        has_syn, has_ack, has_fin, has_rst,
        login_attempts, unique_dst_ports,
    ], dtype=np.float32)

    return np.nan_to_num(feat, nan=0.0, posinf=1e6, neginf=0.0)
