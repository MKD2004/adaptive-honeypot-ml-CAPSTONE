"""
src/extractors/payload.py
Group C — 24 Payload Statistical Features (fed to CNN branch)
Detects obfuscation, encoding, and encryption in command payloads.
"""
from __future__ import annotations
import math, re
from collections import Counter
import numpy as np

PAYLOAD_FEATURE_NAMES = [
    "entropy_shannon","entropy_renyi2","frac_printable","frac_hex_chars",  # 0-3
    "frac_uppercase","frac_lowercase","frac_digit","frac_special",         # 4-7
    "frac_null_bytes","frac_url_encoded","base64_likelihood",              # 8-10
    "log_payload_len","unique_byte_ratio","max_byte_run_log",              # 11-13
    "bigram_entropy","trigram_entropy","rle_compression_ratio",            # 14-16
    "mean_byte_val","std_byte_val",                                        # 17-18
    "token_count","mean_token_len","max_token_len",                        # 19-21
    "pipe_operator_count","redirect_operator_count",                       # 22-23
]
assert len(PAYLOAD_FEATURE_NAMES) == 24

_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS = set("0123456789abcdefABCDEF")
_URL_RE    = re.compile(r"%[0-9a-fA-F]{2}")


def _shannon(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data); n = len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())


def _renyi2(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data); n = len(data)
    sq_sum = sum((v/n)**2 for v in c.values())
    return -math.log2(sq_sum) if sq_sum > 0 else 0.0


def _ngram_entropy(data: bytes, n: int) -> float:
    if len(data) < n: return 0.0
    grams = [data[i:i+n] for i in range(len(data)-n+1)]
    c = Counter(grams); total = len(grams)
    return -sum((v/total)*math.log2(v/total) for v in c.values())


def _rle_ratio(data: bytes) -> float:
    if len(data) < 2: return 1.0
    n_runs = 1 + sum(1 for i in range(1, len(data)) if data[i] != data[i-1])
    return min(1.0, (n_runs * 2) / len(data))


def _max_run(data: bytes) -> int:
    if not data: return 0
    mx = cur = 1
    for i in range(1, len(data)):
        cur = cur+1 if data[i]==data[i-1] else 1
        mx = max(mx, cur)
    return mx


def extract_payload(session: dict) -> np.ndarray:
    """
    Extract 24 payload features.

    Expected keys:
        command_text (str)   : concatenated shell commands
        payload_hex  (str)   : hex-encoded raw payload bytes (optional)
    """
    cmd  = str(session.get("command_text","") or "")
    phex = str(session.get("payload_hex","")  or "")

    # Convert hex payload
    try:
        pbytes = bytes.fromhex(phex) if phex else b""
    except ValueError:
        pbytes = phex.encode("utf-8","replace")

    combined = cmd.encode("utf-8","replace") + pbytes
    if not combined:
        return np.zeros(24, dtype=np.float32)

    n      = len(combined)
    n_str  = len(cmd) + 1e-9
    tokens = cmd.split()

    entropy_sh  = _shannon(combined)
    entropy_r2  = _renyi2(combined)
    frac_print  = sum(1 for b in combined if 32<=b<=126) / n
    frac_hex    = sum(1 for c in cmd if c in _HEX_CHARS) / n_str
    frac_upper  = sum(1 for c in cmd if c.isupper())     / n_str
    frac_lower  = sum(1 for c in cmd if c.islower())     / n_str
    frac_digit  = sum(1 for c in cmd if c.isdigit())     / n_str
    frac_spec   = sum(1 for c in cmd if not c.isalnum() and c not in " \t\n") / n_str
    frac_null   = combined.count(0) / n
    frac_url    = len(_URL_RE.findall(cmd)) / (len(cmd)/3 + 1e-9)
    b64_like    = sum(1 for c in cmd if c in _B64_CHARS) / n_str

    log_len     = math.log1p(n)
    uniq_ratio  = len(set(combined)) / 256.0
    max_run_log = math.log1p(_max_run(combined))

    bigram_e    = _ngram_entropy(combined, 2)
    trigram_e   = _ngram_entropy(combined, 3)
    rle_ratio   = _rle_ratio(combined)

    arr         = np.frombuffer(combined, dtype=np.uint8).astype(np.float32)
    mean_bv     = float(arr.mean())
    std_bv      = float(arr.std())

    tok_cnt     = float(len(tokens))
    mean_tl     = float(np.mean([len(t) for t in tokens])) if tokens else 0.0
    max_tl      = float(max((len(t) for t in tokens), default=0))

    pipes       = float(cmd.count("|"))
    redirs      = float(cmd.count(">") + cmd.count("<"))

    feat = np.array([
        entropy_sh, entropy_r2, frac_print, frac_hex,
        frac_upper, frac_lower, frac_digit, frac_spec,
        frac_null, frac_url, b64_like,
        log_len, uniq_ratio, max_run_log,
        bigram_e, trigram_e, rle_ratio,
        mean_bv, std_bv,
        tok_cnt, mean_tl, max_tl,
        pipes, redirs,
    ], dtype=np.float32)

    return np.nan_to_num(feat, nan=0.0, posinf=1e6, neginf=0.0)
