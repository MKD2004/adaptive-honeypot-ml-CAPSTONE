"""
src/extractors/tls_host.py
Group F — 8 TLS/JA3 + Host Context Features (fed to CNN)
High-signal attacker fingerprinting. JA3 identifies attack tools
more reliably than IP addresses.
"""
from __future__ import annotations
import hashlib
import numpy as np

TLS_FEATURE_NAMES = [
    "ja3_hash_bucket","ja3_is_known_malicious","tls_version_num",
    "cipher_suite_count","cipher_suite_entropy","sni_domain_entropy",
    "attacker_repeat_visitor","geo_risk_score",
]
assert len(TLS_FEATURE_NAMES) == 8

# Subset of known-malicious JA3 hashes (Salesforce/Arkime threat intel)
# These identify Metasploit, Cobalt Strike, Nmap TLS probes
_KNOWN_MALICIOUS_JA3 = {
    "a0e9f5d64349fb13191bc781f81f42e1",  # Metasploit meterpreter
    "6734f37431670b3ab4292b8f60f29984",  # Cobalt Strike default
    "51c64c77e60f3980eea90869b68c58a8",  # Nmap TLS probe
    "c35b0e1ff4c170c1e8e9a2d8d8f3c2cd",  # curl default (low risk but common)
    "e7d705a3286e19ea42f587b6a00e55b3",  # Python requests default
}

_TLS_VERSION_MAP = {
    "SSLv3": 0.0, "TLSv1": 1.0, "TLSv1.1": 2.0,
    "TLSv1.2": 3.0, "TLSv1.3": 4.0,
}

# Country-level geo risk scores (0=low, 1=high) — simplified
_GEO_RISK = {
    "CN": 0.75, "RU": 0.80, "KP": 0.95, "IR": 0.85,
    "US": 0.30, "GB": 0.25, "DE": 0.20, "IN": 0.45,
    "BR": 0.50, "NL": 0.40, "UA": 0.65, "RO": 0.55,
}


def _entropy(items: list) -> float:
    import math
    from collections import Counter
    if not items: return 0.0
    c = Counter(items); n = len(items)
    return -sum((v/n)*math.log2(v/n) for v in c.values())


def compute_ja3_hash(cipher_suites: list[int],
                     extensions: list[int],
                     elliptic_curves: list[int]) -> str:
    """
    Compute JA3 fingerprint MD5 hash from TLS ClientHello parameters.
    https://github.com/salesforce/ja3
    """
    ja3_str = ",".join([
        "771",                                       # TLS version
        "-".join(str(c) for c in cipher_suites),
        "-".join(str(e) for e in extensions),
        "-".join(str(ec) for ec in elliptic_curves),
        "0-1-2",                                    # elliptic curve point formats
    ])
    return hashlib.md5(ja3_str.encode()).hexdigest()


def extract_tls_host(session: dict) -> np.ndarray:
    """
    Extract 8 TLS/host context features.

    Expected keys (all optional):
        ja3_hash         (str)       : MD5 JA3 hash string
        cipher_suites    (List[int]) : offered cipher suite IDs
        tls_version      (str)       : 'TLSv1.2', 'TLSv1.3', etc.
        sni_hostname     (str)       : Server Name Indication hostname
        src_country      (str)       : 2-letter ISO country code
        seen_before      (bool)      : IP seen in last 30 days
    """
    ja3_hash  = str(session.get("ja3_hash","") or "")
    ciphers   = session.get("cipher_suites", []) or []
    tls_ver   = str(session.get("tls_version","TLSv1.2") or "TLSv1.2")
    sni       = str(session.get("sni_hostname","") or "")
    country   = str(session.get("src_country","") or "").upper()
    seen      = float(bool(session.get("seen_before", False)))

    # JA3 bucket: MD5 → integer bucket for embedding
    ja3_bucket = 0.0
    if ja3_hash:
        try:
            ja3_bucket = int(ja3_hash[:4], 16) / 65535.0
        except ValueError:
            pass

    ja3_malicious = 1.0 if ja3_hash in _KNOWN_MALICIOUS_JA3 else 0.0
    tls_ver_num   = _TLS_VERSION_MAP.get(tls_ver, 3.0) / 4.0   # normalise 0-1

    cipher_count  = float(len(ciphers))
    cipher_entropy = _entropy(ciphers)

    # SNI entropy — DGA-generated domains have high character entropy
    sni_entropy = _entropy(list(sni.split(".")[0])) if sni else 0.0

    geo_risk = _GEO_RISK.get(country, 0.35)   # default mid risk for unknown

    feat = np.array([
        ja3_bucket, ja3_malicious, tls_ver_num,
        min(cipher_count / 20.0, 1.0),   # normalise to 0-1
        cipher_entropy, sni_entropy,
        seen, geo_risk,
    ], dtype=np.float32)

    return np.nan_to_num(feat, nan=0.0, posinf=1.0, neginf=0.0)
