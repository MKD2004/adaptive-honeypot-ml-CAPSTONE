"""
response_mitigation/host

The part that runs on the Linux honeypot host, outside the pipeline's Python.
apply_blocklist.py is deliberately self-contained; the rest of the package may
import from it (so the command text has one source), never the other way round.
"""
