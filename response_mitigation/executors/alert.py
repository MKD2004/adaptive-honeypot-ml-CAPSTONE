"""
response_mitigation/executors/alert.py

ALERT: tell a human. For now the only sink is one WARNING line in the log.
A webhook / email sink is a later step (MITIGATION_DESIGN.md section 12, step 5).
"""
from __future__ import annotations

import logging
from typing import Optional

from ..models import PlannedAction, Verdict

log = logging.getLogger("response_mitigation.alert")


class LogAlertExecutor:
    def skip_reason(self, verdict: Verdict, planned: PlannedAction) -> Optional[str]:
        return None

    def apply(self, verdict: Verdict, planned: PlannedAction) -> str:
        log.warning("ALERT %s: %s", verdict.ip, planned.reason)
        return "written to the log"
