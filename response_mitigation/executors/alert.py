"""
response_mitigation/executors/alert.py

ALERT: tell a human.

Two sinks, used together:
  LogAlertExecutor      one WARNING line in the log. Always on.
  WebhookAlertExecutor  one message to a chat webhook (Slack, Discord or anything that accepts JSON).
                        Off unless MITIGATION_ALERT_WEBHOOK is set.

The webhook runs in a background thread. A slow or dead webhook can never delay the pipeline, and
a failure is logged (with the host name only, never the URL: chat webhook URLs are secrets).
At most MITIGATION_ALERT_MAX_PER_HOUR messages are sent per hour, so a bug or a busy attacker
cannot flood a channel. The message holds the attacker's address, the phase, the model's label,
the confidence and the rule, and nothing the attacker typed.
"""
from __future__ import annotations

import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from typing import Callable, Deque, List, Optional, Sequence
from urllib.parse import urlsplit

from ..models import PlannedAction, Verdict

log = logging.getLogger("response_mitigation.alert")

_MESSAGE_MAX = 1800          # Discord allows 2000 characters
_HOUR_S = 3600


class LogAlertExecutor:
    def skip_reason(self, verdict: Verdict, planned: PlannedAction) -> Optional[str]:
        return None

    def apply(self, verdict: Verdict, planned: PlannedAction) -> str:
        log.warning("ALERT %s: %s", verdict.ip, planned.reason)
        return "written to the log"


def alert_text(verdict: Verdict, planned: PlannedAction) -> str:
    """The message a person reads. Built only from what MT3 and the policy said."""
    text = (f"ALERT {verdict.ip}: {verdict.micro_state} "
            f"(phase {verdict.phase} {verdict.phase_name}, confidence {verdict.confidence:.0%}). "
            f"Rule: {planned.rule}. {planned.reason}")
    if verdict.session_id:
        text += f" Session {verdict.session_id}."
    text = " ".join(text.split())
    return text if len(text) <= _MESSAGE_MAX else text[:_MESSAGE_MAX - 1] + "…"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the webhook URL is the only place we agreed to send to."""

    def redirect_request(self, *args, **kwargs):
        return None


def _post_json(url: str, payload: dict, timeout_s: float) -> int:
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "honeypot-mitigation/1"})
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=timeout_s) as response:
        return response.status


class WebhookAlertExecutor:
    def __init__(self, url: str, *, max_per_hour: int = 30, timeout_s: float = 5.0,
                 post: Callable[[str, dict, float], int] = _post_json,
                 clock: Callable[[], float] = time.time, queue_size: int = 100) -> None:
        self._url = url
        self._host = urlsplit(url).hostname or "?"
        self._max, self._timeout, self._post, self._clock = max_per_hour, timeout_s, post, clock
        self._sent: Deque[float] = deque()
        self._queue: "queue.Queue[Optional[str]]" = queue.Queue(maxsize=queue_size)
        self._lock = threading.Lock()
        self._worker = threading.Thread(target=self._run, name="alert-webhook", daemon=True)
        self._worker.start()

    # -- the Executor interface --------------------------------------------
    def skip_reason(self, verdict: Verdict, planned: PlannedAction) -> Optional[str]:
        return None

    def apply(self, verdict: Verdict, planned: PlannedAction) -> str:
        with self._lock:
            now = self._clock()
            while self._sent and now - self._sent[0] >= _HOUR_S:
                self._sent.popleft()
            if len(self._sent) >= self._max:
                return f"webhook limit of {self._max} per hour reached; not sent"
            try:
                self._queue.put_nowait(alert_text(verdict, planned))
            except queue.Full:
                return "webhook queue is full; not sent"
            self._sent.append(now)
        return f"queued for the webhook at {self._host}"

    # -- background ---------------------------------------------------------
    def _run(self) -> None:
        while True:
            message = self._queue.get()
            try:
                if message is None:
                    return
                try:
                    status = self._post(self._url, {"text": message, "content": message}, self._timeout)
                    if not 200 <= int(status) < 300:
                        log.warning("alert webhook at %s answered HTTP %s", self._host, status)
                except urllib.error.HTTPError as exc:
                    log.warning("alert webhook at %s answered HTTP %s", self._host, exc.code)
                except Exception as exc:          # a dead webhook must never matter to anyone else
                    log.warning("alert webhook at %s failed: %s", self._host, type(exc).__name__)
            finally:
                self._queue.task_done()

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Wait until everything queued has been sent (or failed). For tests and shutdown."""
        deadline = time.monotonic() + timeout_s
        while self._queue.unfinished_tasks and time.monotonic() < deadline:
            time.sleep(0.01)
        return not self._queue.unfinished_tasks

    def close(self) -> None:
        self._queue.put(None)


class CompositeAlertExecutor:
    """Runs every sink. One failing sink does not stop the others."""

    def __init__(self, sinks: Sequence) -> None:
        self._sinks = list(sinks)

    def skip_reason(self, verdict: Verdict, planned: PlannedAction) -> Optional[str]:
        return None

    def apply(self, verdict: Verdict, planned: PlannedAction) -> str:
        notes: List[str] = []
        errors: List[Exception] = []
        for sink in self._sinks:
            try:
                notes.append(sink.apply(verdict, planned))
            except Exception as exc:
                log.exception("an alert sink failed")
                errors.append(exc)
        if errors and not notes:
            raise errors[0]
        return "; ".join(notes)
