"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """TODO: store input + start timestamp keyed by request_id/user_id."""
        request_id = request_id or uuid.uuid4().hex
        self._open[request_id] = {
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "started_at": utc_now_iso(),
            "started_perf": time.perf_counter(),
        }
        return request_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
        action_type: str | None = None,
        reviewer_decision: str | None = None,
        reviewer_id: str | None = None,
    ):
        """TODO: store output, layer decision, latency; append to self.logs."""
        request_id = request_id or uuid.uuid4().hex
        opened = self._open.pop(request_id, None)
        started_perf = opened.get("started_perf") if opened else None
        latency_ms = (
            round((time.perf_counter() - started_perf) * 1000, 2)
            if started_perf is not None
            else None
        )
        record = {
            "request_id": request_id,
            "user_id": user_id,
            "input": opened.get("input") if opened else None,
            "output": text,
            "started_at": opened.get("started_at") if opened else None,
            "timestamp": utc_now_iso(),
            "latency_ms": latency_ms,
            "blocked": blocked,
            "layer": layer,
            "action_type": action_type,
            "reviewer_decision": reviewer_decision,
            "reviewer_id": reviewer_id,
        }
        self.logs.append(record)
        return record

    def export_json(self, filepath: str = "outputs/audit_log.json"):
        """Write logs to disk (JSON array)."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8")
        return path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
