from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


@dataclass
class RecoveryRecord:
    alert_id: str
    target: str
    status: str = "monitoring"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    cleared_at: Optional[datetime] = None
    notes: List[str] = field(default_factory=list)

    def close(self, note: str | None = None) -> None:
        self.status = "cleared"
        self.cleared_at = datetime.now(timezone.utc)
        if note:
            self.notes.append(note)


class RecoveryTracker:
    def __init__(self, max_records: int = 100):
        self.max_records = max(1, int(max_records))
        self.records: Dict[str, RecoveryRecord] = {}

    def _enforce_limit(self) -> None:
        while len(self.records) > self.max_records:
            oldest_key = next(iter(self.records))
            self.records.pop(oldest_key, None)

    def record_alert(self, alert_id: str, target: str, note: str | None = None) -> RecoveryRecord:
        if alert_id in self.records:
            record = self.records[alert_id]
            if note:
                record.notes.append(note)
            return record
        record = RecoveryRecord(alert_id=alert_id, target=target)
        if note:
            record.notes.append(note)
        self.records[alert_id] = record
        self._enforce_limit()
        return record

    def close_alert(self, alert_id: str, note: str | None = None) -> RecoveryRecord:
        record = self.records.get(alert_id)
        if record is None:
            record = RecoveryRecord(alert_id=alert_id, target="unknown")
            self.records[alert_id] = record
        record.close(note)
        return record

    def list_active(self) -> List[RecoveryRecord]:
        return [record for record in self.records.values() if record.status != "cleared"]

    def list_cleared(self) -> List[RecoveryRecord]:
        return [record for record in self.records.values() if record.status == "cleared"]
