from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Iterable

from .models import AuditEntry


def _hash_json(payload: dict) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only hash chained audit log for integrity checks."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(self, actor_user_id: str, action: str, resource: str, payload: dict) -> AuditEntry:
        prev_hash = self._entries[-1].chain_hash if self._entries else "GENESIS"
        payload_hash = _hash_json(payload)
        chain_hash = hashlib.sha256(f"{prev_hash}:{payload_hash}".encode("utf-8")).hexdigest()
        entry = AuditEntry(
            id=str(uuid.uuid4()),
            actor_user_id=actor_user_id,
            action=action,
            resource=resource,
            created_at=datetime.now(timezone.utc),
            prev_hash=prev_hash,
            payload_hash=payload_hash,
            chain_hash=chain_hash,
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> Iterable[AuditEntry]:
        return tuple(self._entries)

    def validate_integrity(self) -> bool:
        prev_hash = "GENESIS"
        for entry in self._entries:
            expected = hashlib.sha256(f"{prev_hash}:{entry.payload_hash}".encode("utf-8")).hexdigest()
            if expected != entry.chain_hash:
                return False
            prev_hash = entry.chain_hash
        return True
