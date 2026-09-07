"""Persistent Wazuh rule ID allocator."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from sigmwah.exceptions import IdRangeExhaustedError

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Allocation:
    wazuh_id: int
    sigma_key: str
    title: str
    allocated_at: str


class IdAllocator:
    """Map stable Sigma keys to Wazuh numeric IDs and persist them."""

    def __init__(
        self,
        path: Path,
        id_start: int = 100100,
        id_max: int = 119999,
    ) -> None:
        self.path = path
        self.id_start = id_start
        self.id_max = id_max
        self._allocations: dict[str, Allocation] = {}
        self._used: set[int] = set()
        self._next = id_start
        if path.exists():
            self._load()

    def allocate(self, sigma_key: str, title: str = "") -> int:
        existing = self._allocations.get(sigma_key)
        if existing is not None:
            return existing.wazuh_id
        wazuh_id = self._next_free()
        record = Allocation(
            wazuh_id=wazuh_id,
            sigma_key=sigma_key,
            title=title,
            allocated_at=datetime.now(tz=UTC).isoformat(timespec="seconds"),
        )
        self._allocations[sigma_key] = record
        self._used.add(wazuh_id)
        return wazuh_id

    def get(self, sigma_key: str) -> Allocation | None:
        return self._allocations.get(sigma_key)

    def list_allocations(self) -> list[Allocation]:
        return sorted(self._allocations.values(), key=lambda item: item.wazuh_id)

    def save(self) -> None:
        payload: dict[str, Any] = {
            "version": SCHEMA_VERSION,
            "id_start": self.id_start,
            "id_max": self.id_max,
            "next": self._next,
            "allocations": {
                key: {
                    "wazuh_id": alloc.wazuh_id,
                    "title": alloc.title,
                    "allocated_at": alloc.allocated_at,
                }
                for key, alloc in self._allocations.items()
            },
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def export_csv(self, dest: Path | TextIO) -> None:
        rows = self.list_allocations()
        close = False
        if isinstance(dest, Path):
            handle: TextIO = dest.open("w", encoding="utf-8", newline="")
            close = True
        else:
            handle = dest
        try:
            writer = csv.writer(handle)
            writer.writerow(["wazuh_id", "sigma_key", "title", "allocated_at"])
            for row in rows:
                writer.writerow([row.wazuh_id, row.sigma_key, row.title, row.allocated_at])
        finally:
            if close:
                handle.close()

    def _next_free(self) -> int:
        candidate = max(self._next, self.id_start)
        while candidate <= self.id_max and candidate in self._used:
            candidate += 1
        if candidate > self.id_max:
            raise IdRangeExhaustedError(
                f"No free Wazuh IDs left in range {self.id_start}-{self.id_max}"
            )
        self._next = candidate + 1
        return candidate

    def _load(self) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self._next = int(raw.get("next", self.id_start))
        for key, item in raw.get("allocations", {}).items():
            alloc = Allocation(
                wazuh_id=int(item["wazuh_id"]),
                sigma_key=key,
                title=str(item.get("title", "")),
                allocated_at=str(item.get("allocated_at", "")),
            )
            if self.id_start <= alloc.wazuh_id <= self.id_max:
                self._allocations[key] = alloc
                self._used.add(alloc.wazuh_id)
        if self._used:
            self._next = max(self._next, max(self._used) + 1)
