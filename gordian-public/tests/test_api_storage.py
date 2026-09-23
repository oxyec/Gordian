from __future__ import annotations

from pathlib import Path

from api.storage import RAMStorage, SQLiteStorage, create_storage


def test_ram_storage_crud_and_event_retention() -> None:
    storage = RAMStorage(max_events_per_scan=3)

    record = storage.create_scan({"target": "example.com"})
    assert record.scan_id
    assert storage.get_scan(record.scan_id) is not None

    record.status = "running"
    storage.update_scan(record)
    updated = storage.get_scan(record.scan_id)
    assert updated is not None
    assert updated.status == "running"

    storage.store_events(
        record.scan_id,
        [
            {"sequence": 1},
            {"sequence": 2},
            {"sequence": 3},
            {"sequence": 4},
        ],
    )
    events = storage.get_events(record.scan_id, limit=10)
    assert [event["sequence"] for event in events] == [2, 3, 4]

    assert storage.delete_scan(record.scan_id) is True
    assert storage.get_scan(record.scan_id) is None


def test_sqlite_storage_crud_and_event_readback(tmp_path: Path) -> None:
    db_path = tmp_path / "gordian-test.db"
    storage = SQLiteStorage(db_path=db_path)

    record = storage.create_scan({"target": "api.example.com"})
    assert record.scan_id

    record.stage = "running"
    record.progress_percent = 42.0
    storage.update_scan(record)

    fetched = storage.get_scan(record.scan_id)
    assert fetched is not None
    assert fetched.stage == "running"
    assert fetched.progress_percent == 42.0

    storage.store_events(record.scan_id, [{"type": "pipeline.start"}, {"type": "pipeline.done"}])
    events = storage.get_events(record.scan_id, limit=10)
    assert [event["type"] for event in events] == ["pipeline.start", "pipeline.done"]

    records = storage.list_scans(limit=5)
    assert len(records) == 1
    assert records[0].scan_id == record.scan_id

    assert storage.delete_scan(record.scan_id) is True
    assert storage.get_scan(record.scan_id) is None


def test_storage_factory_builds_supported_backends(tmp_path: Path) -> None:
    ram = create_storage("ram")
    sqlite = create_storage("sqlite", db_path=tmp_path / "factory.db")

    assert isinstance(ram, RAMStorage)
    assert isinstance(sqlite, SQLiteStorage)
