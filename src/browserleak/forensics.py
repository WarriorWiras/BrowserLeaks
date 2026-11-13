"""Read-only Chrome History evidence inspection and bounded SQLite record recovery.


It handles small, inline table-leaf records, valid committed WAL frames and main-file
freelist/free-space remnants. It does not reconstruct overflow payloads or every
SQLite layout. Its results require ground-truth validation.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import sqlite3
import struct
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
URL_REGEX = re.compile(rb"https?://[\x21-\x7e]{4,400}")
MAX_RECORD = 4_000_000


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def chrome_to_utc(value: int | None) -> str:
    if value is None or value <= 0:
        return ""
    try:
        return (CHROME_EPOCH + timedelta(microseconds=value)).isoformat()
    except (OverflowError, ValueError):
        return ""


def page_size_from_header(content: bytes) -> int:
    if len(content) < 100 or content[:16] != b"SQLite format 3\x00":
        raise ValueError("Not a SQLite 3 database header")
    value = int.from_bytes(content[16:18], "big")
    size = 65536 if value == 1 else value
    if size < 512 or size > 65536 or size & (size - 1):
        raise ValueError("Invalid SQLite page size")
    return size


def decode_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for i in range(9):
        if offset + i >= len(data):
            raise ValueError("Truncated SQLite varint")
        byte = data[offset + i]
        if i == 8:
            return (value << 8) | byte, offset + 9
        value = (value << 7) | (byte & 0x7f)
        if byte < 128:
            return value, offset + i + 1
    raise ValueError("Invalid SQLite varint")


def decode_serial(serial: int, data: bytes, pos: int, encoding: str) -> tuple[Any, int]:
    if serial == 0:
        return None, pos
    if serial in (8, 9):
        return serial - 8, pos
    widths = {1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8}
    if serial in widths:
        size = widths[serial]
        if pos + size > len(data):
            raise ValueError("Truncated SQLite value")
        raw = data[pos:pos + size]
        if serial == 7:
            return struct.unpack(">d", raw)[0], pos + size
        return int.from_bytes(raw, "big", signed=True), pos + size
    if serial < 12:
        raise ValueError("Reserved SQLite serial type")
    size = (serial - 12) // 2
    if size > MAX_RECORD or pos + size > len(data):
        raise ValueError("Invalid SQLite string/blob length")
    raw = data[pos:pos + size]
    if serial % 2:
        return raw.decode(encoding, errors="replace"), pos + size
    return raw.hex(), pos + size


def decode_record(payload: bytes, encoding: str) -> list[Any]:
    header_len, offset = decode_varint(payload, 0)
    if header_len > len(payload) or header_len < offset:
        raise ValueError("Invalid SQLite record header")
    serials = []
    while offset < header_len:
        serial, offset = decode_varint(payload, offset)
        serials.append(serial)
        if len(serials) > 100:
            raise ValueError("Too many record columns")
    pos = header_len
    values = []
    for serial in serials:
        value, pos = decode_serial(serial, payload, pos, encoding)
        values.append(value)
    return values


def inline_payload_size(payload_size: int, usable: int) -> int:
    """SQLite table leaf local payload calculation (does not follow overflow)."""
    maximum = usable - 35
    minimum = ((usable - 12) * 32 // 255) - 23
    if payload_size <= maximum:
        return payload_size
    local = minimum + (payload_size - minimum) % (usable - 4)
    return minimum if local > maximum else local


def table_leaf_rows(page: bytes, page_number: int, usable: int, encoding: str) -> list[dict]:
    start = 100 if page_number == 1 else 0
    if len(page) < start + 8 or page[start] != 0x0d:
        return []
    count = int.from_bytes(page[start + 3:start + 5], "big")
    if count > (usable - start - 8) // 2:
        return []
    rows = []
    for index in range(count):
        ptr_offset = start + 8 + 2 * index
        ptr = int.from_bytes(page[ptr_offset:ptr_offset + 2], "big")
        try:
            if ptr <= 0 or ptr >= usable:
                continue
            size, pos = decode_varint(page, ptr)
            rowid, pos = decode_varint(page, pos)
            if size <= 0 or size > MAX_RECORD:
                continue
            local = inline_payload_size(size, usable)
            if local != size:  # Cannot safely reconstruct overflow pages yet.
                continue
            if pos + size > usable:
                continue
            values = decode_record(page[pos:pos + size], encoding)
            rows.append({"rowid": rowid, "values": values, "offset": ptr})
        except (ValueError, IndexError, OverflowError):
            continue
    return rows


def free_regions(page: bytes, page_number: int, usable: int) -> list[tuple[int, bytes, str]]:
    start = 100 if page_number == 1 else 0
    if len(page) < start + 8 or page[start] != 0x0d:
        return []
    count = int.from_bytes(page[start + 3:start + 5], "big")
    if count > (usable - start - 8) // 2:
        return []
    regions = []
    content_start = int.from_bytes(page[start + 5:start + 7], "big") or 65536
    array_end = start + 8 + 2 * count
    if array_end < content_start <= usable:
        regions.append((array_end, page[array_end:content_start], "unallocated"))
    free = int.from_bytes(page[start + 1:start + 3], "big")
    visited = set()
    while free and free not in visited and free + 4 <= usable:
        visited.add(free)
        next_free = int.from_bytes(page[free:free + 2], "big")
        length = int.from_bytes(page[free + 2:free + 4], "big")
        if length < 4 or free + length > usable:
            break
        regions.append((free + 4, page[free + 4:free + length], "freeblock"))
        free = next_free
    return regions


def iter_freelist_leaf_pages(database: bytes, page_size: int) -> list[tuple[int, bytes]]:
    first_trunk = int.from_bytes(database[32:36], "big")
    results = []
    seen = set()
    trunk = first_trunk
    max_page = len(database) // page_size
    while trunk and trunk not in seen and 1 <= trunk <= max_page:
        seen.add(trunk)
        data = database[(trunk - 1) * page_size:trunk * page_size]
        next_trunk = int.from_bytes(data[:4], "big")
        n = int.from_bytes(data[4:8], "big")
        if n > (page_size - 8) // 4:
            break
        for i in range(n):
            number = int.from_bytes(data[8 + i * 4:12 + i * 4], "big")
            if 1 <= number <= max_page and number not in seen:
                seen.add(number)
                results.append((number, database[(number - 1) * page_size:number * page_size]))
        trunk = next_trunk
    return results


def update_checksum(data: bytes, state: tuple[int, int], order: str) -> tuple[int, int]:
    if len(data) % 8:
        raise ValueError("WAL checksum requires an 8-byte multiple")
    a, b = state
    for offset in range(0, len(data), 8):
        x, y = struct.unpack_from(order + "II", data, offset)
        a = (a + x + b) & 0xffffffff
        b = (b + y + a) & 0xffffffff
    return a, b


def committed_wal_frames(raw: bytes, expected_page_size: int) -> tuple[list[dict], list[str]]:
    warnings = []
    if not raw:
        return [], warnings
    if len(raw) < 32:
        return [], ["WAL header is incomplete"]
    magic = int.from_bytes(raw[0:4], "big")
    if magic not in (0x377f0682, 0x377f0683):
        return [], ["Invalid WAL magic"]
    byteorder = "<" if magic == 0x377f0682 else ">"
    wal_page_size = int.from_bytes(raw[8:12], "big")
    wal_page_size = 65536 if wal_page_size == 1 else wal_page_size
    if wal_page_size != expected_page_size:
        return [], ["WAL page size does not match SQLite database"]
    state = update_checksum(raw[:24], (0, 0), byteorder)
    if state != struct.unpack(">II", raw[24:32]):
        return [], ["WAL header checksum failed"]
    salt = raw[16:24]
    parsed = []
    pos = 32
    frame_number = 0
    while pos + 24 + wal_page_size <= len(raw):
        frame_number += 1
        header = raw[pos:pos + 24]
        data = raw[pos + 24:pos + 24 + wal_page_size]
        if header[8:16] != salt:
            warnings.append("WAL frame salt changed, stopped at frame " + str(frame_number))
            break
        frame_state = update_checksum(header[:8] + data, state, byteorder)
        if frame_state != struct.unpack(">II", header[16:24]):
            warnings.append("WAL frame checksum failed at frame " + str(frame_number))
            break
        page_number, db_pages = struct.unpack(">II", header[:8])
        if page_number < 1:
            warnings.append("Invalid WAL page number")
            break
        parsed.append({"frame": frame_number, "page": page_number,
                       "data": data, "commit": bool(db_pages)})
        state = frame_state
        pos += 24 + wal_page_size
    # Frames after the last commit may belong to an unfinished transaction.
    last_commit = max((i for i, f in enumerate(parsed) if f["commit"]), default=-1)
    if last_commit < 0 and parsed:
        warnings.append("No committed WAL transaction found")
    if last_commit + 1 < len(parsed):
        warnings.append("Excluded uncommitted WAL frames")
    return parsed[:last_commit + 1], warnings


def _looks_like_url(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(("http://", "https://"))


def _extract_rows(rows: list[dict], columns: dict, source: str, page: int, frame: int | None,
                  urls: list[dict], visits: list[dict]) -> None:
    for row in rows:
        vals = row["values"]
        for table, target in (("urls", urls), ("visits", visits)):
            schema = columns.get(table, [])
            if not schema or len(vals) != len(schema):
                continue
            record = dict(zip(schema, vals))
            if "id" in record and record["id"] is None:
                record["id"] = row["rowid"]
            if table == "urls":
                if not _looks_like_url(record.get("url")):
                    continue
            else:
                if not (isinstance(record.get("url"), int)
                        and isinstance(record.get("visit_time"), int)
                        and record["visit_time"] > 0):
                    continue
            target.append({"record": record, "source": source, "page": page,
                           "frame": frame, "offset": row["offset"]})


def _extract_fragments(page: bytes, page_number: int, page_size: int,
                       source: str, frame: int | None, fragments: list[dict]) -> None:
    for base, data, region in free_regions(page, page_number, page_size):
        for hit in URL_REGEX.finditer(data):
            url = hit.group().decode("ascii", errors="replace")
            # URL carving provides a clue, not proof of a complete history visit.
            fragments.append({"url": url, "source": source + ":" + region,
                              "page": page_number, "frame": frame,
                              "offset": base + hit.start()})


def _active_database(evidence_dir: Path) -> tuple[dict, dict, dict]:
    """Open a private disposable copy so SQLite never writes into source evidence."""
    with tempfile.TemporaryDirectory(prefix="browserleak_") as tmp:
        for name in ("History", "History-wal", "History-shm"):  # a hot -journal would be rolled back
            origin = evidence_dir / name
            if origin.is_file():
                shutil.copy2(origin, Path(tmp) / name)
        connection = sqlite3.connect(str(Path(tmp) / "History"))
        try:
            connection.execute("PRAGMA query_only=ON")
            schema = {}
            active = {}
            for table in ("urls", "visits"):
                found = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
                ).fetchone()
                if not found:
                    raise ValueError("Missing Chrome History table: " + table)
                schema[table] = [r[1] for r in connection.execute(f"PRAGMA table_info({table})")]
                cursor = connection.execute(f"SELECT * FROM {table}")
                active[table] = [dict(zip([c[0] for c in cursor.description], row))
                                 for row in cursor.fetchall()]
            settings = {key: connection.execute(f"PRAGMA {key}").fetchone()[0]
                        for key in ("page_size", "freelist_count")}
            return schema, active, settings
        finally:
            connection.close()


def analyse(evidence_dir: Path) -> dict:
    start = time.perf_counter()
    evidence_dir = Path(evidence_dir).resolve()
    history_path = evidence_dir / "History"
    if not history_path.is_file():
        raise FileNotFoundError(f"Missing History file in {evidence_dir}")
    raw = history_path.read_bytes()
    size = page_size_from_header(raw)
    usable = size - raw[20]
    encoding_map = {1: "utf-8", 2: "utf-16-le", 3: "utf-16-be"}
    encoding = encoding_map.get(int.from_bytes(raw[56:60], "big"), "utf-8")
    if len(raw) % size:
        raise ValueError("Main database file is not a whole number of pages")

    input_hashes = {name: sha256(evidence_dir / name)
                    for name in ("History", "History-wal", "History-shm", "History-journal")
                    if (evidence_dir / name).is_file()}
    schema, active, settings = _active_database(evidence_dir)
    # These settings belong to Chrome's own connection, not the file, so they are
    # derived from the file header and the evidence files instead of a PRAGMA here.
    settings["journal_mode"] = ("wal" if raw[18] == 2 and raw[19] == 2 else
                                "rollback journal (Chrome uses TRUNCATE when not in WAL mode)")
    settings["journal_files_present"] = sorted(
        name for name in ("History-wal", "History-journal") if (evidence_dir / name).is_file())
    settings["secure_delete"] = ("not stored in the database file; Chrome compiles SQLite with "
                                 "SQLITE_SECURE_DELETE, so deleted records are overwritten with zeros by default")
    url_records, visit_records, fragments = [], [], []

    for i in range(len(raw) // size):
        number = i + 1
        page = raw[i * size:(i + 1) * size]
        _extract_rows(table_leaf_rows(page, number, usable, encoding), schema,
                      "main_database", number, None, url_records, visit_records)
        _extract_fragments(page, number, usable, "main_database", None, fragments)

    free_pages = iter_freelist_leaf_pages(raw, size)
    for number, page in free_pages:
        _extract_rows(table_leaf_rows(page, number, usable, encoding), schema,
                      "freelist", number, None, url_records, visit_records)

    wal_path = evidence_dir / "History-wal"
    frames, warnings = committed_wal_frames(wal_path.read_bytes(), size) if wal_path.is_file() else ([], [])
    for frame in frames:
        number = frame["page"]
        data = frame["data"]
        _extract_rows(table_leaf_rows(data, number, usable, encoding), schema,
                      "wal", number, frame["frame"], url_records, visit_records)
        _extract_fragments(data, number, usable, "wal", frame["frame"], fragments)

    active_visits = {(r.get("id"), r.get("url"), r.get("visit_time")) for r in active["visits"]}
    active_urls = {(r.get("id"), r.get("url")) for r in active["urls"]}
    # URL dictionary intentionally combines historical and currently active records.
    historical_urls: dict[int, list[dict]] = {}
    for r in url_records:
        historical_urls.setdefault(r["record"]["id"], []).append(r)
    for r in active["urls"]:
        historical_urls.setdefault(r["id"], []).append({"record": r, "source": "active",
                                                        "page": None, "frame": None, "offset": None})

    candidates = []
    seen_visits = set()
    for row in visit_records:
        r = row["record"]
        key = (r.get("id"), r.get("url"), r.get("visit_time"))
        if key in active_visits or key in seen_visits:
            continue
        seen_visits.add(key)
        possible_urls = historical_urls.get(r["url"], [])
        for u in possible_urls:
            if not _looks_like_url(u["record"].get("url")):
                continue
            candidates.append({"level": "visit", "url": u["record"]["url"],
                               "visit_id": r["id"], "url_id": r["url"],
                               "visit_time_raw": r["visit_time"],
                               "visit_time_utc": chrome_to_utc(r["visit_time"]),
                               "source": row["source"], "url_source": u["source"],
                               "page": row["page"], "frame": row["frame"],
                               "offset": row["offset"], "status": "candidate"})
        if not possible_urls:
            warnings.append(f"Visit {r['id']} was found without a matching URL record")

    seen_url = set()
    for entry in url_records:
        r = entry["record"]
        key = (r["id"], r["url"])
        if key in active_urls or key in seen_url:
            continue
        seen_url.add(key)
        candidates.append({"level": "url_only", "url": r["url"],
                           "visit_id": None, "url_id": r["id"], "visit_time_raw": None,
                           "visit_time_utc": "", "source": entry["source"],
                           "url_source": entry["source"], "page": entry["page"],
                           "frame": entry["frame"], "offset": entry["offset"],
                           "status": "partial_candidate"})

    seen_fragment = set()
    for entry in fragments:
        key = (entry["url"], entry["source"], entry["page"], entry["offset"])
        if key in seen_fragment:
            continue
        seen_fragment.add(key)
        candidates.append({"level": "url_fragment", "url": entry["url"],
                           "visit_id": None, "url_id": None, "visit_time_raw": None,
                           "visit_time_utc": "", "source": entry["source"],
                           "url_source": entry["source"], "page": entry["page"],
                           "frame": entry["frame"], "offset": entry["offset"],
                           "status": "partial_candidate"})

    return {"evidence_path": str(evidence_dir), "hashes": input_hashes,
            "settings": settings, "page_count": len(raw) // size,
            "wal_committed_frames": len(frames), "freelist_leaf_pages": len(free_pages),
            "active_url_count": len(active["urls"]), "active_visit_count": len(active["visits"]),
            "processing_seconds": round(time.perf_counter() - start, 4),
            "candidates": candidates, "warnings": sorted(set(warnings)),
            "limitations": [
                "A candidate absent from the current logical view is not automatically proof of user deletion.",
                "Overflow page payloads and index b-tree pages are not reconstructed.",
                "Incomplete URL fragments are not full recovered visits.",
                "Freelist inspection uses the main-file header and may not represent the latest WAL state.",
                "Recovery is limited to structured records and detectable URL fragments.",
            ]}


def save_json(path: Path, result: dict) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
