"""BrowserLeak structured SQLite record carver (read-only research prototype).

Searches intact SQLite record payloads in freeblocks/unallocated areas of known
Chrome urls/visits table leaf pages, plus intact table cells on freelist leaf
pages. Reports partial and linked visits distinctly. Ground truth is used ONLY
for optional validation, never for discovery.

Limitations: Freeblock headers overwrite the first four bytes of a deleted cell;
these are rebuilt from the known Chrome schema where possible (header
reconstruction), but other damaged payloads cannot be reconstructed. Does not scan rollback
journals, WAL, index keys or overflow chains. 
"""
from __future__ import annotations
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3

from .forensics import (
    page_size_from_header, decode_varint, decode_serial,
    iter_freelist_leaf_pages, table_leaf_rows, chrome_to_utc
)

VALID_TABLES = ('urls', 'visits')


def uint(data: bytes, pos: int, count: int) -> int:
    return int.from_bytes(data[pos:pos + count], 'big')


def database_encoding(data: bytes) -> str:
    return {1: 'utf-8', 2: 'utf-16-le', 3: 'utf-16-be'}.get(uint(data, 56, 4), 'utf-8')


def record_at(buf: bytes, start: int, columns: list[str], encoding: str):
    """Decode a SQLite record payload, not a full B-tree cell."""
    try:
        header, pos = decode_varint(buf, start)
        end_header = start + header
        if header < 2 or header > 300 or end_header > len(buf):
            return None
        serials = []
        while pos < end_header:
            serial, pos = decode_varint(buf, pos)
            serials.append(serial)
            if len(serials) > len(columns):
                return None
        if pos != end_header or len(serials) != len(columns):
            return None
        values = []
        pos = end_header
        for serial in serials:
            value, pos = decode_serial(serial, buf, pos, encoding)
            values.append(value)
        if pos > len(buf):
            return None
        return dict(zip(columns, values)), pos - start
    except (ValueError, IndexError, OverflowError, UnicodeError):
        return None


def cell_rowid_before(buf: bytes, start: int, nbytes: int):
    """Recover the rowid of an intact table-leaf cell whose payload begins at `start`.

    A table-leaf cell is [payload-length varint][rowid varint][payload]. If the
    cell header is still intact (e.g. in the unallocated region), the payload
    length must equal the decoded record size and the rowid varint must end
    exactly at `start`. Returns None when the header was overwritten (freeblock).
    """
    for back in range(2, 19):
        cell = start - back
        if cell < 0:
            break
        try:
            length, pos = decode_varint(buf, cell)
            if length != nbytes:
                continue
            rowid, pos = decode_varint(buf, pos)
        except (ValueError, IndexError):
            continue
        if pos == start and rowid > 0:
            return rowid
    return None


def record_header_reconstructed(buf: bytes, columns: list[str], encoding: str, missing: int):
    """Decode a deleted cell whose first 4 bytes were overwritten by a freeblock header.

    A table-leaf cell is [payload length][rowid][record header length][serial types...][values].
    Freeing the cell overwrites its first 4 bytes. For small Chrome rows this destroys the
    payload length, rowid, header length and (missing=1) the first serial type. Chrome's
    first column `id` is an INTEGER PRIMARY KEY alias, which SQLite always stores as
    serial type 0 (NULL), so that lost serial type is known. The remaining serial types
    and all values are intact. This is the header-reconstruction approach used by
    tools such as FQLite and bring2lite.
    """
    if not columns or columns[0] != 'id' or missing not in (0, 1):
        return None
    try:
        pos = 0
        serials = [0] * missing
        while len(serials) < len(columns):
            serial, pos = decode_varint(buf, pos)
            serials.append(serial)
        if serials[0] != 0:
            return None
        values = []
        for serial in serials:
            value, pos = decode_serial(serial, buf, pos, encoding)
            values.append(value)
        return dict(zip(columns, values)), pos
    except (ValueError, IndexError, OverflowError, UnicodeError):
        return None


def is_plausible(table: str, row: dict) -> bool:
    if table == 'urls':
        url = row.get('url')
        return (isinstance(url, str) and url.startswith(('https://', 'http://'))
                and len(url) <= 2048 and '\ufffd' not in url
                and all(ord(c) >= 32 for c in url))
    url_id, when = row.get('url'), row.get('visit_time')
    if not (isinstance(url_id, int) and 0 < url_id < 2**50
            and isinstance(when, int) and when > 0):
        return False
    stamp = chrome_to_utc(when)
    try:
        return bool(stamp and 2000 <= datetime.fromisoformat(stamp).year <= 2100)
    except ValueError:
        return False


def ownership(con: sqlite3.Connection, raw: bytes, size: int):
    """Map active B-tree pages to table/index. Does not infer freed-page owners."""
    limit = min(uint(raw, 28, 4), len(raw) // size)
    found: dict[int, set[str]] = {}
    for typ, name, root in con.execute(
        "SELECT type, name, rootpage FROM sqlite_schema WHERE rootpage>0"):
        pending, seen = [root], set()
        while pending:
            number = pending.pop()
            if number in seen or number < 1 or number > limit:
                continue
            seen.add(number)
            found.setdefault(number, set()).add(name)
            block = raw[(number-1)*size:number*size]
            h = 100 if number == 1 else 0
            kind = block[h]
            if kind not in (2, 5):
                continue
            n = uint(block, h+3, 2)
            if n > (size-h-12)//2:
                continue
            for i in range(n):
                ptr = uint(block, h+12+2*i, 2)
                if 0 < ptr <= size-4:
                    pending.append(uint(block, ptr, 4))
            pending.append(uint(block, h+8, 4))
    return found


def free_regions(raw: bytes, size: int, usable: int, owner: dict[int, set[str]]):
    """Only table leaf pages with known urls/visits ownership, never active cells."""
    limit = min(uint(raw, 28, 4), len(raw)//size)
    for number in range(1, limit+1):
        names = VALID_TABLES and (owner.get(number, set()) & set(VALID_TABLES))
        if len(names) != 1:
            continue
        page = raw[(number-1)*size:number*size]
        h = 100 if number == 1 else 0
        if page[h] != 13:
            continue
        count = uint(page, h+3, 2)
        ptr_end = h+8+count*2
        content = uint(page, h+5, 2) or 65536
        if ptr_end > content or content > usable:
            continue
        if content > ptr_end:
            yield number, next(iter(names)), 'unallocated', ptr_end, page[ptr_end:content]
        free = uint(page, h+1, 2)
        visited = set()
        while free and free not in visited:
            visited.add(free)
            if free < content or free+4 > usable:
                break
            next_free = uint(page, free, 2)
            length = uint(page, free+2, 2)
            if length < 4 or free+length > usable:
                break
            if length > 4:
                yield number, next(iter(names)), 'freeblock_payload', free+4, page[free+4:free+length]
            free = next_free


def damaged_cells(raw: bytes, size: int, usable: int, owner: dict[int, set[str]],
                  columns: dict[str, list[str]], encoding: str):
    """Find deleted cells whose first 4 bytes were overwritten by a freeblock header.

    When SQLite frees a cell it writes [next freeblock (2 bytes)][block size (2 bytes)]
    over the start of the cell. That header stays behind even after the page is reset,
    so it is used as an anchor: the reconstructed record must end exactly where the
    recorded block size says the cell ended, or where the next leftover header (from
    an adjacent freed cell merged into the same block) begins. This rejects random
    byte matches.
    """
    limit = min(uint(raw, 28, 4), len(raw)//size)
    for number in range(1, limit+1):
        names = owner.get(number, set()) & set(VALID_TABLES)
        if len(names) != 1:
            continue
        table = next(iter(names))
        page = raw[(number-1)*size:number*size]
        h = 100 if number == 1 else 0
        if page[h] != 13:
            continue
        count = uint(page, h+3, 2)
        ptr_end = h+8+count*2
        active = {uint(page, h+8+2*i, 2) for i in range(count)}
        for cell in range(ptr_end, usable-8):
            if cell in active:
                continue
            block = uint(page, cell+2, 2)
            if block <= 8 or cell + block > usable:
                continue
            body = page[cell+4:cell+block]
            for missing in (1, 0):
                rebuilt = record_header_reconstructed(body, columns[table], encoding, missing)
                if not rebuilt or not is_plausible(table, rebuilt[0]):
                    continue
                cell_size = 4 + rebuilt[1]
                # Anchor 1: the block holds exactly this cell.
                exact = rebuilt[1] == len(body)
                # Anchor 2: SQLite merged this cell with freed cells after it. The next
                # cell then starts with its own leftover header, whose size is ours minus this cell.
                nxt = cell + cell_size
                chained = (block > cell_size and nxt + 4 <= usable
                           and uint(page, nxt+2, 2) == block - cell_size)
                # Anchor 3: merge order varies, so otherwise require a structurally valid
                # leftover freeblock header: next pointer 0 or further down the page, and a
                # block size large enough to have held this cell.
                next_ptr = uint(page, cell, 2)
                header_ok = (block >= cell_size and
                             (next_ptr == 0 or cell + cell_size <= next_ptr <= usable - 4))
                if exact or chained or header_ok:
                    yield number, table, cell, rebuilt[0], rebuilt[1]
                    break


def run(evidence: Path, truth: Path | None = None, tolerance: float = 2.0):
    evidence = evidence.resolve(strict=True)
    raw = evidence.read_bytes()
    size = page_size_from_header(raw)
    usable = size - raw[20]
    encoding = database_encoding(raw)
    if len(raw) % size:
        raise ValueError('Database is not page aligned')
    con = sqlite3.connect(f'file:{evidence.as_posix()}?mode=ro&immutable=1', uri=True)
    try:
        con.execute('PRAGMA query_only=ON')
        tables = {r[0] for r in con.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
        if not set(VALID_TABLES).issubset(tables):
            raise ValueError('Expected Chrome urls and visits tables')
        columns = {t:[r[1] for r in con.execute(f'PRAGMA table_info({t})')]
                   for t in VALID_TABLES}
        owner = ownership(con, raw, size)
        active_urls = {int(i):u for i,u in con.execute('SELECT id,url FROM urls')}
        active_visits = {(int(url),int(when)) for url,when
                         in con.execute('SELECT url,visit_time FROM visits')}
        evidence_hash = hashlib.sha256(raw).hexdigest()
    finally:
        con.close()
    discovered = []
    regions = 0
    # Sliding header search in unallocated/freeblock content, record must be intact.
    for page, table, region, base, buf in free_regions(raw,size,usable,owner):
        regions += 1
        for offset in range(len(buf)):
            result = record_at(buf, offset, columns[table], encoding)
            if result is None:
                continue
            row, nbytes = result
            if not is_plausible(table,row):
                continue
            rowid = cell_rowid_before(buf, offset, nbytes)
            if rowid is not None and row.get('id') is None:
                row['id'] = rowid  # INTEGER PRIMARY KEY is stored in the cell header, not the record
            discovered.append(dict(table=table, record=row,
                page=page, offset=(page-1)*size+base+offset,
                source=region, rowid=rowid, payload_bytes=nbytes))
    # Deleted cells with an overwritten 4-byte header, anchored by the leftover freeblock size.
    for page, table, cell, row, nbytes in damaged_cells(raw, size, usable, owner, columns, encoding):
        discovered.append(dict(table=table, record=row,
            page=page, offset=(page-1)*size+cell,
            source='header_reconstructed', rowid=None, payload_bytes=nbytes))
    # Freelist leaf pages sometimes retain full, intact table leaf cell headers.
    freelist = iter_freelist_leaf_pages(raw, size)
    for page_no, page_data in freelist:
        for cell in table_leaf_rows(page_data, page_no, usable, encoding):
            for table in VALID_TABLES:
                if len(cell['values']) != len(columns[table]):
                    continue
                row = dict(zip(columns[table], cell['values']))
                if not is_plausible(table, row):
                    continue
                if row.get('id') is None:
                    row['id'] = cell['rowid']
                discovered.append(dict(table=table, record=row,
                    page=page_no, offset=(page_no-1)*size+cell['offset'],
                    source='freelist_intact_cell', rowid=cell['rowid'],
                    payload_bytes=None))
    unique = {}
    for record in discovered:
        r = record['record']
        if record['table'] == 'visits':
            key = ('visits', r.get('url'), r.get('visit_time'))
        else:
            key = ('urls', r.get('url'), r.get('last_visit_time'))
        # Prefer a record with a recovered id over one without.
        if key not in unique or (unique[key]['record'].get('id') is None and r.get('id') is not None):
            unique[key] = record
    discovered = list(unique.values())
    # Filter cells still matching active rows, and attach linked URLs only when known.
    historical_urls = dict(active_urls)
    for f in discovered:
        if f['table']=='urls' and isinstance(f['record'].get('id'),int):
            historical_urls[f['record']['id']] = f['record']['url']
    # Fallback link: Chrome sets urls.last_visit_time to the URL's latest visit time.
    # Only unambiguous times are used, and such links are labelled separately.
    by_time: dict[int, set[str]] = {}
    for f in discovered:
        if f['table']=='urls' and isinstance(f['record'].get('last_visit_time'),int):
            by_time.setdefault(f['record']['last_visit_time'], set()).add(f['record']['url'])
    findings = []
    for f in discovered:
        r = f['record']; table=f['table']; link_method = None
        if table=='urls':
            if r['url'] in active_urls.values():
                continue
            level, url, stamp = 'url_only', r['url'], None
        else:
            if (r['url'],r['visit_time']) in active_visits:
                continue
            url = historical_urls.get(r['url'])
            if url:
                link_method = 'url_id'
            elif len(by_time.get(r['visit_time'], ())) == 1:
                url = next(iter(by_time[r['visit_time']]))
                link_method = 'last_visit_time'
            level = 'linked_visit_candidate' if url else 'unlinked_visit_payload'
            stamp = chrome_to_utc(r['visit_time'])
        findings.append({**{k:v for k,v in f.items() if k!='record'},
                         'level':level,'url':url,'link_method':link_method,
                         'visit_time_utc':stamp,
                         'decoded_record':r,'validated_deleted_visit':False})
    result = dict(evidence=str(evidence),sha256=evidence_hash,
                  page_size=size,free_regions_examined=regions,
                  freelist_leaf_pages=len(freelist),
                  candidate_count=len(findings),
                  linked_visit_candidates=sum(x['level']=='linked_visit_candidate' for x in findings),
                  findings=findings,
                  limitations=[
                    'Unallocated and freeblock payloads may be partly overwritten; many records cannot be decoded.',
                    'Freelist leaf pages only are tested for intact full cells.',
                    'Does not parse index keys, overflow chains, rollback journals or WAL.',
                    'Record candidates are not proof of intentional browser history deletion.',
                    'Ground truth is used solely for optional validation.'
                  ])
    if truth:
        with truth.open(newline='',encoding='utf-8') as f:
            expected = [r for r in csv.DictReader(f) if r.get('phase', 'baseline') == 'baseline']
        used=set(); matches=[]
        for f in findings:
            if f['level']!='linked_visit_candidate' or not f['url'] or not f['visit_time_utc']:
                continue
            actual = datetime.fromisoformat(f['visit_time_utc']).astimezone(timezone.utc)
            for i,row in enumerate(expected):
                if i in used or f['url'] != row['url']:
                    continue
                try:
                    dt=datetime.fromisoformat(row['visited_at_utc']).astimezone(timezone.utc)
                except (KeyError,ValueError):
                    continue
                if abs((dt-actual).total_seconds()) <= tolerance:
                    used.add(i)
                    f['validated_deleted_visit']=True
                    matches.append({'url':f['url'],'expected_time':dt.isoformat(),
                                    'recovered_time':f['visit_time_utc'],'page':f['page'],
                                    'source':f['source'],'link_method':f['link_method']})
                    break
        result['validation'] = dict(expected_deleted_visits=len(expected),
                                    confirmed_matches=len(matches),
                                    recovery_rate_percent=round(len(matches)/len(expected)*100,2) if expected else None,
                                    matches=matches,
                                    note='Validated linked visit candidates only, not URL-only or unlinked fragments')
    return result
