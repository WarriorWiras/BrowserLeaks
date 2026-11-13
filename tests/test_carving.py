"""Record carving tests with synthetic SQLite, not real Chrome evidence."""
from __future__ import annotations
from pathlib import Path
import sqlite3
import tempfile
import unittest
import csv
from datetime import datetime, timezone

from browserleak.carving import record_at, is_plausible, run


class TestRecordCarving(unittest.TestCase):
    def test_malformed_record_is_rejected(self):
        self.assertIsNone(record_at(b'\x00\x00\x00',0,['id','url'],'utf-8'))
        self.assertFalse(is_plausible('visits', {'url':42,'visit_time':23}))

    def test_runs_against_actual_deleted_sqlite_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'History'
            con=sqlite3.connect(path)
            con.execute('PRAGMA page_size=1024')
            con.execute('PRAGMA secure_delete=OFF')
            con.execute('CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER)')
            con.execute('CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)')
            for i in range(1,401):
                con.execute('INSERT INTO urls VALUES (?,?,?,?)',
                            (i,f'https://example.test/experiment/{i:04d}', 'Example'*7, 1))
                con.execute('INSERT INTO visits VALUES (?,?,?)',
                            (i,i,13404528000000000+i*1000000))
            con.commit()
            con.execute('DELETE FROM visits WHERE id BETWEEN 1 AND 300')
            con.execute('DELETE FROM urls WHERE id BETWEEN 1 AND 300')
            con.commit()
            con.close()
            truth = Path(temporary) / 'truth.csv'
            with truth.open('w', newline='', encoding='utf-8') as stream:
                writer=csv.DictWriter(stream,fieldnames=['url','visited_at_utc'])
                writer.writeheader()
                from browserleak.forensics import chrome_to_utc
                for i in range(1,301):
                    writer.writerow({'url':f'https://example.test/experiment/{i:04d}',
                                     'visited_at_utc':chrome_to_utc(13404528000000000+i*1000000)})
            result=run(path,truth)
            self.assertEqual(result['page_size'],1024)
            self.assertTrue(result['sha256'])
            self.assertGreaterEqual(result['free_regions_examined'],0)
            self.assertGreater(result['linked_visit_candidates'],0)
            self.assertGreater(result['validation']['confirmed_matches'],0)
            self.assertLessEqual(result['validation']['confirmed_matches'],300)
            self.assertTrue(all(f['source'] in ('unallocated','freeblock_payload','freelist_intact_cell','header_reconstructed') for f in result['findings']))
            self.assertTrue(all(f['level'] in ('url_only','unlinked_visit_payload','linked_visit_candidate') for f in result['findings']))
            print('Experimental deleted-row fixture:')
            print('free_regions_examined',result['free_regions_examined'])
            print('freelist_leaf_pages',result['freelist_leaf_pages'])
            print('candidates',result['candidate_count'])
            print('linked_visits',result['linked_visit_candidates'])
            print('validated_matches',result['validation']['confirmed_matches'])

    def test_header_reconstruction_on_chrome_schema_row_deletes(self):
        """Chrome-style schema, rows deleted one at a time with secure_delete OFF."""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'History'
            con = sqlite3.connect(path)
            con.execute('PRAGMA secure_delete=OFF')
            con.executescript(
                'CREATE TABLE urls(id INTEGER PRIMARY KEY AUTOINCREMENT,url LONGVARCHAR,title LONGVARCHAR,'
                'visit_count INTEGER DEFAULT 0 NOT NULL,typed_count INTEGER DEFAULT 0 NOT NULL,'
                'last_visit_time INTEGER NOT NULL,hidden INTEGER DEFAULT 0 NOT NULL);'
                'CREATE TABLE visits(id INTEGER PRIMARY KEY AUTOINCREMENT,url INTEGER NOT NULL,'
                'visit_time INTEGER NOT NULL,from_visit INTEGER,transition INTEGER DEFAULT 0 NOT NULL,'
                'segment_id INTEGER,visit_duration INTEGER DEFAULT 0 NOT NULL);')
            from browserleak.forensics import chrome_to_utc
            truth = Path(temporary) / 'truth.csv'
            rows = []
            for i in range(1, 21):
                when = 13437972000000000 + i * 1000000
                url = f'http://127.0.0.1:8765/visit/baseline/{i:04d}'
                con.execute('INSERT INTO urls(url,title,visit_count,typed_count,last_visit_time,hidden) '
                            'VALUES (?,?,1,0,?,0)', (url, f'Experiment {i}', when))
                con.execute('INSERT INTO visits(url,visit_time,from_visit,transition,segment_id,visit_duration) '
                            'VALUES (?,?,0,805306368,0,1500000)', (i, when))
                rows.append({'phase': 'baseline', 'url': url, 'visited_at_utc': chrome_to_utc(when)})
            con.commit()
            for i in range(1, 21):
                con.execute('DELETE FROM visits WHERE id=?', (i,))
                con.execute('DELETE FROM urls WHERE id=?', (i,))
                con.commit()
            con.close()
            with truth.open('w', newline='', encoding='utf-8') as stream:
                writer = csv.DictWriter(stream, fieldnames=['phase', 'url', 'visited_at_utc'])
                writer.writeheader()
                writer.writerows(rows)
            result = run(path, truth)
            self.assertEqual(result['validation']['confirmed_matches'], 20)
            false = [f for f in result['findings']
                     if f['level'] == 'linked_visit_candidate' and not f['validated_deleted_visit']]
            self.assertEqual(false, [])
            self.assertTrue(any(f['source'] == 'header_reconstructed' for f in result['findings']))

if __name__ == '__main__':
    unittest.main()
