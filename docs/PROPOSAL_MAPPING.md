# Proposal to implementation mapping

| Proposal section | Requirement | Where it is implemented | Output / evidence |
|---|---|---|---|
| III.A Scope | Google Chrome on Windows, `History` database, `urls` and `visits` tables | `experiment.find_profile_history`, `forensics.analyse`, `carving.run` | All reports |
| III.A Scope | `History-wal` and SQLite free/unallocated areas | `forensics.committed_wal_frames`, `forensics.free_regions`, `carving.free_regions`, `carving.damaged_cells`; `capture` also copies `History-journal` | `recovery_source` column |
| III.B Step 1-2 | Visit predefined websites, perform predefined searches | `experiment.ExperimentServer` (15 pages + 5 search URLs by default, automatic) | `ground_truth.csv` |
| III.B Step 3 | Record activity and timestamps separately | Server writes `ground_truth.csv` with its own clock, outside the evidence folders | `ground_truth.csv` |
| III.B Step 4 | Acquire the Chrome database | `capture_closed_profile` with SHA-256 manifest; check that Chrome saved every visit | `evidence_predelete\manifest.json`, console "Chrome saved 20/20" |
| III.B Step 5 | Delete with Chrome's built-in history clearing | `run` step 3: user deletes in Chrome's **Delete browsing data** window | `deleted_urls_still_in_current_history` = 0 confirms it |
| III.B Step 6 | Controlled additional browsing | Post-deletion pages unlocked only after deletion, visited automatically | Scenarios B, C, F |
| III.B Step 7-8 | Acquire evidence, run BrowserLeak | `run` steps 5-6, `recover` | `results_real\` |
| III.B Table | Scenarios A-E (+1,000 visits) | `scenario.SCENARIOS` A, B, C, D, E, F | `data\scenarios\<name>` |
| III.C | Active pages, free/unallocated areas, freelist, WAL | `forensics.analyse` + `carving.run`, combined in `pipeline.recover` | `recovery_source`: main_database, unallocated, freeblock_payload, header_reconstructed, freelist, freelist_intact_cell, wal |
| III.C | Existing techniques as baseline | Header reconstruction of overwritten cell headers (as in FQLite / bring2lite) | `header_reconstructed` |
| III.C | Per record: URL, visit info, timestamp, table, recovery source, status, condition | `pipeline.recover` | `recovered_records.csv` |
| III.D | Correctly / not / incorrectly recovered | `pipeline.recover` with one-to-one URL + timestamp matching (`validation.match_visits`) | `recovery_status` column |
| III.D | Recovery rate = correct / deleted x 100 | `validation.match_visits` | `result.json`, `report.md` |
| IV.A | Deleted, correct, rate, incorrect, accuracy, processing time, source | `pipeline.recover` | `report.md`, `summary.md` |
| IV.B | Effect of post-deletion activity, graph | Real runs B/C/F; `curve` command on the positive control | `curve.svg`, `summary.svg` |
| IV.C | Chrome open / closed and reopened / Windows restart | Scenarios A, D, E (`run` + `finish`) | `summary.md` |
| IV.D | Comparison with FQLite and Hindsight | Manual procedure on the same evidence | `docs/TOOL_COMPARISON.md` |
| V | Reproducible workflow | One command per scenario; 22 automated tests; synthetic `demo` | `tests/`, this repository |

## Design decision added during the project: the positive control

Chrome compiles SQLite with `SQLITE_SECURE_DELETE`, so Chrome's own deletion overwrites deleted records with zeros. Real Chrome trials therefore give 0%. The positive control deletes the same known visits from a copy of the pre-deletion evidence with `secure_delete` OFF (the only difference) and shows that the recovery method does recover them (20/20 in testing, with no incorrect recoveries). This separates "the tool failed" from "the evidence was destroyed".
