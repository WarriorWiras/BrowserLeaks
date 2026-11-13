# Comparison with existing tools

BrowserLeak was compared with FQLite 5.2 and Hindsight v2026.06 on the evidence of scenario A (report Section IV-G, Table IX). Every tool was run on **copies** of the evidence, so the original evidence keeps its SHA-256 hashes.

## Results (scenario A, 20 deleted visits)

| Feature | BrowserLeak | FQLite 5.2 | Hindsight v2026.06 |
|---|---|---|---|
| Correct visits, real Chrome deletion | 0/20 | 0/20 | 7/20 (Session file) |
| Correct visits, positive control | 20/20 | 0/20 | 7/20 (Session file) |
| Deleted URL records, positive control | 20/20 | 18/20 | 0/20 |
| Incorrect recoveries | 0 | 0 | 0 |
| Processing time | 0.016–0.025 s | ≈2.0–2.7 s (manual) | ≈2 s |
| Recovery source shown | Yes | Offset only | Artefact file |
| Ground-truth validation | Automatic | No | No |
| Carves deleted records | Yes | Yes | No |

Findings:

- **FQLite** recovered 18 of the 20 deleted `urls` rows from the control (status `D`), but no `visits` rows. The recovered rows had lost their `id` (rowid `-1`), so they could not be linked to visits.
- **Hindsight** reported no URL records from the History database, but Chrome's **Session file** (`Sessions\Tabs_*`, tab navigation entries) still held the last 7 deleted visits (`baseline/0014`, `baseline/0015` and the 5 searches) with the exact URL, title and timestamp. Deleted Chrome history can therefore survive outside the History database.
- The `visited_links` and `keyword_search_terms` tables held no deleted URLs.

## How to reproduce

Run from the `BrowserLeak` folder in PowerShell, after scenario A has finished.

### 1. Copy the evidence

```powershell
New-Item -ItemType Directory -Force data\compare\A_real, data\compare\A_control | Out-Null
Copy-Item data\scenarios\A\evidence_postdelete\History* data\compare\A_real\
Copy-Item data\scenarios\A\evidence_control\History data\compare\A_control\
```

### 2. FQLite

1. Install FQLite from https://github.com/pawlaszczyk/fqlite/releases (Windows `.exe`; the Java runtime is bundled).
2. **File > Open**, choose `data\compare\A_real\History` (set the file type to *All files*). Time the loading with a stopwatch.
3. Open the tables `urls` and `visits`. Deleted rows are marked `D` in the status column.
4. Export each table with the **CSV** toolbar button.
5. Close the database and repeat with `data\compare\A_control\History`.
6. Count the deleted rows whose URL and time match `data\scenarios\A\ground_truth.csv`.

### 3. Hindsight

Hindsight reads a whole profile folder, so make two profile copies. The control copy gets the control `History`:

```powershell
Copy-Item -Recurse data\scenarios\A\profile\Default data\compare\hs_real\Default
Copy-Item -Recurse data\scenarios\A\profile\Default data\compare\hs_control\Default
Copy-Item -Force data\compare\A_control\History data\compare\hs_control\Default\History
Remove-Item -ErrorAction SilentlyContinue data\compare\hs_control\Default\History-journal
```

Download `hindsight.exe` from https://github.com/obsidianforensics/hindsight/releases into `data\compare`, then:

```powershell
cd data\compare
.\hindsight.exe -i "hs_real\Default" -o "hindsight_real"
.\hindsight.exe -i "hs_control\Default" -o "hindsight_control"
```

Open the `.xlsx` output, search the workbook for `127.0.0.1:8765` and compare the URLs and timestamps of the matching rows with the ground truth.
