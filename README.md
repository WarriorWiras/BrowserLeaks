# BrowserLeak

**Investigating the recovery of deleted Google Chrome history from SQLite**

📺 **Video demonstration:** "Youtube Link"

BrowserLeak measures how much deleted Google Chrome history can still be recovered from Chrome's `History` SQLite database, under controlled post-deletion conditions, and validates every recovered record against an independently recorded ground truth.

It connects three parts:

1. **Controlled activity**: a local test website makes Chrome visit known pages and searches automatically, and logs every visit with its own clock (the ground truth).
2. **Recovery**: deleted records are recovered from the acquired SQLite evidence (unallocated space, freeblocks, header reconstruction of damaged records, freelist pages, WAL frames), and the storage source of every record is reported.
3. **Validation**: every recovered visit is compared with the ground truth (URL and timestamp) and classified as correctly recovered, not recovered or incorrectly recovered.

A **positive control** repeats exactly the same deletion with SQLite `secure_delete` OFF, to separate "the tool failed" from "the evidence was destroyed".

---

## Contents

1. [Requirements](#1-requirements)
2. [Installation](#2-installation)
3. [Quick start](#3-quick-start)
4. [Running the scenarios](#4-running-the-scenarios)
5. [Results across scenarios](#5-results-across-scenarios)
6. [Command reference](#6-command-reference)
7. [Output files](#7-output-files)
8. [How results are measured](#8-how-results-are-measured)
9. [Troubleshooting](#9-troubleshooting)
10. [Tests](#10-tests)
11. [Project structure](#11-project-structure)
12. [Limitations](#12-limitations)
13. [Evidence handling](#13-evidence-handling)

---

## 1. Requirements

| Item | Version used in the project |
|---|---|
| Windows | Windows 11 (tested on version 26H2, build 26300.9711, in a VMware Workstation VM) |
| Google Chrome | 157.0.8103.51 (64-bit), installed in the default location |
| Python | 3.10 or newer (tested with 3.12.10) |
| Python packages | None for normal use (standard library only); `pytest` to run the tests |

A virtual machine is recommended, so you can take a snapshot before each experiment.

## 2. Installation

1. Download this repository (**Code > Download ZIP**, or the zip under **Releases**) and extract it, e.g. to `C:\Projects\BrowserLeak`. Or clone it:
   ```powershell
   git clone <repository URL> C:\Projects\BrowserLeak
   ```
2. Open **PowerShell** in the project folder:
   ```powershell
   cd C:\Projects\BrowserLeak
   ```
3. Choose one of the two ways to run BrowserLeak:

   **Option A: without installing (simplest).** Run this line in every new PowerShell window:
   ```powershell
   $env:PYTHONPATH = (Resolve-Path .\src).Path
   ```
   Then use `python -m browserleak <command>`.

   **Option B: install the command.**
   ```powershell
   python -m pip install -e .
   ```
   Then `browserleak <command>` works in any window (equivalent to `python -m browserleak <command>`).

4. Check that it works:
   ```powershell
   python -m browserleak --help
   python -m browserleak demo --out data\demo
   ```
   The demo uses a synthetic SQLite database (no Chrome) and should print `Correctly recovered: 10 / 10`.

## 3. Quick start

```powershell
python -m browserleak run --scenario A
```

What happens:

| Step | What BrowserLeak does | What you do |
|---|---|---|
| 1 | Opens a **new, isolated** Chrome profile that visits 15 pages and 5 searches by itself | Nothing. Close Chrome when asked |
| 2 | Copies and hashes the History files; checks that Chrome saved every known visit ("Chrome saved 20/20") | Nothing |
| 3 | Opens Chrome again | Press **Ctrl+Shift+Delete**, time range **Last hour**, tick only **Browsing history**, click **Delete data**, then press **Enter** in PowerShell |
| 4 | Applies the post-deletion condition (none for A) | Close Chrome when asked |
| 5 | Acquires and hashes the post-deletion evidence | Nothing |
| 6 | Recovers, builds the positive control, validates both and prints the result table | Read the result |

Example result (scenario A on Windows):

```
                                           Real Chrome  Positive control
  Deleted visits (ground truth)                     20                20
  Deleted URLs still in history (0 = OK)             0                 0
  Correctly recovered                                0                20
  Incorrectly recovered                              0                 0
  Recovery rate                                   0.0%            100.0%
  Recovery accuracy                                n/a            100.0%
  Deleted URLs left in raw bytes                     0                20
  Recovery sources (control): {'header_reconstructed': 19, 'unallocated': 1}
```

## 4. Running the scenarios

| Scenario | Command | Post-deletion condition |
|---|---|---|
| A | `python -m browserleak run --scenario A` | Evidence acquired immediately |
| B | `python -m browserleak run --scenario B` | 100 additional visits (automatic, about 1 min) |
| C | `python -m browserleak run --scenario C` | 500 additional visits (automatic, about 3 min) |
| D | `python -m browserleak run --scenario D` | Chrome closed and reopened (close Chrome a second time when asked) |
| E | `python -m browserleak run --scenario E` | Windows restarted (see below) |
| F | `python -m browserleak run --scenario F` | 1,000 additional visits (optional) |

**Scenario E:** the command stops after the deletion and prints instructions. Restart Windows, log in, open PowerShell in the project folder and run:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m browserleak finish --name E
```

**Repeating a scenario:** give the run a new name, e.g. `python -m browserleak run --scenario A --name A2`.

## 5. Results across scenarios

After running several scenarios:

```powershell
python -m browserleak summary            # table + bar chart of all runs -> data\summary\
python -m browserleak curve --name A     # recovery vs. post-deletion visits -> data\scenarios\A\curve\
start data\summary\summary.svg
start data\scenarios\A\curve\curve.svg
```

Results obtained in the project (20 deleted visits per scenario):

| Scenario | Real Chrome deletion | Positive control |
|---|---|---|
| A immediate | 0/20 | 20/20 |
| B +100 visits | 0/20 | 0/20 |
| C +500 visits | 0/20 | 0/20 |
| D Chrome reopened | 0/20 | 20/20 |
| E Windows restarted | 0/20 | 20/20 |

No incorrect recoveries occurred in any run. Without secure delete, each new visit after the deletion overwrote about one deleted visit (`curve`: 19/20 after 1 visit, 10/20 after 10, 0/20 after 20). The comparison with FQLite and Hindsight is in [docs/TOOL_COMPARISON.md](docs/TOOL_COMPARISON.md).

## 6. Command reference

All commands are run as `python -m browserleak <command> [options]`. Use `--help` after any command for details.

| Command | Purpose | Main options |
|---|---|---|
| `run` | Complete guided experiment for one scenario | `--scenario A-F` (required), `--name`, `--pages 15`, `--searches 5`, `--post-count N`, `--port 8765`, `--delay-ms 300`, `--chrome <path to chrome.exe>` |
| `finish` | Finish a run after the Windows restart (scenario E) | `--name E` |
| `summary` | Table and bar chart across all finished runs | `--root data\scenarios`, `--out data\summary` |
| `curve` | Overwrite curve: control with 0, 1, 2, 5 ... 1000 simulated new visits | `--name A`, `--counts 0 5 10 20` |
| `recover` | Recovery and validation on any evidence folder | `--evidence <folder>`, `--ground-truth <csv>`, `--out <folder>`, `--tolerance 2` |
| `control` | Positive control from a pre-deletion evidence folder | `--evidence <predelete folder>`, `--ground-truth <csv>`, `--out <folder>`, `--post-count N` |
| `capture` | Copy and hash `History` files from a **closed** Chrome profile | `--profile <user data dir>`, `--out <folder>`, `--confirm-closed` |
| `verify-baseline` | Check that Chrome saved the known visits (use on pre-deletion evidence) | `--evidence <folder>`, `--ground-truth <csv>` |
| `demo` | Synthetic WAL recovery demonstration, no Chrome needed | `--out <empty folder>` |

Example: check the pre-deletion evidence of every scenario:

```powershell
foreach ($s in "A","B","C","D","E") {
  $r = python -m browserleak verify-baseline --evidence "data\scenarios\$s\evidence_predelete" --ground-truth "data\scenarios\$s\ground_truth.csv" | ConvertFrom-Json
  "{0}: Chrome saved {1}/{2} known visits before deletion" -f $s, $r.correct_recoveries, $r.expected_deleted_visits
}
```

## 7. Output files

Each run is stored in `data\scenarios\<name>\`:

| Path | Contents |
|---|---|
| `scenario.json` | Scenario, condition and timestamps of each step |
| `ground_truth.csv` | Independent log of every known visit (server clock), kept outside the evidence folders |
| `profile\` | The isolated, disposable Chrome profile |
| `evidence_predelete\` | `History` (and `History-journal` / `-wal` if present) before deletion, with `manifest.json` (SHA-256) |
| `evidence_postdelete\` | The same after Chrome's deletion and the post-deletion condition |
| `evidence_control\` | Positive control: pre-deletion copy with the same visits deleted with `secure_delete` OFF |
| `results_real\`, `results_control\` | `report.md` (readable report), `result.json` (all metrics), `recovered_records.csv` (one row per record) |
| `curve\` | `curve.csv`, `curve.svg` (after the `curve` command) |

`recovered_records.csv` columns: `scenario`, `condition`, `evidence`, `recovery_status` (correctly_recovered / not_recovered / incorrectly_recovered / partial_url_not_counted), `ground_truth_match` (Yes / No / URL only), `record_type`, `url`, `visit_time_utc`, `database_table`, `recovery_source`, `link_method`, `page`, `offset`.

## 8. How results are measured

- A recovery is **correct** only if the URL **and** the visit time match a ground-truth visit within 2 seconds (the observed difference between server clock and Chrome is about 0.01 s). Matching is one to one, closest first.
- **Recovery rate** = correctly recovered / deleted visits x 100.
- **Recovery accuracy** = correctly recovered / all full visits reported x 100.
- URL-only traces (no timestamp) are reported separately and are never counted as recoveries.
- **Deleted URLs still in history** must be 0: this confirms that Chrome's deletion took place.
- **Deleted URLs left in raw bytes** counts the deleted URLs whose text still appears anywhere in the acquired files.

**Why a positive control?** Chrome compiles SQLite with `SQLITE_SECURE_DELETE`, so its own deletion overwrites deleted records with zeros. A 0% result on real evidence alone cannot show whether the tool failed or the evidence was destroyed. The control deletes the same visits from the pre-deletion copy with `secure_delete` OFF (the only difference). Control results and simulated visits are always labelled as such.

## 9. Troubleshooting

| Problem | Solution |
|---|---|
| `No module named browserleak` | Run `$env:PYTHONPATH = (Resolve-Path .\src).Path` in this PowerShell window, from the project folder (or use Option B in Installation) |
| `Port 8765 is already in use` | Close other BrowserLeak windows, or add `--port 8766` |
| `... already exists. Use --name` | Choose a new run name, e.g. `--name A2` |
| `Chrome not found` | Add `--chrome "C:\Program Files\Google\Chrome\Application\chrome.exe"` |
| Waiting for Chrome to close never ends | Close every window of the test profile; if needed run `Get-Process chrome -ErrorAction SilentlyContinue \| Stop-Process` (this closes all Chrome windows) |
| `chrome://history` does not open in step 3 | Press **Ctrl+Shift+Delete** in the Chrome window instead |
| Chrome saved fewer than 20 visits | Results are still measured honestly; repeat the scenario with a new `--name` if you need a full baseline |

## 10. Tests

```powershell
python -m pip install pytest
python -m pytest -q
```

22 automated tests cover SQLite parsing, WAL checksums, record carving, header reconstruction (including rejection of random bytes), the positive control, ground-truth validation, the test website, evidence acquisition and hashing, and the summaries. They use synthetic SQLite databases and need no Chrome.

## 11. Project structure

```
BrowserLeak/
├── README.md                 user manual (this file)
├── pyproject.toml            package definition (no runtime dependencies)
├── docs/
│   ├── PROPOSAL_MAPPING.md   proposal requirements -> implementation
│   └── TOOL_COMPARISON.md    FQLite and Hindsight comparison and procedure
├── src/browserleak/
│   ├── cli.py                command line interface
│   ├── scenario.py           guided scenario runner (run, finish)
│   ├── experiment.py         test website, ground-truth log, evidence acquisition
│   ├── forensics.py          SQLite page, freelist and WAL parsing
│   ├── carving.py            record carving, header reconstruction, URL linking
│   ├── pipeline.py           combined recovery, validation, per-record output
│   ├── control.py            positive control
│   ├── validation.py         ground-truth matching
│   ├── summary.py            cross-scenario summary, charts, overwrite curve
│   └── demo.py               synthetic WAL demonstration
└── tests/                    22 pytest tests
```

## 12. Limitations

- Evidence is acquired only after Chrome has closed. Live acquisition needs a consistent VM or file-system snapshot.
- Only the `History` files are analysed. Chrome's Session files and cache can still contain recently deleted visits (shown with Hindsight, see `docs/TOOL_COMPARISON.md`).
- "Searches" are search-style URLs on the local test site; Chrome's `keyword_search_terms` table is only filled for registered search engines.
- Overflow pages and index B-trees are not reconstructed.
- Results were obtained with one Chrome version on one Windows installation.

## 13. Evidence handling

- Use only the isolated profiles created by `run`, with no sign-in, sync or personal browsing.
- Ground truth is stored separately from the evidence, and every acquisition is hashed (`manifest.json`).
- `data/` is excluded by `.gitignore`. **Never commit or upload browser profiles or evidence.**
