# Tor Artifact Collector

**Python-based forensic tool for extracting Tor Browser artifacts from Windows systems**

Built for an NFI (Netherlands Forensic Institute) internship application. The tool collects and correlates Tor Browser execution and browsing artifacts from nine Windows sources and produces a unified, timestamped timeline with confidence scoring and chain-of-custody hashing. It is designed around a single forensic principle: no standard user-level cleanup action wipes evidence across all sources at once, so unifying findings across independent artifact sources is both possible and meaningful.

---

## What It Does

The tool extracts Tor Browser evidence from nine Windows sources and correlates them into a unified timeline:

| Source | What I Extract | Implementation Status |
|--------|---------------|----------------------|
| **Windows Registry (NTUSER.DAT)** | UserAssist execution logs (run count, last execution FILETIME) | Working - `yarp` for offline images; `winreg` stdlib for live systems |
| **places.sqlite** | Firefox/Tor Browser `.onion` visit history, titles, visit counts | Working |
| **places.sqlite-wal** | Deleted `.onion` URLs recovered from uncheckpointed WAL frames | Working - WAL frame parser with binary fallback |
| **Chrome/Edge/Brave History** | `.onion` URLs including failed DNS lookups (`ERR_NAME_NOT_RESOLVED`) | Working - covers all three Chromium browsers |
| **Prefetch Files** | Execution timestamps (last 8 runs), total run count | Working |
| **EVTX Event Logs** | Process creation events (Event ID 4688): exact path, PID, parent process | Working |
| **Jump Lists** | Application launch entries from `AutomaticDestinations` - records Tor Browser launches via desktop shortcut | Working - OLE CFB parsing with `olefile`; binary carving fallback |
| **Volume Shadow Copies (VSS)** | Previous versions of `places.sqlite` from VSS snapshots - may contain pre-deletion browsing history | Working - enumerates via `vssadmin`, extracts from each shadow copy found |
| **Source artifact hashes** | SHA-256 of each input file computed before extraction begins | Working - recorded in `artifact_hashes` section of output JSON |

### Why These Nine Sources?

The selection is driven by one principle: **no single user-level cleanup action eliminates evidence across all sources simultaneously.**

**What "Clear Recent History" in Tor Browser actually clears:**
Rows in `places.sqlite`. It does not touch the WAL file; history deleted just before a force-kill of the browser may still survive in `places.sqlite-wal` as uncheckpointed frames. UserAssist, Prefetch, EVTX, and Jump Lists are unaffected.

**What uninstalling Tor Browser clears:**
The application files on disk. The Windows Registry is not modified by uninstallers, so UserAssist entries persist with the original executable path even after the software is gone. `C:\Windows\Prefetch\TOR.EXE-*.pf` is also untouched because Prefetch is managed by Windows, not by the application. Jump List entries in `AutomaticDestinations` are managed by Windows Explorer and also survive uninstallation.

**What "Clear browsing data" in Chrome/Edge clears:**
Only those browsers' History databases. It has no effect on Tor Browser's SQLite files, UserAssist, Prefetch, EVTX, or Jump Lists.

**What Volume Shadow Copies can preserve:**
If VSS was active, a snapshot taken before the user cleared their history may contain the full `places.sqlite` with all visited `.onion` URLs intact. This is the most impactful recovery source for browsing history: it operates independently of what the user deleted at the application level.

**What requires admin privileges to fully erase:**
- `Security.evtx`: standard users cannot clear the Security event log.
- `C:\Windows\Prefetch\`: admin-only directory on live systems.
- UserAssist: the registry key is not cleaned by an uninstaller.
- Volume Shadow Copies: deleting all VSS snapshots requires `vssadmin delete shadows` as Administrator.
- Jump Lists: stored under the user profile but not cleaned by browser uninstallers.

In practice, a non-technical user who uninstalls Tor Browser and clears browser history still leaves UserAssist entries, Prefetch files, Jump List entries, and sometimes EVTX events and VSS snapshots intact. The tool is designed to surface that residual evidence.

The important split is this:
- The tool is strongest for proving **execution**: Tor Browser ran, roughly when, and often how many times.
- The tool is weaker for proving **which specific sites were visited**, because browsing-history sources are easier to wipe — though VSS recovery significantly improves the outlook when shadow copies are available.

### Chain of Custody: Source File Hashing

Before reading any artifact file, the tool computes its SHA-256 hash and records it in the output under `artifact_hashes`. This documents the state of each source at collection time, a standard requirement for forensic evidence handling.

```json
"artifact_hashes": {
  "E:\\Users\\Alice\\AppData\\Roaming\\Tor Browser\\...\\places.sqlite": "a3f9c2...",
  "E:\\Windows\\Prefetch\\TOR.EXE-A1B2C3D4.pf": "7de4b1..."
}
```

---

## Quick Start

### Installation

```bash
git clone https://github.com/danilosolciaa/tor-forensic-collector.git
cd tor-forensic-collector
pip install -r requirements.txt

# Optional: install olefile for proper Jump List OLE parsing
pip install olefile
```

### Fastest Commands

**See the tool working without real evidence:**

```bash
python -m src.cli --demo --output demo_timeline.json --pretty --stats
```

This uses synthetic artifact input, then runs the same normalization, correlation, filtering, and export pipeline as a real collection. It prints the timeline JSON directly in the terminal and also writes `demo_timeline.json`.

**Run against one mounted disk image:**

```bash
python -m src.cli --mount "E:\" --output timeline.json --pretty
```

This scans the mounted image, auto-discovers supported artifacts, and writes one timeline file.

**Run against three mounted snapshots in one command:**

```bash
python -m src.cli \
    --snapshot A=E:\ \
    --snapshot B=F:\ \
    --snapshot C=G:\ \
    --output-dir output \
    --hash \
    --pretty
```

This produces:
- `output/phase_a.json`
- `output/phase_b.json`
- `output/phase_c.json`
- one `.sha256` sidecar per JSON output

### Before You Collect - Verify Artifacts Exist

```bash
python -m src.cli --verify
```

This prints PowerShell one-liners to confirm EVTX audit policy, Prefetch files, browser databases, registry keys, Jump Lists, and VSS snapshots are present before running the full collection.

### Real Usage

**Mounted disk image, single snapshot:**

```bash
python -m src.cli --mount "E:\" --output timeline.json --pretty
```

**Specify artifact paths manually (offline image or explicit files):**

```bash
python -m src.cli \
    --places "C:\Users\Alice\AppData\Roaming\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\places.sqlite" \
    --places-wal "C:\Users\Alice\AppData\Roaming\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\places.sqlite-wal" \
    --prefetch "C:\Windows\Prefetch" \
    --evtx "C:\Windows\System32\winevt\Logs\Security.evtx" \
    --chrome "C:\Users\Alice\AppData\Local\Google\Chrome\User Data\Default\History" \
    --edge   "C:\Users\Alice\AppData\Local\Microsoft\Edge\User Data\Default\History" \
    --brave  "C:\Users\Alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History" \
    --jump-lists "C:\Users\Alice\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations" \
    --output timeline.json --pretty
```

For live Windows collection, omit `--ntuser` to use the live `winreg` extractor (`extract_userassist_live`) instead of the offline hive parser.

**With VSS recovery (requires Administrator, live Windows only):**

```bash
python -m src.cli --mount "C:\" --vss --output timeline.json --pretty
```

VSS recovery enumerates all shadow copies for the drive and checks each for Tor Browser `places.sqlite`. Any found databases are extracted and events are flagged `recovery_status: carved` in the output.

**Mounted disk images, multi-snapshot workflow (A/B/C) in one command:**

Use `--snapshot LABEL=PATH` once per mounted image. The label is embedded into each exported timeline as `phase`, and `--hash` writes a SHA-256 sidecar for each output file.

```bash
python -m src.cli \
    --snapshot A=E:\ \
    --snapshot B=F:\ \
    --snapshot C=G:\ \
    --output-dir output \
    --hash \
    --pretty
```

If you prefer separate runs, the one-image-at-a-time form still works:

```bash
python -m src.cli --mount "E:\" --phase A --hash -o output/phase_a.json
python -m src.cli --mount "F:\" --phase B --hash -o output/phase_b.json
python -m src.cli --mount "G:\" --phase C --hash -o output/phase_c.json
```

Each exported JSON contains `"phase": "A"` / `"B"` / `"C"` so the snapshots stay distinct.

### CLI Examples

```bash
python -m src.cli --examples
python -m src.cli --help
```

---

## How It Works

### 1. Extraction

Each extractor module in `src/extractors/` handles one artifact type:
- `registry.py` - parses offline `NTUSER.DAT` with `yarp` and live UserAssist via `winreg`
- `places_sqlite.py` - queries Firefox/Tor Browser SQLite databases for `.onion` URLs
- `places_wal.py` - parses WAL headers/frames and recovers deleted `.onion` URLs
- `chrome_history.py` - finds `.onion` URLs in Chrome, Edge, and Brave
- `prefetch.py` - parses Windows Prefetch files for execution evidence
- `evtx.py` - extracts Event ID 4688 (process creation) from `Security.evtx`
- `jump_lists.py` - parses `.automaticDestinations-ms` OLE documents for Tor Browser launch entries; falls back to binary carving when `olefile` is not available
- `vss.py` - enumerates Volume Shadow Copies via `vssadmin` and locates Tor Browser history databases within each snapshot

### 2. Normalization

All artifacts are converted into a unified schema in `src/models.py`:
- standard timestamp format (ISO 8601)
- normalized file paths
- provenance tracking (source file, extraction method)
- optional hash sidecars for export verification

### 3. Source Artifact Hashing

Before any file is read, `src/hashing.py` computes its SHA-256 hash. All hashes are written to `artifact_hashes` in the output JSON. This gives the receiving analyst a record of what state each source file was in at the time of collection.

### 4. Correlation

The correlation engine in `src/correlation.py` is intentionally conservative:
- groups execution artifacts by time windows
- matches only on normalized executable paths
- merges sources that likely describe the same execution
- keeps browsing-history artifacts separate unless they are explicitly the same record

### 5. Confidence Scoring

Events receive confidence levels based on:
- number of independent sources
- whether precise timestamps actually align within tolerance
- whether multiple sources agree on run count
- whether the artifact is active or recovered from deleted data

This scoring is deliberately simple. It is meant to help triage findings, not to overclaim mathematical certainty.

---

## Output Format

The tool exports a JSON timeline where each event looks like this:

```json
{
  "event_id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-12-15T14:32:15Z",
  "timestamp_confidence": "high",
  "event_type": "tor_execution",
  "executable_path": "c:\\users\\alice\\desktop\\tor browser\\browser\\firefox.exe",
  "run_count": 15,
  "sources": [
    {
      "artifact": "NTUSER.DAT",
      "extraction_method": "UserAssist",
      "registry_path": "HKCU\\Software\\Microsoft\\Windows\\..."
    },
    {
      "artifact": "Prefetch",
      "extraction_method": "TOR.EXE-A1B2C3D4.pf"
    },
    {
      "artifact": "Jump List",
      "extraction_method": "AutomaticDestinations (olefile)"
    }
  ],
  "confidence": "high",
  "confidence_reasons": [
    "Corroborated across 3 independent sources",
    "Timestamps align within 60s"
  ]
}
```

Top-level timeline metadata also includes:
- `run_mode` (`demo` or `collection`)
- `data_origin` (`synthetic` or `artifact`)
- `phase` when supplied for snapshot workflows
- `artifact_hashes` - SHA-256 of each source file at collection time

CSV export is also supported via `--format csv`.

---

## Project Structure

```text
tor-forensic-collector/
|-- src/
|   |-- models.py              # Data structures
|   |-- normalizers.py         # Convert raw artifacts to unified format
|   |-- correlation.py         # Deduplication and confidence scoring
|   |-- cli.py                 # Command-line interface
|   |-- artifact_locator.py    # Auto-discovery from disk images
|   |-- hashing.py             # Pre-collection SHA-256 hashing (chain of custody)
|   `-- extractors/            # One module per artifact type
|       |-- registry.py
|       |-- places_sqlite.py
|       |-- places_wal.py
|       |-- chrome_history.py
|       |-- prefetch.py
|       |-- evtx.py
|       |-- jump_lists.py
|       `-- vss.py
|-- tests/
|-- examples/
|-- requirements.txt
|-- pyproject.toml
`-- README.md
```

---

## Dependencies

The tool uses established forensic libraries:

- `yarp` (>= 1.0.0) - pure-Python registry parser
- `python-evtx` (>= 0.7.4) - EVTX log parser
- `windowsprefetch` (>= 4.0.3) - Prefetch file parser
- `sqlite3` - built-in Python support for browser databases
- `olefile` (optional) - OLE Compound File parsing for Jump Lists; falls back to binary carving if not installed

Optional development tools: `pytest`, `black`, `isort`, `mypy`

---

## Testing

```bash
pytest tests/ -v
pytest tests/ -v --cov=src --cov-report=html
pytest tests/test_extractors_integration.py -v -o "addopts="
```

---

## Limitations and Future Work

This is a learning project, not a polished forensic suite. Current limitations:

**Browsing Evidence Is Fragile**: `places.sqlite` and Chromium History are erased by standard browser history clears. The execution-evidence sources (UserAssist, Prefetch, EVTX, Jump Lists) are less fragile. VSS recovery can partially offset this for browsing history, but only if shadow copies existed before the deletion.

**WAL Recovery**: URL recovery works, but visit timestamps are not reconstructed. The timeline currently uses the WAL file modification time as an estimate instead of claiming a true visit time.

**EVTX Availability**: Event ID 4688 requires "Audit Process Creation" to be enabled beforehand. Many systems will not have that by default. A sub-policy for command-line argument logging (available from Windows 8.1) adds the full command line to each event — also off by default.

**Prefetch Limitations**: Prefetch can be disabled via registry, and Windows only keeps a limited number of recent Prefetch files.

**Jump List Parsing Without olefile**: When `olefile` is not installed, the extractor falls back to raw binary carving. This recovers the path but loses the LNK-embedded timestamp, reducing confidence to `estimated` instead of `high`.

**VSS Scope**: VSS enumeration only works on live Windows systems and requires Administrator. Accessing shadow copies from a mounted forensic image directly would require `libvshadow` or similar — not implemented here.

**No Memory Forensics**: This project only handles disk artifacts. Memory analysis would add more evidence but is out of scope here.

**Chrome WAL Recovery**: Not implemented. Chromium flushes more aggressively than Firefox, so recovery is less reliable.

**Why OS-level network telemetry is not treated as baseline evidence:**
- Event ID 4688 only exists if Audit Process Creation was enabled before activity.
- WFP events (5156/5157/5158) depend on Filtering Platform auditing, which is often off.
- Windows Firewall logs only help if firewall logging was enabled beforehand.

These are useful when preconfigured, but poor assumptions for ordinary home-user systems.

### What I Would Add With More Time

- `AmCache.hve` parsing (records SHA-1 hash and execution metadata for every binary that ran — strongest single execution artifact after EVTX)
- `ShimCache` (AppCompatCache) extraction
- Full WAL B-tree parser for deeper record reconstruction
- `$MFT` parsing
- SRUM database analysis (per-app network bytes sent/received — could directly corroborate Tor network usage)
- Tor `state` parser for guard connectivity evidence
- `libvshadow` integration for VSS access from mounted images, not just live systems
- Better handling of corrupted or locked files

---

## Dataset Readiness Changes (Internship Scope)

For building realistic E01 demo images without overengineering:

- Use GUI launch via desktop shortcut (`.lnk`) so UserAssist **and Jump List** entries are generated.
- Spread activity across multiple sessions with clear time gaps.
- Create real WAL deletion scenarios: visit `.onion`, delete from history UI, then force-close the browser.
- Generate Chromium `.onion` attempts in Chrome and Edge.
- Add non-Tor browsing traffic as background noise to test filtering quality.
- Use only basic user deletion behavior, not advanced anti-forensics.
- Validate artifacts before acquisition (UserAssist, `places.sqlite-wal`, Prefetch, EVTX policy, Jump Lists).
- Build three image stages: baseline (A), active usage (B), post-deletion (C).
- Enable VSS on the demo VM before session B so shadow copies of phase-B `places.sqlite` survive into phase C — this creates a realistic VSS recovery scenario.
- Keep implementation practical for internship scope; skip deep carving and advanced memory work.

---

## License

MIT License - See `LICENSE` for details.
