# Go watcher — why it was rewritten and what changed

**Language:** [українська](README.md) · English

This document explains why the DocScan watcher (the service that scans new files on PCs and servers) was
rewritten from PowerShell to Go: the defect a load test found, how it was fixed, what stayed the same, what
was added and what the tests measured. Project documentation: [SCAN-FLOW.en.md](../SCAN-FLOW.en.md), the
watcher is its §7.

**Status (2026-11-18):** the Go watcher has been tested on a test terminal server and now ships in the
package: ▷ (cirun) builds `docscan-watcher.exe` from the commit under test (cross-built on the Mac, `go vet` +
`go test`), `build_package.ps1` puts it into `watcher\`, and `install.ps1` registers it as the Windows service "DocScan Watcher" (`DocScanWatcher`: automatic, SYSTEM, restarted
after a failure; `service_windows.go`)
with it. The PowerShell watcher stays in the package as a fallback: `install.ps1 -WatcherEngine ps`.

**Contents**
1. [Summary](#1-summary)
2. [How it was found: a terminal-server load test](#2-how-it-was-found-a-terminal-server-load-test)
3. [The PowerShell watcher's defect](#3-the-powershell-watchers-defect)
4. [Other weaknesses found on the way](#4-other-weaknesses-found-on-the-way)
5. [The new watcher](#5-the-new-watcher)
6. [What stayed the same (compatibility)](#6-what-stayed-the-same-compatibility)
7. [Test results](#7-test-results)
8. [Not done yet](#8-not-done-yet)
9. [Files](#9-files)

---

## 1. Summary

| | Before (PowerShell) | Now (Go) |
|---|---|---|
| File-system events | PowerShell event queue; draining it costs time proportional to the square of its length | a dedicated goroutine reads `ReadDirectoryChangesW` and hands names on immediately |
| When scanning starts | only after the whole event queue is drained | at once, while events keep arriving |
| Files at a time | 1 | automatic, `-MinWorkers`..`-MaxWorkers` (by queue and machine CPU) |
| `yara64` priority | normal | below normal: the users' programs get the CPU first |
| Scan order | arrival order | single files (a download, a saved document) before bulk copies; bulk copies round-robin per user |
| Queue visibility | none: the watcher stays silent | queue size logged every minute, WARN while it grows |
| 114 450 files at once (25 RDP sessions) | **0 scans in 45 min**, 330–410 MB and growing | **all 114 450 scanned, 0 missed**, up to ~100 MB |

Records in `docscan-results.json` (Wazuh), `watcher.log` lines, options, disarm, quarantine, the macro
store, the critical-information queue and disarm retries are unchanged (§6).

---

## 2. How it was found: a terminal-server load test

DocScan was to be installed on a terminal server (Windows Server 2019) with a few hundred RDP users. The
watcher had only been tested on single-user PCs, so a test terminal server and load-test tools were built
([../ci/loadtest/](../ci/loadtest/), §9):

- test server: Windows Server 2019 Standard, 16 vCPU, 32 GB, RD Session Host role, 25 local users; DocScan
  installed from the GitHub release with critical-information rules;
- **25 real RDP sessions at once** (opened by a script from another Windows machine);
- test set of 4 579 documents: 42 inert attack samples (`test-samples`), documents for false-positive and
  critical-information checks (`seeds`), public corpora (Apache POI, Apache Tika, pdf.js, plaso,
  LibreOffice, oletools, LNK);
- a user-activity generator logs every action with millisecond time; the report matches it with the
  watcher's records: every file scanned (misses), latency, verdicts, resources.

Scenarios:
1. **Normal pace** — every user creates, edits, renames or deletes a document every ~20 s. The PowerShell
   watcher coped: 0 misses, a new file scanned in ~4 s.
2. **Stress** — all 25 users copy the whole set to their desktop at once: **114 450 files** (~9.4 GB) in
   ~6 minutes, the way a morning looks when several people unpack big archives, or a folder syncs. This is
   where the defect showed.

---

## 3. The PowerShell watcher's defect

**Observed.** After 5 minutes ~97 000 files were copied and the watcher had made **not a single scan**
(`yara64` never started); after 45 minutes still 0. The process neither crashed nor hung: task `Running`,
no errors in the log, one CPU core busy all the time, 330–413 MB of memory. After ~35 minutes buffer
overflows appeared (`Too many changes at once in directory`) — some events were lost as well.

**Impact.** While in this state DocScan detects and disarms nothing on the machine, and from outside all
looks fine: no errors, no alerts. On a server with hundreds of users a few concurrent bulk copies are enough.

**Cause** — the main loop of [../watcher/docscan-watcher.ps1](../watcher/docscan-watcher.ps1) (the
`while ($true)` after `Register-ObjectEvent`):

1. **Order of work.** The inner `while ($e) { ... }` takes **all** queued events first and only then goes on
   to scanning. While events arrive faster than they are taken, scanning is never reached.
2. **Quadratic cost.** The next event is taken with `Get-Event | Select-Object -First 1`; `Get-Event` returns
   the whole queue each time, so N events cost ~N². With ~300 000 events (Created + several Changed per file)
   that is hundreds of billions of steps, and every new event makes the rest longer.
3. **Heavy objects.** Every `FileSystemWatcher` event is wrapped in a PowerShell `PSEventArgs`; hundreds of
   thousands of them are the growing memory.
4. **One thread.** Even without 1–3, files are scanned strictly one by one: 114 450 files at ~0.5–0.8 s is
   many hours, with a user's new file at the end of the queue.

A single-user PC gets tens of events at a time, so neither daily use nor the CI tests (the combat test feeds
files in batches and waits) ever showed it.

---

## 4. Other weaknesses found on the way

- **Critical-information queue under parallel scans.** `yara64` appends a document to `critical.json` with
  `fopen(..., "ab")` + `fwrite`; the CRT writes a large line in several `WriteFile` calls, so two `yara64`
  writing at once can interleave lines. The PowerShell watcher never ran two at once, but a parallel watcher
  without protection would corrupt the queue. Fix — §5.
- **Silence instead of a signal.** No way to see the watcher falling behind: no queue size, no warning.
- **A hung `yara64`** would block the whole watcher for good (no per-scan timeout).
- **Log line format:** `<time> [LEVEL] <verdict> <category> <path>  <findings>` — path and findings are
  separated by two spaces, and a path may itself hold two spaces (the corpus has `WinHex  18.5 32-bit.lnk`).
  Anything parsing `watcher.log` must allow for it (the load-test report tries every cut). The format is
  kept — the CI checks rely on it.

---

## 5. The new watcher

Go 1.22+, standard library only (no third-party dependencies), one `docscan-watcher.exe` (~7 MB), builds on
any OS: `GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w"`.

```
ReadDirectoryChangesW (every -WatchPath folder, recursive, 1 MB buffer)
   │  receiver goroutine: only reads the kernel buffer and hands names on - never waits,
   │  so the buffer does not overflow while files are scanned
   ▼
coordinator (one goroutine, owns all state)
   │  merges a file's events · waits -SettleSeconds of quiet · -RescanCooldown for autosave
   │  scan order (sched.go) · writes records and log lines · disarm retries · rescan after overflow
   │  pool size (pool.go) · "queue: ..." in the log every minute
   ▼
workers (pool of automatic size)
      file complete? → SHA256 (same content - skip) → yara64 (+ disarm, macro copy, critical queue)
```

**Scan order** ([sched.go](sched.go)):
- `retry` — disarm retries of locked files (few, and already late);
- `fresh` — single files: a folder that got at most 10 files in the last minute and a branch (profile + two
  folders) that got at most 30 (a download, a saved
  document, an attachment); scanned before any bulk copy, newest first (a burst leaves files here too - the
  first files of every folder and the small folders - and a file just downloaded must not wait behind them);
- `bulk` — mass copies (a folder copied, an archive unpacked, a sync): one queue per profile
  (`C:\Users\<name>`), served round-robin — one user's 100 000 files do not stall the others.

**Automatic pool size** ([pool.go](pool.go)), every 30 s:
- queue empty for 2 min → back towards `-MinWorkers` (by 2);
- machine CPU ≥ `-CpuHigh` (85 %) → −2 workers: terminal-server users come first;
- queue > 4 × workers and CPU < `-CpuTarget` (60 %) → +2, up to `-MaxWorkers` (default: CPU count, max 32);
- if the last +2 brought no more scans (the limit is the disk, the antivirus or process start, not the
  number of workers) → back, and no growth above that for 10 min;
- every change is logged: `workers 8 -> 10 (queue grows; queue 4064, CPU 55%, 72 scans in 30s)`;
- `-Workers N` — a fixed number (no automatic size).

**Also new:**
- `yara64` (and its sandboxed worker process, which inherits it) runs at **below-normal** priority;
- **critical-information queue:** the same content is checked once (claimed before the scan, as several
  workers may scan it at once); every worker gives `yara64` its own file (`critical\critical-<n>.part`);
  after the scan the coordinator appends it to `critical.json` in one write under a lock — lines never
  interleave (checked: 194 lines from a parallel scan, each valid JSON);
- **per-scan timeout** `-ScanTimeout` (600 s): a hung `yara64` is killed, the file gets a record with the
  error, the watcher goes on;
- **queue monitoring:** `queue: waiting W, ready R (single files F, bulk B from U users), scanning S of N
  workers, done in the last minute D`; WARN `scan backlog: ...` when the queue is > 1000 and growing;
- lost events (kernel buffer overflow or a full internal channel) → a minute later the folders are walked
  and files changed since then are scanned (as before, `rescan after overflow`).

---

## 6. What stayed the same (compatibility)

- **Options** — the names of `docscan-watcher.ps1` (`-WatchPath`, `-Yara`, `-Rules`, `-OutDir`,
  `-BackupDir`, `-NoDisarm`, `-QuarantineGeneral`, `-CriticalRules`, `-CriticalOut`, `-MacroUpload`, …), so
  `install.ps1` and the docs need little change. New: `-MinWorkers`, `-MaxWorkers`, `-Workers`, `-CpuTarget`,
  `-CpuHigh`, `-ScanTimeout`.
- **`docscan-results.json` record** — the same fields in the same order, no `null` values (they once broke
  the Wazuh indexing), the same `summary` (up to 600 characters), identical repeats skipped (except HIGH).
- **`watcher.log` lines** — the same format (`check_watcher.py` and the load-test report rely on it).
- **Verdict logic**: policy + vendor rules, a match makes a document at least MEDIUM / a general file HIGH,
  `.zip` and an archive under another name, `-QuarantineGeneral`, `SKIPPED` / `ERROR`.
- **Disarm and retries**: a locked file is retried every 30 s, then every 5 min, `DisarmPending` after
  `-DisarmNoticeHours`, the list in `retry.json` (same format, read by both versions).
- **Macro store** `macros\<sha256>.vba.txt` with its header, `sent.txt`, upload to `-MacroUpload`,
  retention; VBA code decoded from the machine's ANSI code page.
- **Rules** compiled once at start (`yarac64` → `rules.yarc`), checked before the start.
- The verdicts of the 42 reference samples match `ci/expected-verdicts.tsv`.

---

## 7. Test results

Test terminal server: 16 vCPU, 32 GB, Windows Server 2019, Microsoft Defender on, 25 active RDP sessions.
Stress: 25 × 4 579 = **114 450 files** in ~6 min.

| | PowerShell | Go, 8 workers (fixed) | Go, automatic pool + scan order |
|---|---|---|---|
| Scanned | 0 in 45 min (stopped) | 114 450 / 114 450 | 114 450 + 400 single files / all |
| Misses / scan errors | — | 0 / 0 | 0 / 0 |
| Event buffer overflows | yes (events lost) | 0 | 0 |
| Workers | 1 | 8 | 8 → 12 → 16 (automatic; one +2 without a gain was rolled back) |
| Throughput | 0 | ~630 documents / min | ~1 140 / min on average, ~1 200 / min at 16 workers |
| Time for the whole queue | — | 3 h 8 min | **1 h 41 min** |
| Machine CPU while scanning | ~6 % (one core: queue draining) | ~21 % | ~46 % |
| Watcher memory | 330–413 MB, growing | ≤ 103 MB | ≤ 109 MB |
| A single file during the burst | — | (would wait in the common queue, up to 3 h) | median 2.7 s; in the first ~12 min up to 7 min (fixed, see below) |
| Findings | — | HIGH 4 400 (all disarmed), MEDIUM 3 875, 322 in the critical-information queue | HIGH 4 413, MEDIUM 3 885, 443 in the critical-information queue (with duplicates — fixed, see below) |

**What the third run showed and what was fixed after it:**
- *Single files waited 4.5–7 min in the first ~12 min*, 2.5–3.5 s afterwards. The copied tree has hundreds of
  small folders (< 10 files), so ~5 000 burst files landed in the "fresh" lane and real downloads queued
  behind them. Fix: the fresh lane is served **newest first**.
- *Duplicates in the critical-information queue* (443 lines): the same document in 25 profiles was scanned by
  several workers at once, and each saw "not queued yet". Fix: the content is **claimed before the scan**.

**Fourth run (with these fixes)**: the same stress, 16 workers; Defender turned off at minute 7 (see below),
so the throughput is not directly comparable.
- 114 685 scans, **0 missed**, 0 scan errors; the whole queue in **1 h 38 min**, ~1 170 files / min.
- **Critical-information queue: 236 lines** (was 443): no more duplicates.
- **Single files:** 90 % within ≤ 3.2 s (median 2.6 s). But 23 of 385 waited 5.5–14 min — all of them dropped
  in the first 6 min, **while the copy was still running**: burst files from small folders kept entering the
  fresh lane and were newer than the real downloads. After the copy ended: 2.5–3 s.
- Fix after the run: a mass copy is also detected **by branch** (profile + two folders,
  `C:\Users\<name>\Desktop\<tree>`): more than 30 files a minute into any subfolders of a branch — all of it goes
  to the bulk queue. A file in `Downloads` or saved straight to the desktop stays a single file. Checked by a
  unit test; on the server — in the next run.

**Why not faster.** At 8 workers the CPU is ~21 %, so the processor is not the limit: every scan is two new
processes (the `yara64` broker and its sandboxed worker, [SCAN-FLOW §4.11](../SCAN-FLOW.en.md)), loading
`rules.yarc`, and Defender checking every process start and every file. The automatic pool sees it (+2
workers without a gain → back). Further speed-ups — §8.

---

### Microsoft Defender during the test

- **What it detected.** After a signature update Defender on the test server started detecting DDE test
  documents of the public oletools corpus (`Exploit:O97M/DDEDownloader`, `Exploit:O97M/CVE-2016-7262`) and
  blocked copying them into the profiles: 150 copy errors per run (6 files × 25 users), and it deleted one source file
  from the test set. The watcher was not affected (no "gone before scan"), but the set became incomplete and
  the runs incomparable. On the same 4 579 documents DocScan gave ~176 HIGH and ~155 MEDIUM per user,
  Defender 4 detections: different layers (see [SCAN-FLOW §1](../SCAN-FLOW.en.md#docscan-and-the-antivirus-microsoft-defender-eset)).
- **What was done.** On the test server Defender is turned off by `rds_defender.ps1 -Off` (as policy —
  survives reboots and signature updates; the test-set folder excluded); `rds_reset.ps1 -DefenderOff` checks
  it before every run. Workstations keep their antivirus, with exclusions for the DocScan folders.
- **What it cost.** When Defender was turned off in the middle of the fourth run, the throughput at 16 workers
  rose only from ~1 200 to ~1 270 files / min (~6 %): the main cost of a scan is starting two processes and
  loading the rules for every file, not the antivirus (§8, item 4).

## 8. Not done yet

1. ~~Package and install~~ — done: `build_package.ps1`, `install.ps1` (`-WatcherEngine go|ps`, `-Workers N`),
   `DocScan-Install.ps1` (passes both on), the combat test (`check_watcher.py` reads the extension lists from
   `config.go`; `config_test.go` checks they match the `.ps1`).
2. **A normal PC** (Windows 11, 4 cores, Defender) — the same stress in one user's profile.
3. ~~A Windows service~~ — done: `DocScanWatcher` instead of a scheduled task (clean stop, restart by the SCM,
   events in the System log); `install_smoke.ps1` in CI checks the restart after the process is killed.
4. **Batch mode for `yara64`** (several files per process) — would remove the cost of a process start and a
   rules load per file.
5. Signing `docscan-watcher.exe`, so antivirus heuristics leave the new binary alone.

---

## 9. Files

| File | Contents |
|---|---|
| [main.go](main.go) | start, rules check and compile, coordinator, disarm retries, writing results |
| [scan.go](scan.go) | one file: wait until complete, SHA256, run `yara64`, verdict, `summary`, log line |
| [sched.go](sched.go) | scan order: retries, single files, bulk copies round-robin per user |
| [pool.go](pool.go) | worker pool and its automatic size |
| [store.go](store.go) | critical-information queue (one writer) and the macro store |
| [config.go](config.go) | options (the PowerShell watcher's names), default extension and exclusion lists |
| [logx.go](logx.go) | `watcher.log` / `docscan-results.json`: append with rotation |
| [fs_windows.go](fs_windows.go) | `ReadDirectoryChangesW`, locked file, ANSI → UTF-8, machine CPU, priority |
| [fs_other.go](fs_other.go) | stubs for development on macOS / Linux (folder polling) |
| [sched_test.go](sched_test.go) | scan-order tests (`go test ./...`) |

Load test — [../ci/loadtest/](../ci/loadtest/):

| File | Runs on | What it does |
|---|---|---|
| `rds_setup.ps1` | test server | RD Session Host role, N local users, RDP, time zone |
| `rds_connect.ps1` | Windows client | N RDP sessions at once (`-Close` to close them) |
| `rds_docs.ps1` | test server | test sets from the file share into `C:\loadtest\docs` (no malware) |
| `rds_reset.ps1` | test server | from zero: uninstall DocScan with its data, remove test files, install the release, (optionally) the Go watcher |
| `rds_defender.ps1` | test server | Microsoft Defender off / on (`-Off` / `-On`; as policy - survives reboots and signature updates; `C:\loadtest` excluded). Without it, after a signature update Defender blocks and deletes part of the test set (DDE samples of the oletools corpus) and slows every scan |
| `rds_watcher_swap.ps1` | test server | replace `docscan-watcher.exe` with a build that is not released yet (or, for old packages, switch PowerShell ↔ Go) |
| `loadgen.ps1` | test server, one process per user | user activity: normal pace, `-Burst`, `-All` (whole set), `-Probe` (single files) |
| `rds_load.ps1` | test server | one run: generators + resources every 5 s; waits until every file is scanned |
| `loadtest_report.py` | anywhere | report: misses, latency per action type, verdicts, resources, per-minute timeline |
