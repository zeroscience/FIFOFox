# FIFOFox

```
  ____ _ ____ ____ ____ ____ _  _
  |___ | |___ |  | |___ |  |  \/ 
  |    | |    |__| |    |__| _/\_
  FIFOFox v1.2.3 (ilegnisi)  - Windows named-pipe security auditor and fuzzer
```

**Windows named-pipe security auditor + fuzzer.**
A single-file C tool that enumerates and *grades* named-pipe DACLs, audits
individual pipes, captures live pipe traffic (MITM relay), and fuzzes a pipe
server with crash detection, supported by HTML security-overview report.

<span style="color:red">Warning: </span>The fuzz/squat modes can crash services and the squat+impersonate
path is exactly the behavior EDR rules flag.


---

## 1. Build

No external dependencies beyond `advapi32` (SDDL/ACL/SID/token) and `kernel32`
(pipe APIs). C89-clean; builds on both major Windows toolchains.

```bat
:: MSVC (from a "x64 Native Tools" Developer Command Prompt)
cl /W3 /O2 /D_CRT_SECURE_NO_WARNINGS fifofox.c

:: MinGW-w64
gcc -O2 -Wall -o fifofox.exe fifofox.c -ladvapi32
```

Under MSVC the `advapi32.lib` link is automatic via `#pragma comment(lib,...)`.
Under MinGW you must pass `-ladvapi32` as shown.

---

## 2. Do I need administrator rights?

**No, and running as a *standard user* is usually the most informative way to
use it**, because that is exactly the low-privilege attack surface you want to
measure. Admin/SYSTEM only adds *visibility*, and a service context is needed
only to *weaponize* impersonation.

| Operation | Standard user | Administrator | SYSTEM / service (`SeImpersonatePrivilege`) |
|---|---|---|---|
| Enumerate `\\.\pipe\` (`enum`) | ✅ | ✅ | ✅ |
| Read a pipe's SD / grade DACL | ✅ *if the DACL grants the caller `READ_CONTROL`* (most pipes do; restrictive ones show **N/A**) | ✅ reads more restrictive SDs | ✅ |
| Resolve **server image path** (`audit`, HTML) | ⚠️ denied for processes owned by other users / SYSTEM → shows `(OpenProcess denied)` | ✅ resolves most | ✅ |
| Connect + `fuzz` a pipe | ✅ *if DACL grants connect* (e.g. `Everyone:FA`, NULL DACL) | ✅ | ✅ |
| `capture` (create competing instance) | ✅ *unless server used `FILE_FLAG_FIRST_PIPE_INSTANCE`* | ✅ | ✅ |
| `squat` (claim a free name) | ✅ | ✅ | ✅ |
| **Weaponize** `squat --impersonate` → act as SYSTEM | ❌ token obtained but not usable | ❌ | ✅ requires `SeImpersonatePrivilege` |

**Recommendation:** run `enum`/`audit` first as your normal account to see the
real low-priv exposure, then optionally re-run elevated to fill in server image
paths and any SDs you couldn't read.

---

## 3. Command synopsis

```
fifofox enum    [--all] [--html <file>]
fifofox audit   <pipe> [--html <file>]
fifofox capture <pipe> --authorized [--count N]
fifofox fuzz    <pipe> --authorized [options]
fifofox squat   <pipe> --authorized [--impersonate]
fifofox version | help
```

`<pipe>` may be a **bare name** (`cowork-vm-service`) or a **full device path**
(`\\.\pipe\cowork-vm-service`). The bare form is expanded to `\\.\pipe\<name>`.

### Global flags (valid in any position, any mode)

| Flag | Effect |
|---|---|
| `-v`, `--verbose` | Narrate each step to **stderr** (`[*] ...`). Keeps stdout/HTML clean for redirection. |
| `--debug` | Verbose **plus** handles, Win32 error codes, and per-iteration fuzz detail (`[dbg] ...`). Implies `-v`. |
| `--color` | Force ANSI color on (even when redirected). |
| `--no-color` | Force ANSI color off. |
| `--no-banner` | Suppress the startup banner. |

Operational logging goes to **stderr** on purpose, so `fifofox enum --html r.html -v`
won't pollute the report or any piped stdout.

**Console colors (auto):** color is enabled automatically when stdout is an
interactive console that supports VT sequences, and **disabled when stdout is
redirected or piped**, or when the `NO_COLOR` environment variable is set, so a
redirected report/log never contains escape codes. Severity coloring:
**red** = DANGER (and a red highlight for **NULL DACL**), **yellow** = WARN,
**green** = OK, **gray** = N/A / dim labels, **cyan** = SDDL. `enum` and `audit`
print a one-line color legend at the end.

---

## 4. Commands in detail

### 4.1 `enum` - grade every pipe on the box

Walks `\\.\pipe\*`, reads each pipe's security descriptor, converts it to SDDL,
and grades the DACL (see 5.). By default prints only **flagged** pipes
(WARN/DANGER) plus a summary.

| Option | Meaning |
|---|---|
| `--all` | Also list **OK** pipes and **unreadable** ones (`N/A`), not just flagged. |
| `--squat` | **Active probe.** For each pipe, also attempt a `FILE_FLAG_FIRST_PIPE_INSTANCE` create; if it succeeds the name has no owner → flagged **DANGER (squattable)** and the grade is escalated. (Most *currently-listening* pipes correctly report "not squattable", an instance already exists. See 4.2 for the more useful single-name case.) |
| `--html <file>` | Additionally write a standalone HTML security-overview report (6). |

```bat
fifofox enum                          :: just the flagged pipes + summary
fifofox enum --all                    :: everything, including OK / N/A
fifofox enum --all --html report.html :: full report to console + HTML
```

> **Behaviour note:** `enum` opens a **client handle** (`READ_CONTROL`) to each
> pipe to read its SD. On some servers this registers as a connection. It is
> read-only and momentary, but be aware of it on sensitive hosts.

### 4.2 `audit` - deep single-pipe report

Full report for one pipe: `GetNamedPipeInfo` geometry (type, buffer sizes, max
instances), server + client PID and image path, SDDL, ACE-by-ACE grade, and a
**live squattability test** (attempts `CreateNamedPipe` with
`FILE_FLAG_FIRST_PIPE_INSTANCE`).

| Option | Meaning |
|---|---|
| `--html <file>` | Write a single-row HTML report including geometry + squattability. |

```bat
fifofox audit cowork-vm-service
fifofox audit cowork-vm-service --html pipe.html
fifofox audit \\.\pipe\lsass --debug
```

Squattability verdicts:
* **SUCCEEDED (DANGER)** - no first-instance owner present; the name can be
  pre-created by a malicious process (instance-interception / impersonation).
* **`ACCESS_DENIED` (ok)** - name already owned with `FILE_FLAG_FIRST_PIPE_INSTANCE`
  (or otherwise denied) → not squattable while held. This is the secure config.
* **`PIPE_BUSY`/`ALREADY_EXISTS` (WARN)** - an instance exists *without*
  first-instance protection → investigate the race window.

A **squattable** result **escalates the overall verdict to DANGER** (console row
and HTML badge), independent of the DACL grade. Because the squat test does not
need the pipe to currently exist, `audit` will **continue to the squat test even
if the name is not currently open** (`open` failed). This is the *most useful*
case: testing whether a name belonging to a **stopped/not-yet-started service**
can be pre-created and squatted before the legitimate server claims it.

### 4.3 `capture` - instance-interception relay (MITM)

Creates a **competing instance** of the target pipe name, waits for a client to
land on it, dials the real server, and relays bytes both ways, logging every
chunk and writing client→server frames to a **corpus** for `fuzz`.

| Option | Meaning |
|---|---|
| `--authorized` | **Required.** Affirms you have permission. Without it the tool refuses (exit 2). |
| `--count N` | Number of client sessions to relay before exiting (default **1**). |

```bat
fifofox capture cowork-vm-service --authorized --count 5 -v
```

**Requires** that the real server did **not** use `FILE_FLAG_FIRST_PIPE_INSTANCE`
(check with `audit` first). If it did, `CreateNamedPipe` returns `ACCESS_DENIED`
and capture reports it as impossible - which is itself the security finding.

Interception is **opportunistic**: you only catch clients the SCM dispatches to
*your* instance. Use `--count >1` and trigger reconnects (e.g. restart the
client app) to gather traffic. **Intrusive and EDR-visible.**

### 4.4 `fuzz` - frame fuzzer with crash detection

Connects as a client and sends mutated frames, reading responses non-blocking,
and detects when the pipe disappears (probable server crash), dumping a repro.

| Option | Default | Meaning |
|---|---|---|
| `--authorized` | - | **Required** (see above). |
| `--frame <kind>` | `raw` | Wire framing: `raw`, `len16le`, `len16be`, `len32le`, `len32be`, `cmd`. |
| `--cmd <prefix>` | `"3 "` | Command prefix used when `--frame cmd` (Timbuktu-style command messages). |
| `--corpus <file>` | none | Seed mutations from a `capture` corpus (structure-aware; ~65% of cases mutate a real frame). |
| `--iters <N>` | `500` | Number of test cases. |
| `--seed <hex\|dec>` | fixed | PRNG seed for **reproducible** runs (`0` → built-in fixed seed). |
| `--maxlen <N>` | `4096` | Max length of random payloads. |
| `--delay <ms>` | `15` | Delay between iterations (and pre-read settle time). |

```bat
:: blind, length-prefixed
fifofox fuzz cowork-vm-service --authorized --frame len32le --iters 2000

:: structure-aware using a captured corpus, reproducible
fifofox fuzz cowork-vm-service --authorized --corpus fifofox_corpus_123.bin --seed 0xC0FFEE -v
```

**Mutation strategies** (cycled; corpus-havoc dominates when a corpus is loaded):

| Strategy | What it probes |
|---|---|
| `random` | Arbitrary bytes |
| `long-A (overflow probe)` | Growing `'A'` walls 64 → 65536 |
| `format-string` | `%n %s %x %p` tokens |
| `path-traversal` | `..\..\` + `/../` sequences |
| `length-lie` | Tiny body, **declared length `0x7FFFFFFF`** (the Timbuktu `nNumberOfBytesToWrite` trick → OOM/overread handling) |
| `boundary 0x00/0xFF` | All-zero / all-ones runs |
| `zero/short` | 0-length declaration, tiny bodies |
| `corpus-havoc` | Real captured frame + multi-bit flips / truncation / padding |

**Crash detection:** after each send the pipe's liveness is probed
(`WaitNamedPipe`). If it vanishes (`ERROR_FILE_NOT_FOUND`), the offending wire
bytes are written to `crash_<ts>_<iter>.bin` and the run stops.

### 4.5 `squat` - squat + impersonation PoC (dual-use, gated)

Claims the pipe name with `FILE_FLAG_FIRST_PIPE_INSTANCE`, waits for a client,
and (optionally) impersonates it to show the squat→impersonation risk.

| Option | Meaning |
|---|---|
| `--authorized` | **Required.** |
| `--impersonate` | After a client connects, call `ImpersonateNamedPipeClient()` and print the impersonated user + integrity level. |

```bat
fifofox squat cowork-vm-service --authorized --impersonate
```

If the name is already owned, it reports the secure outcome and exits. Obtaining
a SYSTEM/High token here is only *exploitable* if your process holds
`SeImpersonatePrivilege` (service accounts, not standard users). **Noisy by
design**. This is the exact behaviour the Elastic impersonation rule flags.

---

## 5. Severity model (the grade)

A pipe's DACL is graded by what **low-privileged SIDs** are granted. Low-priv
SIDs: `Everyone (S-1-1-0)`, `Authenticated Users (S-1-5-11)`,
`Users (S-1-5-32-545)`, `Anonymous (S-1-5-7)`, `Guests (S-1-5-32-546)`,
`Power Users (S-1-5-32-547)`, `INTERACTIVE (S-1-5-4)`.

| Grade | Badge | Trigger |
|---|---|---|
| 2 | **DANGER** | Low-priv SID holds `WRITE_DAC` / `WRITE_OWNER` / `GENERIC_ALL` (object **takeover**), **or** a **NULL DACL** (everyone full), **or** the name is **squattable** (`audit`, or `enum --squat`). |
| 1 | **WARN** | Low-priv SID can write pipe **data** (`FILE_WRITE_DATA` / `APPEND_DATA` / `GENERIC_WRITE` / `DELETE`). |
| 0 | **OK** | No low-priv write right. |
| − | **N/A** | SD not readable as the current user. |

> **Important interpretation:** `Everyone:Full` ("connect + read/write") is
> *common by design* for IPC pipes. The **serious** flags are `WRITE_DAC` /
> `WRITE_OWNER` / `GENERIC_ALL` to a low-priv SID, or a NULL DACL. A permissive
> DACL only governs **who may connect** - real privilege impact depends on the
> server's **in-band authorization** (does it authenticate the caller after
> accept?), which this tool does not evaluate. See 8.

---

## 6. HTML report (`--html`)

`enum --html` and `audit --html` emit a **standalone, self-contained** HTML page
(embedded CSS, dark theme, no external assets):

* Header with tool version, **hostname**, and generation timestamp.
* Summary cards: total pipes, **Danger / Warn / OK** counts.
* A table per pipe: severity badge, pipe name, server PID, server image path,
  findings (flagged ACEs; for `audit` also geometry + squattability), and the
  full **SDDL**.
* A footer severity key.

The table uses a **fixed layout** with defined column widths (`<colgroup>`), and
long values (full image paths, SDDL, long pipe names) **wrap** via
`overflow-wrap:anywhere`; the SDDL and image cells become independently
**scrollable** past a few lines, so one long value can no longer stretch the
whole report. `audit --html` reuses the same layout for a single-row report that
also folds in geometry + squattability.

All dynamic text is HTML-escaped (`& < > " \n`), so SDDL/paths/names cannot break
the markup. Open the file in any browser; it is safe to share as a report.

```bat
fifofox enum --all --html C:\reports\pipes_overview.html
fifofox audit cowork-vm-service --html C:\reports\cowork_pipe.html
```

---

## 7. Output files

| File | Produced by | Contents |
|---|---|---|
| `fifofox_fuzz_<ts>.log` | `fuzz` | Per-iteration strategy, declared/actual length, wire-byte hexdump, response hexdump, crash markers. |
| `crash_<ts>_<iter>.bin` | `fuzz` | Exact wire bytes of a suspected crash case (replay to reproduce). |
| `fifofox_capture_<ts>.log` | `capture` | `C2S`/`S2C` hexdump transcript of relayed traffic. |
| `fifofox_corpus_<ts>.bin` | `capture` | Client→server frames as `[u32 LE length][bytes]` records - feed to `fuzz --corpus`. |
| `<file>` | `--html` | HTML report (6). |

`<ts>` is a Unix timestamp; files land in the current working directory.

---

## 8. Limitations & caveats

* **In-band authorization is not assessed.** The grade reflects who can *connect*
  and *write*, not whether the server authenticates callers afterward. A pipe
  graded WARN/DANGER may still be safe if the server validates the client token;
  conversely an OK pipe may be exploitable via protocol logic.
* **TOCTOU / PID-reuse is not detected.** A content fuzzer cannot find a
  check-then-use race in the auth layer (e.g. `GetNamedPipeClientProcessId` →
  `OpenProcess` → validate). Confirming that needs static RE of the server plus a
  dedicated race harness with a protocol-specific oracle.
* **Grader evaluates ALLOW ACEs only** - it does not subtract DENY ACEs, so the
  grade is a fast heuristic, not a full `AccessCheck` (pipes rarely carry deny
  ACEs; verify if it matters).
* **Memory-safe targets.** Against a Go/Rust/.NET server, the `long-A` /
  `length-lie` strategies are unlikely to yield classic memory corruption; expect
  **DoS (panic)** and **OOM** signals rather than control-flow hijack.
* **`enum` connects to each pipe** to read its SD (see 4.1 note).
* **ASCII names.** Uses ANSI APIs; pipe names with non-ASCII characters may be
  mangled in output.
* **Capture is opportunistic and EDR-visible** (4.3).

---

## 9. Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (or `help`/`version`). |
| `1` | Usage error / missing argument / operation failure. |
| `2` | A gated mode (`fuzz`/`capture`/`squat`) was run without `--authorized`. |

---

## 10. Typical workflow

```bat
:: 1) Survey the whole box (as a standard user) and get a report
fifofox enum --all --html overview.html

:: 2) Drill into an interesting pipe
fifofox audit cowork-vm-service --html cowork.html

:: 3) If not first-instance protected, learn the protocol
fifofox capture cowork-vm-service --authorized --count 5 -v

:: 4) Structure-aware fuzz from the captured corpus
fifofox fuzz cowork-vm-service --authorized --corpus fifofox_corpus_<ts>.bin -v

:: 5) (Optional, gated) demonstrate squat/impersonation feasibility
fifofox squat cowork-vm-service --authorized --impersonate
```

---

## 11. Changelog

**v1.2.3 (ilegnisi)**

* New `--no-banner` flag to suppress the startup banner.
* HTML report footer carries the Zero Science Lab attribution.
* `--verbose` / `-v` and `--debug` operational logging (to stderr).
* HTML security-overview report for `enum` **and** `audit` (`--html`).
* `version` / `help` subcommands; version banner in usage.
* Structure-aware fuzzing via captured corpus (`capture` → `fuzz --corpus`).
* Hardening: fuzz startup OOM cleanup; right-sized HTML-escape buffers;
  documented DENY-ACE grading limitation.
* **Console ANSI color** (auto / `--color` / `--no-color`, honors `NO_COLOR`):
  severity-coded findings, distinct red highlight for NULL DACL, color legend.
* **`audit` reformatted as an aligned attribute table** with the interesting
  rows (grade, squattable, SDDL) color-highlighted.
* **HTML readability**: fixed table layout + `<colgroup>` widths + wrapping and
  scrollable SDDL/image cells so long values no longer overflow the report;
  `.badge{white-space:nowrap}` + wider Severity column so "DANGER" no longer
  wraps to a second line.
* **Squattability escalates to DANGER**: `audit` now folds squattability into the
  overall verdict/badge and squat-tests even names that aren't currently open
  (stopped-service pre-squat case); new `enum --squat` active probe flags
  squattable pipes across the whole box.

---

## 12. Powered by

Silly Security Inc. - https://sillysec.com
