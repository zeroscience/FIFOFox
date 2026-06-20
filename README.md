# FIFOFox

```
  ____ _ ____ ____ ____ ____ _  _
  |___ | |___ |  | |___ |  |  \/
  |    | |    |__| |    |__| _/\_
  FIFOFox v1.2.3 (ilegnisi)  -  Windows named-pipe security auditor & fuzzer
```

![platform](https://img.shields.io/badge/platform-Windows-0a7bbb)
![language](https://img.shields.io/badge/language-C%20(C89)-555555)
![build](https://img.shields.io/badge/build-MSVC%20%7C%20MinGW-blue)
![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![version](https://img.shields.io/badge/version-1.2.3%20%22ilegnisi%22-success)

**FIFOFox** is a single-file, zero-dependency Windows **named-pipe security toolkit**
written in pure C, no installer, no runtime, no NuGet/pip. One small `.exe` takes
you from *recon* all the way to *protocol reverse-engineering*:

- **Enumerate & grade** every pipe's DACL on the box, and flag the dangerous ones.
- **Deep-audit** a single endpoint: SDDL, geometry, server/client PIDs, squattability.
- **Capture** live traffic through an interception (MITM) relay and bank a fuzz corpus.
- **Fuzz** a pipe server with crash detection - blind or structure-aware from a corpus.
- **Squat / impersonate** a pipe name for the dual-use escalation cases (gated).
- **Craft, send, and decode** length-prefixed **protobuf** IPC messages, so you can
  actually *talk to* a service and *read what it says back*.

It is deliberately a **standard-user** tool first: the most interesting view of a
pipe's attack surface is the one a low-privileged process sees. Admin only adds
visibility; a service context is needed only to *weaponize* impersonation.

> ⚠️ **Warning.** `fuzz`, `capture`, and `squat` are intrusive and can crash
> services; `squat --impersonate` is precisely the behavior EDR rules flag. Use
> only on systems you own or are explicitly authorized to test.

> The `decode` and `craft` protocol tooling in this build grew directly out of a
> live named-pipe research engagement against a LocalSystem updater IPC. See the
> companion Zero Science Lab write-up.

---

## Contents

- [1. Build](#1-build)
- [2. Administrator rights](#2-administrator-rights)
- [3. Command synopsis](#3-command-synopsis)
- [4. Commands in detail](#4-commands-in-detail)
- [5. Severity model](#5-severity-model)
- [6. HTML reports](#6-html-reports)
- [7. Output files](#7-output-files)
- [8. Limitations and caveats](#8-limitations-and-caveats)
- [9. Exit codes](#9-exit-codes)
- [10. Typical workflow](#10-typical-workflow)
- [11. Changelog](#11-changelog)
- [12. Credits](#12-credits)

### Modes at a glance

| Mode | What it does |
|---|---|
| `enum` | Enumerate and **grade** every pipe's DACL; optional HTML report. |
| `listeners` | Enumerate **loopback/wildcard TCP IPC** endpoints + owner/privilege (the other half of local IPC). |
| `audit` | Deep single-pipe report: SDDL, geometry, PIDs, squattability, owning-service escalation surface + **trust-predicate linter**. |
| `capture` | Interception **relay** (MITM); logs both directions + writes a fuzz corpus. |
| `fuzz` | Frame **fuzzer** with crash detection; structure-aware with a corpus. |
| `squat` | Claim/relay a pipe name; optional `--impersonate` (gated). |
| `send` | Deliver one message (raw/framed **or** a crafted kiros frame) and decode the reply. |
| `craft` | Build a Logitech **"kiros"** protobuf request frame from flags. |
| `decode` | Offline **protobuf/framing dissector** (file / corpus / hex). |

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

## 2. Administrator rights

**No - and running as a *standard user* is usually the most informative way to use
it**, because that is exactly the low-privilege attack surface you want to measure.
Admin/SYSTEM only adds *visibility*; a service context is needed only to
*weaponize* impersonation.

| Operation | Standard user | Administrator | SYSTEM / service (`SeImpersonatePrivilege`) |
|---|---|---|---|
| Enumerate `\\.\pipe\` (`enum`) | yes | yes | yes |
| Read a pipe's SD / grade DACL | yes *if the DACL grants the caller `READ_CONTROL`* (most do; restrictive ones show **N/A**) | yes (reads more restrictive SDs) | yes |
| Resolve **server image path** (`audit`, HTML) | partial - denied for processes owned by other users / SYSTEM → `(OpenProcess denied)` | yes (resolves most) | yes |
| Connect + `send`/`fuzz` a pipe | yes *if the DACL grants connect* (e.g. `Everyone:FA`, NULL DACL) | yes | yes |
| `capture` (create competing instance) | yes *unless server used `FILE_FLAG_FIRST_PIPE_INSTANCE`* | yes | yes |
| `squat` (claim a free name) | yes | yes | yes |
| **Weaponize** `squat --impersonate` → act as SYSTEM | no (token obtained but not usable) | no | yes (requires `SeImpersonatePrivilege`) |
| `decode` / `craft` (offline) | yes (no connection at all) | yes | yes |

**Recommendation:** run `enum`/`audit` first as your normal account to see the real
low-priv exposure, then optionally re-run elevated to fill in server image paths
and any SDs you couldn't read.

---

## 3. Command synopsis

```
fifofox enum    [--all] [--squat] [--html <file>]
fifofox listeners [--all]                          (loopback TCP IPC endpoints + owner)
fifofox audit   <pipe> [--html <file>]
fifofox capture <pipe> --authorized [--count N]
fifofox fuzz    <pipe> --authorized [options]
fifofox squat   <pipe> --authorized [--impersonate] [--timeout <sec>]
fifofox send    <pipe> --authorized (--str|--json <txt>|--data <f>|--kiros ...) [--frame F] [--nl] [--read ms]
fifofox decode  <file> [--corpus]   |   decode --hex <hexbytes>
fifofox craft   --path <topic> [--type <url> --arg <s>] [--out <f>]
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
| `--no-decode` (alias `--raw`) | Print raw hex only; skip the protobuf/framing dissection that `send`, `capture`, and `decode` apply by default. |
| `--no-service` | In `audit`, skip the owning-service / unquoted-path / directory-ACL escalation-surface check. |

Operational logging goes to **stderr** on purpose, so `fifofox enum --html r.html -v`
won't pollute the report or any piped stdout. Console color is auto-enabled on an
interactive VT console and **auto-disabled when stdout is redirected/piped** or when
`NO_COLOR` is set, so a redirected report/log never contains escape codes.

---

## 4. Commands in detail

### 4.1 `enum` - grade every pipe on the box

Walks `\\.\pipe\*`, reads each pipe's security descriptor, converts it to SDDL, and
grades the DACL (see [5](#5-severity-model)). By default prints only **flagged**
pipes (WARN/DANGER) plus a summary. Each row also shows the pipe's **owner** (from
its security descriptor, e.g. `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, or a
user SID), so a privileged-owned pipe with a permissive DACL stands out at a glance.

| Option | Meaning |
|---|---|
| `--all` | Also list **OK** pipes and **unreadable** ones (`N/A`), not just flagged. |
| `--squat` | **Active probe.** For each pipe, also attempt a `FILE_FLAG_FIRST_PIPE_INSTANCE` create; if it succeeds the name has no owner → flagged **DANGER (squattable)**. |
| `--html <file>` | Additionally write a standalone HTML security-overview report. |

```bat
fifofox enum                          :: just the flagged pipes + summary
fifofox enum --all                    :: everything, including OK / N/A
fifofox enum --all --html report.html :: full report to console + HTML
```

> **Behaviour note:** `enum` opens a **client handle** (`READ_CONTROL`) to each pipe
> to read its SD. On some servers this registers as a momentary connection. It is
> read-only, but be aware of it on sensitive hosts.

### 4.1b `listeners` - loopback TCP IPC endpoints

Named pipes are one local-IPC transport; **loopback TCP** is the other half (auto-updaters,
agents, "Elevator" helpers). Lists every `127.0.0.1`/`::1` (and wildcard `0.0.0.0`/`::`)
**TCP listener** with its owning process and **account/privilege** - because *any* local
user can connect to a loopback listener (TCP has no DACL), so the risk is the **owner's
privilege**. A **SYSTEM-owned loopback listener is the auto-updater IPC attack surface**.

| Option | Meaning |
|---|---|
| (none) | loopback + wildcard listeners only |
| `--all` | include listeners on every interface |

Owners are resolved via the **service account** first (so SYSTEM services resolve even
when `OpenProcess` is denied), else the process token. Grading: **DANGER** = SYSTEM/
LocalSystem owner; **WARN** = LocalService/NetworkService; **ok** = normal user.

```
fifofox listeners            :: loopback/wildcard endpoints + owner
fifofox listeners --all      :: every interface
```
```
[DANGER] 127.0.0.1:4767   (loopback)   PID 5092  PanGPS.exe       owner: LocalSystem [svc:PanGPS]
[  ok  ] 127.0.0.1:19010  (loopback)   PID 4270  logioptionsplus_agent.exe  owner: LAB17\you
```
Then probe an interesting one's protocol with a client / `decode` (it speaks JSON, protobuf,
DCE/RPC, …). TCP listeners have no HTML report yet.

### 4.2 `audit` - deep single-pipe report

Full report for one pipe: `GetNamedPipeInfo` geometry (type, buffer sizes, max
instances), server + client PID and image path, the pipe **owner** (from its SD), a
best-effort live **server integrity level** (Low/Medium/High/System, or "denied" =
higher-IL than you), SDDL, ACE-by-ACE grade, and a **live squattability test**.

| Option | Meaning |
|---|---|
| `--html <file>` | Write a single-row HTML report including geometry + squattability. |
| `--peek` | Passively read any unsolicited server greeting and auto-detect its format (protobuf/DCE-RPC/.NET/JSON/…). Request/response servers that volunteer nothing are reported as such. Opt-in (it connects + reads). |

```bat
fifofox audit cowork-vm-service
fifofox audit cowork-vm-service --html pipe.html
fifofox audit \\.\pipe\lsass --debug
```

A **squattable** result escalates the overall verdict to DANGER independently of the
DACL grade. Because the squat test doesn't need the pipe to currently exist, `audit`
runs it even for a **stopped/not-yet-started service**, the most useful case:
can the name be pre-created and squatted before the legitimate server claims it?

**Escalation surface behind the pipe.** `audit` then maps the pipe to its **owning
service** (via the SCM, which a standard user can read even when `OpenProcess` on a
SYSTEM service is denied) and assesses the classic local-EoP surface *behind* the
endpoint. Disable with `--no-service`:

- **Service + account** - service name, display name, and the account it runs as
  (flagged when **privileged**, i.e. `LocalSystem`).
- **Unquoted ImagePath** - flags an unquoted path with spaces **and** checks whether
  any intercept directory is low-priv writable. Inherit-only ACEs are correctly
  ignored, so `C:\`-rooted unquoted paths are reported **"not exploitable"** rather
  than crying wolf - exactly the distinction that separates a real finding from noise.
- **Binary directory / file** - whether a low-priv SID can plant a side-load DLL in
  the service's program directory or replace the executable; **DANGER** when the
  service is privileged, **WARN** (cross-user code-integrity) otherwise.
- **Trust-predicate linter** (heuristic, static) - greps the service binary (ASCII +
  UTF-16) for the recurring auto-updater weaknesses: `CryptQueryObject`/cert-chain APIs
  **without** `WinVerifyTrust` (CWE-347, signature existence != validity), hardcoded
  `CN=` signer strings (substring-match risk), a temp path + `CreateProcessAsUser`
  (copy->verify->exec TOCTOU), and toggleable `*signature*`/`check_msi_digest` config
  flags. Notes only - it flags leads to confirm, it does not change the verdict grade.

```text
  --- owning service / escalation surface ---
  service       OptionsPlusUpdaterService  -  Logi Options+
  account       LocalSystem  (privileged)
  imagepath     "C:\Program Files\LogiOptionsPlus\logioptionsplus_updater.exe" --run-as-service
  unquoted      no (path is quoted)
  binary dir    [C:\Program Files\LogiOptionsPlus] : not low-priv writable
  binary file   [...\logioptionsplus_updater.exe] : not low-priv writable
  svc verdict   OK - no low-priv write into the service's executable surface
```

For a `svchost`-hosted (shared) service the per-service binary can't be attributed
from the PID alone, so the unquoted/dir checks are skipped with a note. If the pipe
owner isn't a service at all, `audit` still reports the owning image's directory ACL
(a DLL-hijack surface for whoever runs it).

### 4.3 `capture` - instance-interception relay (MITM)

Creates a **competing instance** of the target pipe name, waits for a client to land
on it, dials the real server, and relays bytes both ways, logging every chunk and
writing client→server frames to a **corpus** for `fuzz`. With decoding enabled
(default), each direction is also dissected into the transcript.

| Option | Meaning |
|---|---|
| `--authorized` | **Required.** Affirms you have permission (else exit 2). |
| `--count N` | Number of client sessions to relay before exiting (default **1**). |

```bat
fifofox capture cowork-vm-service --authorized --count 5 -v
```

**Requires** that the real server did **not** use `FILE_FLAG_FIRST_PIPE_INSTANCE`
(check with `audit` first). If it did, `CreateNamedPipe` returns `ACCESS_DENIED` and
capture reports it as impossible, which is itself the security finding. Interception
is **opportunistic** and **EDR-visible**.

### 4.4 `fuzz` - frame fuzzer with crash detection

Connects as a client and sends mutated frames, reads responses non-blocking, and
detects when the pipe disappears (probable server crash), dumping a repro.

| Option | Default | Meaning |
|---|---|---|
| `--authorized` | - | **Required.** |
| `--frame <kind>` | `raw` | Wire framing: `raw`, `len16le`, `len16be`, `len32le`, `len32be`, `cmd`. |
| `--cmd <prefix>` | `"3 "` | Command prefix when `--frame cmd` (Timbuktu-style command messages). |
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

With a corpus, mutation is **format-aware**: recognised frames (kiros/protobuf, DCE/RPC)
are kept structurally valid and only their inner fields/stub are fuzzed, so the target
parses past the framing into the handler; the rest of the time, byte-level strategies are
cycled (corpus-havoc dominates when a corpus is loaded): `random`,
`long-A` overflow walls, `format-string`, `path-traversal`, **`length-lie`** (tiny
body, declared length `0x7FFFFFFF`), `0x00/0xFF` boundaries, `zero/short`, and
`corpus-havoc` (bit-flips/truncation/padding of real frames). On a crash
(`WaitNamedPipe` → `ERROR_FILE_NOT_FOUND`) the offending bytes are saved to
`crash_<ts>_<iter>.bin` and the run stops.

### 4.5 `squat` - squat + impersonation PoC (dual-use, gated)

Claims the pipe name with `FILE_FLAG_FIRST_PIPE_INSTANCE`, waits for a client, and
optionally impersonates it to show the squat→impersonation risk.

| Option | Meaning |
|---|---|
| `--authorized` | **Required.** |
| `--impersonate` | After a client connects, call `ImpersonateNamedPipeClient()` and print the impersonated user + integrity level. |
| `--timeout <sec>` | How long to wait for a client (default `30`). |

```bat
fifofox squat cowork-vm-service --authorized --impersonate --timeout 60
```

Obtaining a SYSTEM/High token here is only *exploitable* if your process holds
`SeImpersonatePrivilege` (service accounts, not standard users). **Noisy by design** -
the exact behavior the Elastic impersonation rule flags.

### 4.6 `send` - precise message delivery / framing probe

Connects as a client, sends **one** message, and prints + **decodes** the reply. Use
it to **reverse a pipe's wire framing** (send a benign message in each framing, see
which one replies), to **deliver a crafted trigger**, or - with `--kiros` - to build
and send a Logitech protobuf request in one step.

| Option | Meaning |
|---|---|
| `--authorized` | **Required.** |
| `--str <text>` / `--json <text>` | Message body = literal text (`--json` is a semantic hint). |
| `--data <file>` | Message body = raw file bytes (e.g. a captured/crafted frame). |
| `--kiros` | Build a kiros protobuf frame from flags instead of a body (see [4.8](#48-craft--build-a-logitech-kiros-request-frame)). |
| `--path` / `--type` / `--arg` / `--argraw` | (with `--kiros`) the route, `Any` type_url, and typed request field. |
| `--frame <kind>` | Length framing for `--str`/`--json`/`--data`: `raw`, `len16le/be`, `len32le/be` (default `raw`). |
| `--nl` | Append a trailing newline (line-delimited protocols). |
| `--read <ms>` | How long to wait for a reply (default `1500`). |

```bat
:: probe framing with a benign read-only topic
fifofox send some-service --authorized --json "{\"op\":\"ping\"}" --frame len32le

:: deliver a captured/crafted trigger
fifofox send logitech_kiros_updater --authorized --data trigger.bin

:: craft + send a kiros message in one step (reply auto-decoded)
fifofox send logitech_kiros_agent-<id> --authorized --kiros --path /updates/depot/info ^
  --type type.googleapis.com/logi.protocol.updates.Depot.Info --arg logioptionsplus
```

A successful **write with no reply** still confirms low-priv **reachability + write**
to the server; silence usually means the framing/schema is wrong, or the server
authenticates the caller before replying. Replies are auto-dissected; add `--raw` for
hex only.

### 4.7 `decode` - offline protocol dissector

Turns captured bytes into a readable field tree **without connecting to anything** -
the same decoder `send` and `capture` apply inline. Protobuf is just one format; IPC
payloads come in many, so `decode` **auto-detects the payload format** and routes to
the matching dissector:

| Detected format | What it shows |
|---|---|
| **protobuf / kiros** | the `u32be(8)["protobuf"]` magic frame (incl. an outer `u32le/u32be` length wrapper), bare length-prefixed and raw protobuf; field tree (`varint/i32/i64/str/bytes/msg`) recursing into nested messages and `google.protobuf.Any`. |
| **DCE/RPC (MSRPC)** | PDU header (version, packet type, endianness, frag length, call id) + the **bound interface UUID** (resolved to `lsarpc`/`samr`/`svcctl`/`spoolss`/`efsrpc`/…) and the **request opnum**. |
| **.NET serialization** | BinaryFormatter / NetDataContractSerializer / NMF streams, **flagged as an unsafe-deserialization candidate** (feed to `ysoserial.net`). |
| **JSON / XML / text** | pretty-printed as text. |
| **ASN.1 / DER** | TLV skeleton (SEQUENCE/SET/INTEGER/OID/…) walk. |
| **binary** | hex+ASCII fallback. |

| Option | Meaning |
|---|---|
| `<file>` | A single captured frame. |
| `--corpus` | Treat `<file>` as a `capture` corpus (`[u32le len][frame]` records) and dissect each. |
| `--hex <bytes>` | Dissect an inline hex string instead of a file (whitespace/punctuation ignored). |
| `--format <f>` | Force the dissector (`auto`/`protobuf`/`dcerpc`/`dotnet`/`json`/`xml`/`asn1`/`text`/`hex`) when auto-detect guesses wrong. |

```bat
fifofox decode trigger.bin
fifofox decode fifofox_corpus_1730000000.bin --corpus
fifofox decode --hex "00000008 70726f746f627566 0000000d 0a..."
```

```text
[*] decoding trigger.bin (129 bytes)
  [frame] magic="protobuf"  payloadlen=113
    f1: str[4] "9999"
    f2: varint 1
    f3: str[19] "/updates/depot/info"
    f4: str[7] "backend"
    f6: msg[73] {
      f1: str[52] "type.googleapis.com/logi.protocol.updates.Depot.Info"
      f2: msg[17] { f1: str[15] "logioptionsplus" }
    }
```

So `f3` is the route/topic, `f6` is the typed `Any` request, and the inner `f1` is
the argument, exactly the fields you set to interact with a service.

### 4.8 `craft` - build a Logitech "kiros" request frame

The inverse of `decode`: build a valid kiros request frame from flags, so you can
talk to the service without hand-assembling bytes. `craft` writes/previews the frame;
`send --kiros` builds and delivers it in one step.

```
u32be(8)["protobuf"] u32be(len) [ Message{ f1 msg_id, f2 verb, f3 path, f4 origin, f6 Any{type_url,value} } ]
```

| Option | Meaning |
|---|---|
| `--path <topic>` | **Required.** Route, e.g. `/updates/depot/info`. |
| `--type <url>` | `google.protobuf.Any` type_url (the typed request message). |
| `--arg <text>` | The request message's first (f1) string field, e.g. a depot name. |
| `--argraw <hex>` | Raw bytes for the `Any` value instead of `--arg`. |
| `--verb <n>` | Message verb (default `1` = request). |
| `--reqid <s>` / `--origin <s>` | Envelope msg_id (default `9999`) / origin (default `backend`). |
| `--out <file>` | Write the frame to a file (else hex preview + self-decode only). |

```bat
:: build a depot-info query and save it for replay / relaying
fifofox craft --path /updates/depot/info ^
  --type type.googleapis.com/logi.protocol.updates.Depot.Info --arg logioptionsplus ^
  --out q.bin

:: then deliver it to a same-user pipe...
fifofox send logitech_kiros_agent-<id> --authorized --data q.bin --frame raw
```

`craft` always self-decodes what it built, so you can verify the frame before sending
it. The kiros decode/craft features are protocol-specific helpers; the rest of
FIFOFox is protocol-agnostic.

---

## 5. Severity model

A pipe's DACL is graded by what **low-privileged SIDs** are granted. Low-priv SIDs:
`Everyone (S-1-1-0)`, `Authenticated Users (S-1-5-11)`, `Users (S-1-5-32-545)`,
`Anonymous (S-1-5-7)`, `Guests (S-1-5-32-546)`, `Power Users (S-1-5-32-547)`,
`INTERACTIVE (S-1-5-4)`.

| Grade | Badge | Trigger |
|---|---|---|
| 2 | **DANGER** | Low-priv SID holds `WRITE_DAC` / `WRITE_OWNER` / `GENERIC_ALL` (object **takeover**), **or** a **NULL DACL** (everyone full), **or** the name is **squattable**. |
| 1 | **WARN** | Low-priv SID can write pipe **data** (`FILE_WRITE_DATA` / `APPEND_DATA` / `GENERIC_WRITE` / `DELETE`). |
| 0 | **OK** | No low-priv write right. |
| - | **N/A** | SD not readable as the current user. |

> **Important interpretation:** `Everyone:Full` ("connect + read/write") is *common by
> design* for IPC pipes. The **serious** flags are `WRITE_DAC` / `WRITE_OWNER` /
> `GENERIC_ALL` to a low-priv SID, or a NULL DACL. A permissive DACL only governs
> **who may connect** - real privilege impact depends on the server's **in-band
> authorization** (does it authenticate the caller after accept?), which this tool
> does not evaluate. See [8](#8-limitations-and-caveats).

---

## 6. HTML reports

`enum --html` and `audit --html` emit a **standalone, self-contained** HTML page
(embedded CSS, dark theme, no external assets):

- Header with tool version, **hostname**, and generation timestamp.
- Summary cards: total pipes, **Danger / Warn / OK** counts - **click a card to filter**
  the table to that severity (click *Pipes* to show all). Pure CSS (hidden radio +
  sibling combinator); no JavaScript, still a single self-contained file.
- A table per pipe: severity badge, pipe name, server PID, **owner**, server image path, findings
  (flagged ACEs; for `audit` also geometry + squattability), and the full **SDDL**.
- A footer severity key.

The table uses a fixed layout with defined column widths; long values (image paths,
SDDL, long pipe names) wrap, and the SDDL/image cells become independently scrollable,
so one long value can't stretch the whole report. All dynamic text is HTML-escaped,
so SDDL/paths/names cannot break the markup. Safe to share as a report.

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
| `fifofox_capture_<ts>.log` | `capture` | `C2S`/`S2C` hexdump transcript (+ decoded field trees) of relayed traffic. |
| `fifofox_corpus_<ts>.bin` | `capture` | Client→server frames as `[u32 LE length][bytes]` records - feed to `fuzz --corpus` or `decode --corpus`. |
| `<file>` | `craft --out` | A single crafted kiros frame (replay with `send --data`). |
| `<file>` | `--html` | HTML report (see [6](#6-html-reports)). |

`<ts>` is a Unix timestamp; files land in the current working directory.

---

## 8. Limitations and caveats

- **In-band authorization is not assessed.** The grade reflects who can *connect* and
  *write*, not whether the server authenticates callers afterward. A WARN/DANGER pipe
  may still be safe if the server validates the client; an OK pipe may be exploitable
  via protocol logic.
- **TOCTOU / PID-reuse is not auto-detected.** A content fuzzer can't find a
  check-then-use race in the auth layer; confirming that needs static RE plus a
  dedicated race harness with a protocol-specific oracle.
- **Grader evaluates ALLOW ACEs only** - it doesn't subtract DENY ACEs, so the grade
  is a fast heuristic, not a full `AccessCheck`.
- **Memory-safe targets.** Against a Go/Rust/.NET server, the `long-A` / `length-lie`
  strategies are unlikely to yield classic memory corruption; expect **DoS (panic)**
  and **OOM** signals rather than control-flow hijack.
- **`enum` connects to each pipe** to read its SD (see 4.1 note).
- **ASCII names.** Uses ANSI APIs; pipe names with non-ASCII characters may be mangled.
- **`capture` is opportunistic and EDR-visible** (4.3).
- **`decode` / `craft` are offline and safe** - no connection, no side effects.

---

## 9. Exit codes

| Code | Meaning |
|---|---|
| `0` | Success (or `help`/`version`). |
| `1` | Usage error / missing argument / operation failure. |
| `2` | A gated mode (`fuzz`/`capture`/`squat`/`send`) was run without `--authorized`. |

---

## 10. Typical workflow

```bat
:: 1) Survey the whole box (as a standard user) and get a report
fifofox enum --all --html overview.html

:: 2) Drill into an interesting pipe
fifofox audit logitech_kiros_updater --html pipe.html

:: 3) Learn the protocol: dissect a captured/crafted frame
fifofox decode trigger.bin

:: 4) Talk to the service: craft a request, send it, read the decoded reply
fifofox send logitech_kiros_agent-<id> --authorized --kiros --path /updates/depot/info ^
  --type type.googleapis.com/logi.protocol.updates.Depot.Info --arg logioptionsplus

:: 5) If not first-instance protected, capture live traffic into a corpus
fifofox capture some-service --authorized --count 5 -v

:: 6) Structure-aware fuzz from the corpus, watching for crashes
fifofox fuzz some-service --authorized --corpus fifofox_corpus_<ts>.bin -v

:: 7) (Optional, gated) demonstrate squat/impersonation feasibility
fifofox squat some-service --authorized --impersonate
```

---

## 11. Changelog

**v1.2.3 (ilegnisi)** - current

- **New `listeners` mode - loopback TCP IPC surface.** Enumerates `127.0.0.1`/`::1`
  (and wildcard) TCP listeners with owning process + **account/privilege**, flagging
  **SYSTEM-owned loopback listeners** (the auto-updater/agent attack surface). Owner is
  resolved via the service account, so SYSTEM services resolve even when `OpenProcess`
  is denied. Extends FIFOFox from a named-pipe tool toward a **local-IPC** tool.
- **Trust-predicate linter in `audit`.** Static heuristics on the owning service binary
  for the classic updater signature-verification weaknesses (`CryptQueryObject` without
  `WinVerifyTrust` = CWE-347, `CN=` substring signer checks, temp+`CreateProcessAsUser`
  TOCTOU, toggleable signature config flags). Reports leads; doesn't change the grade.
- **Multi-format payload dissection.** `decode`/`send`/`capture` now **auto-detect the
  payload format** instead of assuming protobuf: protobuf/kiros, **DCE/RPC** (header +
  bound interface UUID + opnum), **.NET serialization** (flagged as an unsafe-
  deserialization candidate), JSON, XML, ASN.1/DER, text, or hex. `--format <f>` forces it.
- **Format-aware fuzzing.** `fuzz --corpus` now keeps recognised frames **structurally
  valid** while mutating the inner content (protobuf field values incl. boundary varints
  and overflow strings; DCE/RPC stub with a fixed-up frag length), so the target parses
  *past* the framing into the handler instead of bouncing off the length check.
- **`audit --peek`.** Optional passive read of any unsolicited server greeting, then
  format auto-detect - tells you what protocol a pipe speaks without a full capture
  (request/response servers that volunteer nothing are reported as such).
- **Clickable severity filter in the HTML report.** The Danger/Warn/OK summary cards
  are now clickable and filter the table to that severity (Pipes = show all), pure
  CSS, no JavaScript, still one self-contained file.
- **Owner + integrity surfaced.** `enum` and `audit` now show each pipe's **owner**
  (from its security descriptor - readable even when the server process can't be
  opened), so a `SYSTEM`/`Administrators`-owned pipe is obvious at a glance; `audit`
  adds a best-effort live **server integrity level** (`Low`/`Medium`/`High`/`System`,
  or "denied" = the server is higher-IL than you).
- **`audit` now maps the pipe to its owning service** and assesses the escalation
  surface behind it: service account, **unquoted ImagePath** (with a writable-
  intercept-dir check that ignores inherit-only ACEs, so `C:\` paths aren't false
  positives), and a low-priv-writable **binary directory/file** (DLL-plant / replace)
  - DANGER when the service is privileged. Read-only; disable with `--no-service`.
- **New `decode` mode** - offline protobuf/framing dissector: the `["protobuf"]` magic
  frame, an outer `u32le`/`u32be` length wrapper (server replies use this), bare
  length-prefixed protobuf, and raw protobuf; recurses nested messages and
  `google.protobuf.Any`. Inputs: a frame file, a `--corpus`, or inline `--hex`.
- **New `craft` mode + `send --kiros`** - build a Logitech *kiros* request frame from
  flags (`--path` / `--type` / `--arg` / `--argraw` / `--verb` / `--reqid` /
  `--origin` / `--out`); `send --kiros` builds and delivers in one step.
- **Auto-decode of traffic** - `send` dissects the reply and `capture` dissects **both**
  directions into its transcript; `--no-decode` (alias `--raw`) prints hex only.
- **New `send` mode** - precise single-message delivery + reply capture
  (`--str`/`--json`/`--data`, `--frame`, `--nl`, `--read`); the targeted counterpart
  to `fuzz` for framing recovery and crafted-trigger delivery.
- `squat` no longer blocks forever: overlapped `ConnectNamedPipe` with a real,
  configurable `--timeout` (default 30s) and an accurate wait message.
- `--no-banner` flag; HTML report footer carries the Zero Science Lab attribution.
- `--verbose`/`-v` and `--debug` operational logging (to stderr).
- HTML security-overview report for `enum` **and** `audit` (`--html`).
- `version` / `help` subcommands; version banner in usage.
- Structure-aware fuzzing via captured corpus (`capture` → `fuzz --corpus`).
- **Console ANSI color** (auto / `--color` / `--no-color`, honors `NO_COLOR`):
  severity-coded findings, distinct highlight for NULL DACL, color legend.
- **`audit` reformatted** as an aligned attribute table with the interesting rows
  (grade, squattable, SDDL) highlighted.
- **HTML readability**: fixed table layout, `<colgroup>` widths, wrapping + scrollable
  SDDL/image cells, non-wrapping severity badges.
- **Squattability escalates to DANGER**: `audit` folds squattability into the overall
  verdict and squat-tests even names that aren't currently open (stopped-service
  pre-squat); new `enum --squat` active probe across the whole box.
- Hardening: fuzz startup OOM cleanup; right-sized HTML-escape buffers; documented
  DENY-ACE grading limitation.

---

## 12. Credits

**FIFOFox** - Powered by Silly Security Inc. - https://sillysec.com
