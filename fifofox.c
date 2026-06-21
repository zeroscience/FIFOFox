/*
 * fifofox.c  -  Windows named-pipe security auditor and fuzzer
 * ----------------------------------------------------------------------------
 * FIFOFox is a single-file, zero-dependency Windows named-pipe security
 * toolkit. One small .exe takes you from recon (enumerate and grade every
 * pipe's DACL on the box) through deep auditing of a single endpoint, live
 * interception, and fuzzing, all the way to protocol reverse-engineering
 * (craft / send / decode of length-prefixed protobuf IPC). It also maps the
 * loopback TCP IPC surface - the "other half" of local IPC. Standard-user tool
 * first: the most interesting view of a pipe's attack surface is the one a
 * low-privileged process sees.
 *
 * Modes
 *   enum                         List every \\.\pipe\ object, decode its DACL
 *                                to SDDL, and GRADE it (flags low-priv writers
 *                                / object-takeover ACEs / NULL DACLs); shows the
 *                                pipe owner. Optional --html report.
 *   listeners                    Enumerate loopback / wildcard TCP IPC endpoints
 *                                with owning process, account, and privilege -
 *                                the other half of local IPC (a socket has no
 *                                DACL, so any local user can connect).
 *   audit  <pipe>                Deep single-pipe report: GetNamedPipeInfo
 *                                flags, server/client PID + image path, owner,
 *                                SDDL, ACE-by-ACE grading, a live squattability
 *                                test (FILE_FLAG_FIRST_PIPE_INSTANCE), the
 *                                owning-service escalation surface (unquoted
 *                                path / writable dir / privileged account) and
 *                                a trust-predicate linter (CWE-347 leads).
 *   capture <pipe> --authorized  Interception (MITM) relay: stand up a competing
 *                                instance, relay both directions, log the
 *                                traffic, and bank a fuzz corpus.
 *   fuzz   <pipe> --authorized   Connect as a client and send mutated frames
 *                                (raw / length-prefixed / command-prefixed),
 *                                format-aware from a corpus, with liveness /
 *                                crash detection and repro logs.
 *   squat  <pipe> --authorized   Defensive PoC: claim the pipe name first and
 *               [--impersonate]   optionally ImpersonateNamedPipeClient() to
 *                                demonstrate the squat->impersonation risk.
 *   send   <pipe> --authorized   Deliver one message (raw / framed, or a crafted
 *                                "kiros" protobuf frame) and decode the reply.
 *   craft                        Build a Logitech "kiros" protobuf request frame
 *                                from flags (offline; no connection made).
 *   decode <file>                Offline multi-format dissector (protobuf / kiros
 *                                / DCE-RPC / .NET / JSON / XML / ASN.1) over a
 *                                file, a --corpus dir, or raw --hex bytes.
 *
 * <pipe> may be a bare name ("cowork-vm-service") or a full "\\.\pipe\name".
 *
 * Build (MSVC):   cl /W3 /O2 /D_CRT_SECURE_NO_WARNINGS fifofox.c
 * Build (MinGW):  gcc -O2 -Wall -o fifofox.exe fifofox.c -ladvapi32 -liphlpapi
 *
 * Does NOT require administrator rights: enum / listeners / audit / fuzz /
 * capture / squat / send all run as a standard user against endpoints the
 * caller can already reach (which is exactly the low-priv attack surface you
 * want to assess); craft / decode are fully offline. Admin only adds
 * visibility (resolving other-user / SYSTEM server image paths, reading
 * restrictive SDs); a service context with SeImpersonatePrivilege is needed
 * only to *weaponize* squat+impersonate into SYSTEM. See fifofox-readme-current.md.
 *
 * Dependencies: advapi32 (SDDL/ACL/SID/token), kernel32 (pipe APIs),
 * iphlpapi (TCP table for listeners). No others; linked via #pragma under MSVC.
 *
 * lqwrm (c) 2026
 * ----------------------------------------------------------------------------
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>////
#include <tlhelp32.h>///
#include <stdlib.h>/////
#include <string.h>/////
#include <stdint.h>/////
#include <aclapi.h>/////
#include <winsvc.h>/////
#include <stdarg.h>/////
#include <stdio.h>//////
#include <sddl.h>///////
#include <time.h>///////

#define FIFOFOX_VERSION "1.2.3 (ilegnisi)"

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif

static void winerr(const char *ctx, DWORD e)
{
    char *msg = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, e, 0, (LPSTR)&msg, 0, NULL);
    fprintf(stderr, "  [!] %s failed (err %lu): %s", ctx, (unsigned long)e,
            msg ? msg : "(no message)\n");
    if (msg) LocalFree(msg);
}

static int g_verbose = 0;
static int g_debug   = 0;
static int g_decode  = 1;
static int g_no_service = 0;
static int g_peek = 0;
static void dissect_auto(FILE *f, const unsigned char *b, size_t n);

static void vrb(const char *fmt, ...)
{
    va_list ap;
    if (!g_verbose && !g_debug) return;
    va_start(ap, fmt);
    fprintf(stderr, "[*] ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static void dbg(const char *fmt, ...)
{
    va_list ap;
    if (!g_debug) return;
    va_start(ap, fmt);
    fprintf(stderr, "[dbg] ");
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif
static int g_color = 0;
#define CC(x) (g_color ? (x) : "")
#define A_RESET    "\x1b[0m"
#define A_BOLD     "\x1b[1m"
#define A_MAG      "\x1b[35m"
#define A_RED      "\x1b[91m"
#define A_YEL      "\x1b[93m"
#define A_GRN      "\x1b[92m"
#define A_CYN      "\x1b[96m"
#define A_GRY      "\x1b[90m"
#define A_NULLDACL "\x1b[1;97;41m"

static void enable_color(int want)
{
    HANDLE ho = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (want < 0) { g_color = 0; return; }
    if (want == 0) {
        if (getenv("NO_COLOR")) { g_color = 0; return; }
        if (GetFileType(ho) != FILE_TYPE_CHAR) { g_color = 0; return; }
    }
    if (GetConsoleMode(ho, &mode) &&
        SetConsoleMode(ho, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
        g_color = 1;
    else
        g_color = (want == 1);
}

static const char *sev_ansi(int grade)
{
    if (grade >= 2) return A_RED;
    if (grade == 1) return A_YEL;
    if (grade == 0) return A_GRN;
    return A_GRY;
}

static void print_findings_colored(const char *find_buf)
{
    const char *p = find_buf, *nl;
    char line[2048];
    while (*p) {
        size_t len;
        nl = strchr(p, '\n');
        len = nl ? (size_t)(nl - p) : strlen(p);
        if (len >= sizeof(line)) len = sizeof(line) - 1;
        memcpy(line, p, len);
        line[len] = 0;
        if (strstr(line, "NULL DACL"))
            printf("%s%s%s\n", CC(A_NULLDACL), line, CC(A_RESET));
        else if (strstr(line, "[DANGER]"))
            printf("%s%s%s\n", CC(A_RED), line, CC(A_RESET));
        else if (strstr(line, "[WARN"))
            printf("%s%s%s\n", CC(A_YEL), line, CC(A_RESET));
        else if (strstr(line, "[ ok ]"))
            printf("%s%s%s\n", CC(A_GRY), line, CC(A_RESET));
        else
            printf("%s\n", line);
        if (!nl) break;
        p = nl + 1;
    }
}

static void print_legend(void)
{
    printf("  %sLegend:%s %sDANGER%s takeover/NULL-DACL  %sWARN%s low-priv writable  "
           "%sOK%s no low-priv write  %sN/A%s SD unreadable\n",
           CC(A_GRY), CC(A_RESET),
           CC(A_RED), CC(A_RESET), CC(A_YEL), CC(A_RESET),
           CC(A_GRN), CC(A_RESET), CC(A_GRY), CC(A_RESET));
}

static void appendf(char *buf, size_t cap, const char *fmt, ...)
{
    size_t used = strlen(buf);
    va_list ap;
    if (used + 1 >= cap) return;
    va_start(ap, fmt);
    vsnprintf(buf + used, cap - used, fmt, ap);
    va_end(ap);
}

struct sbuf { char *p; size_t len, cap; };
static void sb_init(struct sbuf *s) { s->cap = 8192; s->len = 0; s->p = (char *)malloc(s->cap); if (s->p) s->p[0] = 0; }
static void sb_add(struct sbuf *s, const char *str)
{
    size_t l = strlen(str);
    if (!s->p) return;
    if (s->len + l + 1 > s->cap) {
        while (s->len + l + 1 > s->cap) s->cap *= 2;
        s->p = (char *)realloc(s->p, s->cap);
        if (!s->p) return;
    }
    memcpy(s->p + s->len, str, l + 1);
    s->len += l;
}
static void sb_addf(struct sbuf *s, const char *fmt, ...)
{
    char tmp[35183];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    sb_add(s, tmp);
}
static void sb_free(struct sbuf *s) { if (s->p) free(s->p); s->p = NULL; }

static void html_escape(const char *src, char *dst, size_t cap)
{
    size_t o = 0;
    for (; *src && o + 8 < cap; ++src) {
        switch (*src) {
        case '&':  memcpy(dst + o, "&amp;", 5);  o += 5; break;
        case '<':  memcpy(dst + o, "&lt;", 4);   o += 4; break;
        case '>':  memcpy(dst + o, "&gt;", 4);   o += 4; break;
        case '"':  memcpy(dst + o, "&quot;", 6); o += 6; break;
        case '\n': memcpy(dst + o, "<br>", 4);   o += 4; break;
        case '\r': break;
        default:   dst[o++] = *src;
        }
    }
    dst[o] = 0;
}

static void make_pipe_path(const char *name, char *out, size_t outsz)
{
    if (name[0] == '\\' && name[1] == '\\')
        snprintf(out, outsz, "%s", name);
    else
        snprintf(out, outsz, "\\\\.\\pipe\\%s", name);
}

static const char *kLowPrivSids[] = {
    "S-1-1-0",        // Everyone
    "S-1-5-11",       // Authenticated Users
    "S-1-5-32-545",   // BUILTIN\Users
    "S-1-5-7",        // Anonymous
    "S-1-5-32-546",   // BUILTIN\Guests
    "S-1-5-32-547",   // Power Users
    "S-1-5-4",        // INTERACTIVE
    NULL
};

static int sid_is_lowpriv(const char *sidstr)
{
    int i;
    for (i = 0; kLowPrivSids[i]; ++i)
        if (_stricmp(sidstr, kLowPrivSids[i]) == 0) return 1;
    return 0;
}

static const char *sid_label(const char *sidstr)
{
    if (!_stricmp(sidstr, "S-1-1-0"))      return "Everyone";
    if (!_stricmp(sidstr, "S-1-5-11"))     return "Authenticated Users";
    if (!_stricmp(sidstr, "S-1-5-32-545")) return "BUILTIN\\Users";
    if (!_stricmp(sidstr, "S-1-5-32-544")) return "BUILTIN\\Administrators";
    if (!_stricmp(sidstr, "S-1-5-18"))     return "NT AUTHORITY\\SYSTEM";
    if (!_stricmp(sidstr, "S-1-5-19"))     return "LOCAL SERVICE";
    if (!_stricmp(sidstr, "S-1-5-20"))     return "NETWORK SERVICE";
    if (!_stricmp(sidstr, "S-1-5-7"))      return "Anonymous";
    if (!_stricmp(sidstr, "S-1-5-32-546")) return "BUILTIN\\Guests";
    if (!_stricmp(sidstr, "S-1-5-32-547")) return "Power Users";
    if (!_stricmp(sidstr, "S-1-5-4"))      return "INTERACTIVE";
    return "(other)";
}

struct mask_bit { DWORD bit; const char *name; int dangerous; int takeover; };

static const struct mask_bit kBits[] = {
    { 0x10000000, "GENERIC_ALL",        1, 1 },
    { 0x40000000, "GENERIC_WRITE",      1, 0 },
    { 0x000F0000, "FULL_STD_RIGHTS",    1, 1 },
    { 0x00080000, "WRITE_OWNER",        1, 1 },
    { 0x00040000, "WRITE_DAC",          1, 1 },
    { 0x00010000, "DELETE",             1, 0 },
    { 0x00000002, "FILE_WRITE_DATA",    1, 0 },
    { 0x00000004, "FILE_APPEND_DATA",   1, 0 },
    { 0x00000010, "FILE_WRITE_EA",      0, 0 },
    { 0x00000100, "FILE_WRITE_ATTRS",   0, 0 },
    { 0x00020000, "READ_CONTROL",       0, 0 },
    { 0x00000001, "FILE_READ_DATA",     0, 0 },
    { 0x00100000, "SYNCHRONIZE",        0, 0 },
    { 0, NULL, 0, 0 }
};

static int mask_is_dangerous(ACCESS_MASK m, int *takeover)
{
    int i, danger = 0;
    *takeover = 0;
    for (i = 0; kBits[i].name; ++i) {
        if ((m & kBits[i].bit) == kBits[i].bit) {
            if (kBits[i].dangerous) danger = 1;
            if (kBits[i].takeover)  *takeover = 1;
        }
    }
    return danger;
}

static void format_mask(ACCESS_MASK m, char *out, size_t cap)
{
    int i, first = 1;
    out[0] = 0;
    appendf(out, cap, "0x%08lX [", (unsigned long)m);
    for (i = 0; kBits[i].name; ++i) {
        if ((m & kBits[i].bit) == kBits[i].bit && kBits[i].bit != 0x000F0000) {
            appendf(out, cap, "%s%s", first ? "" : ",", kBits[i].name);
            first = 0;
        }
    }
    appendf(out, cap, "]");
}

static void print_mask(ACCESS_MASK m)
{
    char buf[512];
    format_mask(m, buf, sizeof(buf));
    fputs(buf, stdout);
}

static HANDLE open_pipe_read(const char *path)
{
    HANDLE h = CreateFileA(path, READ_CONTROL,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY) {
        dbg("  %s busy, WaitNamedPipe...\n", path);
        if (WaitNamedPipeA(path, 200))
            h = CreateFileA(path, READ_CONTROL,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_EXISTING, 0, NULL);
    }
    dbg("  open_pipe_read(%s) -> handle=%p\n", path, (void *)h);
    return h;
}

static int grade_pipe_security(HANDLE h, int include_ok,
                               char *sddl_out, size_t sddl_cap,
                               char *find_out, size_t find_cap,
                               char *owner_out, size_t owner_cap)
{
    PSECURITY_DESCRIPTOR psd = NULL;
    PACL dacl = NULL;
    DWORD r;
    int worst = 0;
    DWORD i;

    if (sddl_out && sddl_cap) sddl_out[0] = 0;
    if (find_out && find_cap) find_out[0] = 0;

    r = GetSecurityInfo(h, SE_KERNEL_OBJECT,
                        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                            DACL_SECURITY_INFORMATION,
                        NULL, NULL, &dacl, NULL, &psd);
    if (r != ERROR_SUCCESS) { dbg("GetSecurityInfo err %lu\n", (unsigned long)r); return -1; }

    if (sddl_out && sddl_cap) {
        char *sddl = NULL;
        ULONG sddllen = 0;
        if (ConvertSecurityDescriptorToStringSecurityDescriptorA(
                psd, SDDL_REVISION_1,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
                    DACL_SECURITY_INFORMATION,
                &sddl, &sddllen)) {
            snprintf(sddl_out, sddl_cap, "%s", sddl);
            LocalFree(sddl);
        }
    }

    if (owner_out && owner_cap) {
        PSID osid = NULL; BOOL odef = FALSE;
        owner_out[0] = 0;
        if (GetSecurityDescriptorOwner(psd, &osid, &odef) && osid) {
            char *os = NULL;
            if (ConvertSidToStringSidA(osid, &os)) {
                const char *lbl = sid_label(os);
                snprintf(owner_out, owner_cap, "%s", strcmp(lbl, "(other)") ? lbl : os);
                LocalFree(os);
            }
        }
        if (!owner_out[0]) snprintf(owner_out, owner_cap, "(unknown)");
    }

    if (dacl == NULL) {
        if (find_out) appendf(find_out, find_cap,
                              "  [DANGER] NULL DACL -> unrestricted access for everyone\n");
        LocalFree(psd);
        return 2;
    }

    for (i = 0; i < dacl->AceCount; ++i) {
        ACE_HEADER *hdr = NULL;
        if (!GetAce(dacl, i, (LPVOID *)&hdr)) continue;
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;

        {
            ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)hdr;
            PSID sid = (PSID)&ace->SidStart;
            char *sidstr = NULL;
            char maskbuf[512];
            int takeover = 0, danger;

            if (!ConvertSidToStringSidA(sid, &sidstr)) continue;
            danger = mask_is_dangerous(ace->Mask, &takeover);
            format_mask(ace->Mask, maskbuf, sizeof(maskbuf));

            if (sid_is_lowpriv(sidstr) && danger) {
                if (find_out)
                    appendf(find_out, find_cap, "  [%s] %s (%s) : %s%s\n",
                            takeover ? "DANGER" : "WARN ",
                            sid_label(sidstr), sidstr, maskbuf,
                            takeover ? "  <- can re-DAC/re-own the pipe object" : "");
                if (takeover) worst = 2;
                else if (worst < 1) worst = 1;
            } else if (include_ok && find_out) {
                appendf(find_out, find_cap, "  [ ok ] %s (%s) : %s\n",
                        sid_label(sidstr), sidstr, maskbuf);
            }
            LocalFree(sidstr);
        }
    }

    LocalFree(psd);
    return worst;
}

static void print_proc_image(DWORD pid, const char *which)
{
    HANDLE p;
    char buf[MAX_PATH];
    DWORD sz = MAX_PATH;
    if (pid == 0) { printf("  %s PID: (unknown)\n", which); return; }
    p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (p) {
        if (QueryFullProcessImageNameA(p, 0, buf, &sz))
            printf("  %s PID: %lu  (%s)\n", which, (unsigned long)pid, buf);
        else
            printf("  %s PID: %lu  (image: access denied)\n", which, (unsigned long)pid);
        CloseHandle(p);
    } else {
        printf("  %s PID: %lu  (OpenProcess denied)\n", which, (unsigned long)pid);
    }
}

static void print_token_identity(HANDLE token, const char *tag)
{
    DWORD len = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &len);
    if (len) {
        TOKEN_USER *tu = (TOKEN_USER *)malloc(len);
        if (tu && GetTokenInformation(token, TokenUser, tu, len, &len)) {
            char *s = NULL;
            char name[256], dom[256];
            DWORD nlen = 256, dlen = 256;
            SID_NAME_USE use;
            if (ConvertSidToStringSidA(tu->User.Sid, &s)) {
                if (LookupAccountSidA(NULL, tu->User.Sid, name, &nlen, dom, &dlen, &use))
                    printf("  %s user: %s\\%s (%s)\n", tag, dom, name, s);
                else
                    printf("  %s user SID: %s\n", tag, s);
                LocalFree(s);
            }
        }
        free(tu);
    }

    len = 0;
    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &len);
    if (len) {
        TOKEN_MANDATORY_LABEL *il = (TOKEN_MANDATORY_LABEL *)malloc(len);
        if (il && GetTokenInformation(token, TokenIntegrityLevel, il, len, &len)) {
            DWORD rid = *GetSidSubAuthority(
                il->Label.Sid,
                (DWORD)(*GetSidSubAuthorityCount(il->Label.Sid) - 1));
            const char *lvl = "?";
            if (rid >= 0x4000)      lvl = "SYSTEM";
            else if (rid >= 0x3000) lvl = "High";
            else if (rid >= 0x2000) lvl = "Medium";
            else if (rid >= 0x1000) lvl = "Low";
            else                    lvl = "Untrusted";
            printf("  %s integrity: %s (0x%lX)\n", tag, lvl, (unsigned long)rid);
        }
        free(il);
    }
}

static void server_integrity(DWORD pid, char *out, size_t cap)
{
    HANDLE p, tok;
    snprintf(out, cap, "(unavailable)");
    if (!pid) return;
    p = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!p) { snprintf(out, cap, "(OpenProcess denied - higher IL than us)"); return; }
    if (OpenProcessToken(p, TOKEN_QUERY, &tok)) {
        DWORD len = 0;
        GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &len);
        if (len) {
            TOKEN_MANDATORY_LABEL *t = (TOKEN_MANDATORY_LABEL *)malloc(len);
            if (t && GetTokenInformation(tok, TokenIntegrityLevel, t, len, &len)) {
                DWORD c   = *GetSidSubAuthorityCount(t->Label.Sid);
                DWORD rid = *GetSidSubAuthority(t->Label.Sid, c - 1);
                const char *lv = rid >= 0x4000 ? "Protected" : rid >= 0x3000 ? "System" :
                                 rid >= 0x2000 ? "High" : rid >= 0x1000 ? "Medium" : "Low";
                snprintf(out, cap, "%s (rid 0x%lx)", lv, (unsigned long)rid);
            }
            free(t);
        }
        CloseHandle(tok);
    } else snprintf(out, cap, "(token read denied)");
    CloseHandle(p);
}

static void write_html_report(const char *path, struct sbuf *rows,
                              int total, int danger, int warn, int okc, int shown)
{
    FILE *f = fopen(path, "w");
    char host[256] = "unknown";
    DWORD hlen = sizeof(host);
    char when[64] = "";
    time_t t = time(NULL);
    struct tm *lt;
    (void)shown;
    if (!f) { winerr("open html report", GetLastError()); return; }
    GetComputerNameA(host, &hlen);
    lt = localtime(&t);
    if (lt) strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S", lt);

    fprintf(f,
"<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n"
"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
"<title>FIFOFox report - %s</title>\n<style>\n"
"  :root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--fg:#c9d1d9;--mut:#8b949e;}\n"
"  body{background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px;}\n"
"  h1{font-size:20px;margin:0 0 4px;} .sub{color:var(--mut);margin-bottom:20px;}\n"
"  .cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;}\n"
"  .c{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px 18px;min-width:110px;}\n"
"  .c .n{font-size:26px;font-weight:700;} .c .l{color:var(--mut);font-size:12px;text-transform:uppercase;}\n"
"  table{border-collapse:collapse;width:100%%;table-layout:fixed;background:var(--card);border:1px solid var(--bd);border-radius:8px;overflow:hidden;}\n"
"  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:top;word-break:break-word;overflow-wrap:anywhere;}\n"
"  th{background:#1c2128;color:var(--mut);font-size:12px;text-transform:uppercase;}\n"
"  tr.danger{background:rgba(248,81,73,.08);} tr.warn{background:rgba(210,153,34,.08);}\n"
"  code{display:block;font:11px/1.4 Consolas,monospace;color:#79c0ff;white-space:pre-wrap;word-break:break-all;max-height:11em;overflow:auto;}\n"
"  .find{font:11px/1.5 Consolas,monospace;white-space:normal;word-break:break-word;}\n"
"  .img{display:block;color:var(--mut);font:11px Consolas,monospace;word-break:break-all;max-height:8em;overflow:auto;}\n"
"  .badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;white-space:nowrap;}\n"
"  .badge.danger{background:#f85149;color:#fff;} .badge.warn{background:#d29922;color:#000;}\n"
"  .badge.ok{background:#238636;color:#fff;} .badge.na{background:#484f58;color:#fff;}\n"
"  footer{color:var(--mut);font-size:12px;margin-top:18px;}\n"
"  .filt{display:none;}\n"
"  .c{cursor:pointer;transition:border-color .12s,background .12s;}\n"
"  .c:hover{border-color:var(--mut);}\n"
"  #f-all:checked~.cards label[for=f-all],#f-danger:checked~.cards label[for=f-danger],"
"#f-warn:checked~.cards label[for=f-warn],#f-ok:checked~.cards label[for=f-ok]"
"{border-color:#58a6ff;background:#1b2735;}\n"
"  #f-danger:checked~table tbody tr:not(.danger){display:none;}\n"
"  #f-warn:checked~table tbody tr:not(.warn){display:none;}\n"
"  #f-ok:checked~table tbody tr:not(.ok){display:none;}\n"
"  .hint{color:var(--mut);font-size:11.5px;margin:-10px 0 16px;}\n"
"</style></head><body>\n"
"<input type=\"radio\" name=\"sev\" id=\"f-all\" class=\"filt\" checked>\n"
"<input type=\"radio\" name=\"sev\" id=\"f-danger\" class=\"filt\">\n"
"<input type=\"radio\" name=\"sev\" id=\"f-warn\" class=\"filt\">\n"
"<input type=\"radio\" name=\"sev\" id=\"f-ok\" class=\"filt\">\n"
"<h1>Named-Pipe Security Report</h1>\n"
"<div class=\"sub\">FIFOFox v%s &middot; host <b>%s</b> &middot; generated %s</div>\n"
"<div class=\"cards\">\n"
"  <label class=\"c\" for=\"f-all\"><div class=\"n\">%d</div><div class=\"l\">Pipes</div></label>\n"
"  <label class=\"c\" for=\"f-danger\"><div class=\"n\" style=\"color:#f85149\">%d</div><div class=\"l\">Danger</div></label>\n"
"  <label class=\"c\" for=\"f-warn\"><div class=\"n\" style=\"color:#d29922\">%d</div><div class=\"l\">Warn</div></label>\n"
"  <label class=\"c\" for=\"f-ok\"><div class=\"n\" style=\"color:#3fb950\">%d</div><div class=\"l\">OK</div></label>\n"
"</div>\n"
"<div class=\"hint\">Click a card to filter the table by severity &middot; click <b>Pipes</b> to show all.</div>\n"
"<table>\n<colgroup><col style=\"width:92px\"><col style=\"width:14%%\">"
"<col style=\"width:58px\"><col style=\"width:96px\"><col style=\"width:19%%\">"
"<col style=\"width:26%%\"><col></colgroup>\n"
"<thead><tr><th>Severity</th><th>Pipe</th><th>Server PID</th><th>Owner</th>"
"<th>Server image</th><th>Findings</th><th>SDDL</th></tr></thead>\n<tbody>\n",
        host, FIFOFOX_VERSION, host, when, total, danger, warn, okc);

    if (rows->p && rows->len) fputs(rows->p, f);
    else fputs("<tr><td colspan=\"7\">No rows (nothing flagged; run with --all to include OK pipes).</td></tr>\n", f);

    fprintf(f,
"</tbody></table>\n"
"<footer>Severity key: <b>DANGER</b> = low-priv SID holds WRITE_DAC/WRITE_OWNER/"
"GENERIC_ALL, or a NULL DACL (object takeover); <b>WARN</b> = low-priv SID can write "
"pipe data; <b>OK</b> = no low-priv write. A permissive DACL only governs who may "
"connect - real privilege impact depends on the server's in-band authorization.<br>"
"Generated by FIFOFox %s &middot; Zero Science Lab - https://zeroscience.mk</footer>\n"
"</body></html>\n", FIFOFOX_VERSION);

    fclose(f);
    printf("[*] HTML report written: %s\n", path);
}

static int mode_enum(int show_all, int want_squat, const char *htmlpath)
{
    WIN32_FIND_DATAA fd;
    HANDLE find;
    int total = 0, flagged = 0, danger = 0, warn = 0, okc = 0, shown = 0;
    int want_html = (htmlpath != NULL);
    struct sbuf rows;

    if (want_html) sb_init(&rows);
    vrb("enumerating \\\\.\\pipe\\  (all=%d html=%s)\n", show_all,
        htmlpath ? htmlpath : "no");
    printf("[*] Enumerating \\\\.\\pipe\\ ...\n\n");

    find = FindFirstFileA("\\\\.\\pipe\\*", &fd);
    if (find == INVALID_HANDLE_VALUE) {
        winerr("FindFirstFile", GetLastError());
        if (want_html) sb_free(&rows);
        return 1;
    }

    do {
        char path[512], sddl[2048], find_buf[4096], owner[256] = "-";
        HANDLE h;
        DWORD spid = 0;
        int grade;
        if (!strcmp(fd.cFileName, ".") || !strcmp(fd.cFileName, "..")) continue;
        total++;
        make_pipe_path(fd.cFileName, path, sizeof(path));
        dbg("open %s\n", path);

        h = open_pipe_read(path);
        if (h == INVALID_HANDLE_VALUE) {
            DWORD e = GetLastError();
            dbg("  open failed err %lu\n", (unsigned long)e);
            if (show_all) {
                printf("%s[ ?? ]%s %-45s %s(open: err %lu)%s\n",
                       CC(A_GRY), CC(A_RESET), fd.cFileName,
                       CC(A_GRY), (unsigned long)e, CC(A_RESET));
                if (want_html) {
                    char nesc[1600];
                    html_escape(fd.cFileName, nesc, sizeof(nesc));
                    sb_addf(&rows,
                        "<tr class=\"na\"><td><span class=\"badge na\">N/A</span></td>"
                        "<td>%s</td><td>-</td><td>-</td><td>-</td>"
                        "<td>SD not readable as this user (err %lu)</td>"
                        "<td><code>-</code></td></tr>\n", nesc, (unsigned long)e);
                    shown++;
                }
            }
            continue;
        }

        GetNamedPipeServerProcessId(h, &spid);
        grade = grade_pipe_security(h, show_all, sddl, sizeof(sddl), find_buf, sizeof(find_buf), owner, sizeof(owner));

        if (want_squat) {
            HANDLE sq = CreateNamedPipeA(path,
                                         PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                         1, 4096, 4096, 0, NULL);
            if (sq != INVALID_HANDLE_VALUE) {
                appendf(find_buf, sizeof(find_buf),
                        "  [DANGER] SQUATTABLE: no first-instance owner (interceptable)\n");
                if (grade < 2) grade = 2;
                CloseHandle(sq);
            } else {
                DWORD se = GetLastError();
                if (se == ERROR_PIPE_BUSY || se == ERROR_ALREADY_EXISTS) {
                    appendf(find_buf, sizeof(find_buf),
                            "  [WARN ] instance exists without first-instance protection (err %lu)\n",
                            (unsigned long)se);
                    if (grade < 1) grade = 1;
                } else if (show_all) {
                    appendf(find_buf, sizeof(find_buf),
                            "  [ ok ] not squattable (first-instance protected)\n");
                }
            }
        }

        if (grade >= 2) danger++; else if (grade == 1) warn++; else if (grade == 0) okc++;

        if (grade >= 1 || show_all) {
            const char *sev = grade >= 2 ? "DANGER" : (grade == 1 ? " WARN " : "  ok  ");
            printf("[%s%s%s] %s%s%s  %s(server PID %lu, owner %s)%s\n",
                   CC(sev_ansi(grade)), sev, CC(A_RESET),
                   CC(A_BOLD), fd.cFileName, CC(A_RESET),
                   CC(A_GRY), (unsigned long)spid, owner, CC(A_RESET));
            if (sddl[0])     printf("  %sSDDL:%s %s%s%s\n",
                                    CC(A_GRY), CC(A_RESET), CC(A_CYN), sddl, CC(A_RESET));
            if (find_buf[0]) print_findings_colored(find_buf);
            printf("\n");

            if (want_html) {
                char nesc[1600], sesc[4096], fesc[8192], iesc[1100], oesc[300];
                char imgpath[MAX_PATH] = "-";
                const char *cls = grade >= 2 ? "danger" : (grade == 1 ? "warn" : "ok");
                const char *lbl = grade >= 2 ? "DANGER" : (grade == 1 ? "WARN" : "OK");
                if (spid) {
                    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, spid);
                    if (p) { DWORD sz = MAX_PATH; QueryFullProcessImageNameA(p, 0, imgpath, &sz); CloseHandle(p); }
                }
                html_escape(fd.cFileName, nesc, sizeof(nesc));
                html_escape(sddl[0] ? sddl : "-", sesc, sizeof(sesc));
                html_escape(find_buf[0] ? find_buf : "(no flagged ACEs)", fesc, sizeof(fesc));
                html_escape(imgpath, iesc, sizeof(iesc));
                html_escape(owner[0] ? owner : "-", oesc, sizeof(oesc));
                sb_addf(&rows,
                    "<tr class=\"%s\"><td><span class=\"badge %s\">%s</span></td>"
                    "<td>%s</td><td>%lu</td><td>%s</td><td class=\"img\">%s</td>"
                    "<td class=\"find\">%s</td><td><code>%s</code></td></tr>\n",
                    cls, cls, lbl, nesc, (unsigned long)spid, oesc, iesc, fesc, sesc);
                shown++;
            }
        }
        if (grade >= 1) flagged++;
        CloseHandle(h);
    } while (FindNextFileA(find, &fd));
    FindClose(find);

    printf("------------------------------------------------------------\n");
    printf("[*] %d pipes: %s%d danger%s, %s%d warn%s, %s%d ok%s  (%d flagged)\n",
           total,
           CC(A_RED), danger, CC(A_RESET),
           CC(A_YEL), warn,   CC(A_RESET),
           CC(A_GRN), okc,    CC(A_RESET), flagged);
    print_legend();
    printf("    Note: 'Everyone connect+read/write' is common-by-design; the\n");
    printf("    serious flags are WRITE_DAC / WRITE_OWNER / GENERIC_ALL to a\n");
    printf("    low-priv SID, or a NULL DACL. Authorization still depends on\n");
    printf("    what the server does AFTER accept (verify in-band auth).\n");

    if (want_html) {
        write_html_report(htmlpath, &rows, total, danger, warn, okc, shown);
        sb_free(&rows);
    }
    return 0;
}

static void path_dir(const char *full, char *dir, size_t dlen)
{
    size_t k;
    snprintf(dir, dlen, "%s", full);
    k = strlen(dir);
    while (k > 0 && dir[k - 1] != '\\' && dir[k - 1] != '/') k--;
    if (k > 0) dir[k - 1] = 0; else dir[0] = 0;
    if (strlen(dir) == 2 && dir[1] == ':') { dir[2] = '\\'; dir[3] = 0; }
}

static int ci_eq(char a, char b)
{
    if (a >= 'A' && a <= 'Z') a += 32;
    if (b >= 'A' && b <= 'Z') b += 32;
    return a == b;
}

static void parse_image(const char *image, char *exe, size_t exelen, int *quoted)
{
    const char *p = image, *q;
    size_t i = 0;
    while (*p == ' ' || *p == '\t') p++;
    *quoted = 0; exe[0] = 0;
    if (*p == '"') {
        *quoted = 1; p++;
        while (*p && *p != '"' && i < exelen - 1) exe[i++] = *p++;
        exe[i] = 0; return;
    }
    for (q = p; *q; q++) {
        if (q[0] == '.' && ci_eq(q[1], 'e') && ci_eq(q[2], 'x') && ci_eq(q[3], 'e') &&
            (q[4] == 0 || q[4] == ' ' || q[4] == '\t' || q[4] == '\\' || q[4] == '/')) {
            size_t n = (size_t)(q + 4 - p);
            if (n >= exelen) n = exelen - 1;
            memcpy(exe, p, n); exe[n] = 0; return;
        }
    }
    while (p[i] && p[i] != ' ' && i < exelen - 1) { exe[i] = p[i]; i++; }
    exe[i] = 0;
}

static int path_lowpriv_writable(const char *path, char *whoout, size_t wholen)
{
    PSECURITY_DESCRIPTOR psd = NULL; PACL dacl = NULL; DWORD r, i; int worst = 0;
    if (whoout && wholen) whoout[0] = 0;
    r = GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                              NULL, NULL, &dacl, NULL, &psd);
    if (r != ERROR_SUCCESS) return -1;
    if (dacl == NULL) { if (whoout) snprintf(whoout, wholen, "NULL DACL"); LocalFree(psd); return 2; }
    for (i = 0; i < dacl->AceCount; ++i) {
        ACE_HEADER *hdr = NULL;
        if (!GetAce(dacl, i, (LPVOID *)&hdr)) continue;
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        if (hdr->AceFlags & INHERIT_ONLY_ACE) continue;
        {
            ACCESS_ALLOWED_ACE *ace = (ACCESS_ALLOWED_ACE *)hdr;
            PSID sid = (PSID)&ace->SidStart; char *sidstr = NULL;
            ACCESS_MASK m; int sev = 0;
            if (!ConvertSidToStringSidA(sid, &sidstr)) continue;
            if (sid_is_lowpriv(sidstr)) {
                m = ace->Mask;
                if (m & (0x10000000UL | 0x00040000UL | 0x00080000UL)) sev = 2;
                else if (m & (0x00000002UL | 0x40000000UL | 0x00010000UL)) sev = 1;
                if (sev > worst) {
                    worst = sev;
                    if (whoout) { char mb[300]; format_mask(m, mb, sizeof mb);
                                  snprintf(whoout, wholen, "%s : %s", sid_label(sidstr), mb); }
                }
            }
            LocalFree(sidstr);
        }
    }
    LocalFree(psd);
    return worst;
}

static int check_unquoted(const char *exe, char *find, size_t fcap)
{
    int worst = 0; size_t i;
    for (i = 0; exe[i]; ++i) {
        if (exe[i] == ' ') {
            char cand[MAX_PATH], dir[MAX_PATH], who[320]; int sev;
            if (i >= sizeof(cand) - 5) continue;
            memcpy(cand, exe, i); cand[i] = 0;
            path_dir(cand, dir, sizeof dir);
            if (!dir[0]) continue;
            sev = path_lowpriv_writable(dir, who, sizeof who);
            appendf(find, fcap, "    intercept \"%s.exe\" -> dir [%s] : %s\n", cand, dir,
                    sev > 0 ? who : (sev == 0 ? "not low-priv writable" : "(ACL unreadable)"));
            if (sev > 0) worst = 2;
        }
    }
    return worst;
}

static int svc_find_by_pid(DWORD pid, char *name, size_t nlen, char *disp, size_t dlen, int *shared)
{
    SC_HANDLE scm; BYTE *buf; DWORD bytes = 0, count = 0, resume = 0, i; int found = 0;
    *shared = 0;
    if (pid == 0) return 0;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return 0;
    EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          NULL, 0, &bytes, &count, &resume, NULL);
    if (bytes == 0) { CloseServiceHandle(scm); return 0; }
    buf = (BYTE *)malloc(bytes);
    if (!buf) { CloseServiceHandle(scm); return 0; }
    if (EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                              buf, bytes, &bytes, &count, &resume, NULL)) {
        ENUM_SERVICE_STATUS_PROCESSA *a = (ENUM_SERVICE_STATUS_PROCESSA *)buf;
        for (i = 0; i < count; ++i) {
            if (a[i].ServiceStatusProcess.dwProcessId == pid) {
                if (!found) {
                    snprintf(name, nlen, "%s", a[i].lpServiceName ? a[i].lpServiceName : "");
                    if (disp) snprintf(disp, dlen, "%s", a[i].lpDisplayName ? a[i].lpDisplayName : "");
                    found = 1;
                } else (*shared)++;
            }
        }
    }
    free(buf); CloseServiceHandle(scm);
    return found;
}

static int svc_query_config(const char *svc, char *image, size_t ilen, char *acct, size_t alen)
{
    SC_HANDLE scm, s; DWORD need = 0; QUERY_SERVICE_CONFIGA *cfg; int ok = 0;
    scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    s = OpenServiceA(scm, svc, SERVICE_QUERY_CONFIG);
    if (!s) { CloseServiceHandle(scm); return 0; }
    QueryServiceConfigA(s, NULL, 0, &need);
    cfg = (QUERY_SERVICE_CONFIGA *)malloc(need ? need : 8);
    if (cfg && QueryServiceConfigA(s, cfg, need, &need)) {
        snprintf(image, ilen, "%s", cfg->lpBinaryPathName ? cfg->lpBinaryPathName : "");
        snprintf(acct,  alen, "%s", cfg->lpServiceStartName ? cfg->lpServiceStartName : "");
        ok = 1;
    }
    free(cfg); CloseServiceHandle(s); CloseServiceHandle(scm);
    return ok;
}

static int acct_privileged(const char *a)
{
    return (!_stricmp(a, "LocalSystem") || !_stricmp(a, ".\\LocalSystem") ||
            !_stricmp(a, "NT AUTHORITY\\System") || !_stricmp(a, "NT Authority\\LocalSystem"));
}

static int mem_has(const unsigned char *h, size_t hn, const char *n)
{
    size_t nl = strlen(n), i;
    if (nl == 0 || nl > hn) return 0;
    for (i = 0; i + nl <= hn; ++i) if (h[i] == (unsigned char)n[0] && memcmp(h + i, n, nl) == 0) return 1;
    return 0;
}
static int bin_has(const unsigned char *h, size_t hn, const char *n)
{
    size_t nl = strlen(n), i, j;
    if (mem_has(h, hn, n)) return 1;
    if (nl == 0 || nl * 2 > hn) return 0;
    for (i = 0; i + nl * 2 <= hn; ++i) { int ok = 1;
        for (j = 0; j < nl; ++j) if (h[i + j * 2] != (unsigned char)n[j] || h[i + j * 2 + 1] != 0) { ok = 0; break; }
        if (ok) return 1; }
    return 0;
}
static int lint_trust(const char *exe, char *out, size_t cap)
{
    FILE *f; long sz; size_t got; unsigned char *b; int sev = 0, wvt, cqo, chain, cps, cn, temp, k;
    static const char *flags[] = { "check_msi_digest", "skip_signature", "skipSignature", "SkipSignature",
        "disable_signature", "verifySignature", "check_signature", "NoSignatureCheck", "AllowUnsigned", NULL };
    if (!exe || !exe[0]) return 0;
    f = fopen(exe, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (64L << 20)) { fclose(f); return 0; }
    b = (unsigned char *)malloc((size_t)sz); if (!b) { fclose(f); return 0; }
    got = fread(b, 1, (size_t)sz, f); fclose(f);
    wvt   = mem_has(b, got, "WinVerifyTrust");
    cqo   = mem_has(b, got, "CryptQueryObject");
    chain = mem_has(b, got, "CertGetCertificateChain") || mem_has(b, got, "CertVerifyCertificateChainPolicy");
    cps   = mem_has(b, got, "CreateProcessAsUser");
    cn    = bin_has(b, got, "CN=");
    temp  = bin_has(b, got, "\\Temp\\") || mem_has(b, got, "GetTempPath");
    appendf(out, cap, "    sig APIs: WinVerifyTrust=%s CryptQueryObject=%s CertChain=%s\n",
            wvt ? "yes" : "no", cqo ? "yes" : "no", chain ? "yes" : "no");
    if (!wvt && (cqo || chain)) { appendf(out, cap,
        "    [WARN] parses a signature but NOT via WinVerifyTrust -> may check existence, not trust (CWE-347)\n"); if (sev < 1) sev = 1; }
    if (!wvt && !cqo && !chain)
        appendf(out, cap, "    [note] no signature-verification API found in the binary\n");
    if (cn)        appendf(out, cap, "    [note] hardcoded \"CN=\" present -> verify signer match is exact, not substring\n");
    if (temp && cps) appendf(out, cap, "    [note] temp path + CreateProcessAsUser -> check for copy->verify->exec TOCTOU\n");
    for (k = 0; flags[k]; ++k) if (bin_has(b, got, flags[k]))
        appendf(out, cap, "    [note] config flag \"%s\" present -> signature check may be toggleable\n", flags[k]);
    free(b);
    return sev;
}

static int audit_service_surface(DWORD spid, const char *pidimg, char *html, size_t hcap)
{
    char svc[256] = "", disp[256] = "", image[1024] = "", acct[256] = "";
    char exe[MAX_PATH] = "", bdir[MAX_PATH] = "", who[320] = "", find[2560] = "";
    int shared = 0, quoted = 0, sev = 0, privileged = 0;

    printf("\n  %s--- owning service / escalation surface ---%s\n", CC(A_GRY), CC(A_RESET));
    if (spid == 0) {
        printf("  %sserver PID unknown - cannot map to a service%s\n", CC(A_GRY), CC(A_RESET));
        if (html) appendf(html, hcap, "service: (server PID unknown)\n");
        return 0;
    }
    if (!svc_find_by_pid(spid, svc, sizeof svc, disp, sizeof disp, &shared)) {
        printf("  %-12s  (none) - PID %lu is not a Windows service: %s\n", "service", (unsigned long)spid,
               pidimg ? pidimg : "-");
        if (html) appendf(html, hcap, "service: none (owner PID %lu, %s)\n", (unsigned long)spid, pidimg ? pidimg : "-");
        if (pidimg && pidimg[0] && pidimg[0] != '(') {
            char d[MAX_PATH]; int s;
            path_dir(pidimg, d, sizeof d);
            s = path_lowpriv_writable(d, who, sizeof who);
            printf("  %-12s  [%s] : %s\n", "image dir", d,
                   s > 0 ? who : (s == 0 ? "not low-priv writable" : "(unreadable)"));
            if (s > 0) { sev = 1; if (html) appendf(html, hcap, "image dir writable: %s\n", who); }
        }
        return sev;
    }
    if (!svc_query_config(svc, image, sizeof image, acct, sizeof acct))
        snprintf(image, sizeof image, "%s", pidimg ? pidimg : "");
    privileged = acct_privileged(acct);

    printf("  %-12s  %s%s%s\n", "service", svc, disp[0] ? "  -  " : "", disp);
    printf("  %-12s  %s%s%s%s\n", "account", acct[0] ? acct : "(unknown)",
           privileged ? CC(A_RED) : "", privileged ? "  (privileged)" : "", CC(A_RESET));
    printf("  %-12s  %s\n", "imagepath", image[0] ? image : "(unreadable)");

    if (shared > 0) {
        printf("  %-12s  %sshared host (svchost / %d+ services on this PID) - per-service binary "
               "attribution not possible; skipping%s\n", "note", CC(A_GRY), shared + 1, CC(A_RESET));
        if (html) appendf(html, hcap, "service: %s (shared host, %d+ svcs) account=%s\n", svc, shared + 1, acct);
        return 0;
    }

    parse_image(image, exe, sizeof exe, &quoted);
    path_dir(exe, bdir, sizeof bdir);

    if (!quoted && strchr(exe, ' ')) {
        int us;
        printf("  %-12s  %sYES%s - path has spaces and is not quoted\n", "unquoted", CC(A_RED), CC(A_RESET));
        us = check_unquoted(exe, find, sizeof find);
        if (us > sev) sev = us;
    } else {
        printf("  %-12s  no (%s)\n", "unquoted", quoted ? "path is quoted" : "no spaces in path");
    }

    if (bdir[0]) {
        int ds = path_lowpriv_writable(bdir, who, sizeof who);
        printf("  %-12s  [%s] : %s\n", "binary dir", bdir,
               ds > 0 ? who : (ds == 0 ? "not low-priv writable" : "(unreadable)"));
        if (ds > 0) { appendf(find, sizeof find, "    binary dir low-priv writable: %s  (plant a side-load DLL)\n", who);
                      if (privileged) sev = 2; else if (sev < 1) sev = 1; }
    }
    if (exe[0]) {
        char who2[320]; int fs = path_lowpriv_writable(exe, who2, sizeof who2);
        if (fs > 0) { printf("  %-12s  [%s] : %s\n", "binary file", exe, who2);
                      appendf(find, sizeof find, "    binary file low-priv writable: %s  (replace the executable)\n", who2);
                      if (privileged) sev = 2; else if (sev < 1) sev = 1; }
        else printf("  %-12s  [%s] : not low-priv writable\n", "binary file", exe);
    }

    {
        char lint[1600] = "";
        lint_trust(exe, lint, sizeof lint);
        if (lint[0]) {
            printf("  %strust checks (heuristic):%s\n", CC(A_GRY), CC(A_RESET));
            fputs(lint, stdout);
            if (html) { appendf(html, hcap, "trust-checks:\n%s", lint); }
        }
    }

    {
        int unq = (!quoted && strchr(exe, ' ') != NULL);
        const char *v = sev >= 2
              ? (privileged ? "DANGER - low-priv code execution as a PRIVILEGED service account"
                            : "DANGER - low-priv can run code as the service account")
              : sev == 1 ? "WARN - low-priv writable but service not privileged (cross-user code-integrity)"
              : unq ? "OK - unquoted path, but no low-priv-writable intercept dir (not exploitable)"
                    : "OK - no low-priv write into the service's executable surface";
        printf("  %-12s  %s%s%s\n", "svc verdict", CC(sev_ansi(sev)), v, CC(A_RESET));
        if (find[0]) { printf("  %sdetails:%s\n", CC(A_GRY), CC(A_RESET)); fputs(find, stdout); }
    }
    if (html) {
        appendf(html, hcap, "service: %s  account: %s%s\n", svc, acct, privileged ? " (privileged)" : "");
        appendf(html, hcap, "imagepath: %s\n", image);
        appendf(html, hcap, "unquoted: %s\n", (!quoted && strchr(exe, ' ')) ? "YES" : "no");
        appendf(html, hcap, "%s", find[0] ? find : "  (no low-priv-writable service surface)\n");
    }
    return sev;
}

static int mode_audit(const char *name, const char *htmlpath)
{
    char path[512];
    HANDLE h;
    DWORD spid = 0, cpid = 0;
    int grade = -1;
    int squat_sev = 0;
    char sddl[2048], find_buf[4096];
    char geo[512] = "", squatv[400] = "", simg[MAX_PATH] = "-";
    char s_type[80] = "(n/a)", s_buf[64] = "(n/a)", s_maxinst[32] = "(n/a)";
    char s_server[MAX_PATH + 48] = "(none)", s_client[48] = "(none)";
    char squat_short[256] = "(n/a)";
    const char *gtxt;
    int svc_sev = 0;
    char svc_html[2816] = "";
    char owner[256] = "-", servinteg[128] = "(unavailable)";
    make_pipe_path(name, path, sizeof(path));

    printf("[*] Auditing %s\n\n", path);
    vrb("audit: opening %s for READ_CONTROL\n", path);
    h = open_pipe_read(path);
    sddl[0] = find_buf[0] = 0;

    if (h == INVALID_HANDLE_VALUE) {
        DWORD oe = GetLastError();
        printf("  %s(pipe not open / SD unreadable: err %lu - testing squattability anyway)%s\n",
               CC(A_GRY), (unsigned long)oe, CC(A_RESET));
        vrb("audit: open failed err %lu; continuing to squat test\n", (unsigned long)oe);
    } else {
        {
            DWORD flags = 0, outbuf = 0, inbuf = 0, maxinst = 0;
            if (GetNamedPipeInfo(h, &flags, &outbuf, &inbuf, &maxinst)) {
                if (maxinst == PIPE_UNLIMITED_INSTANCES) snprintf(s_maxinst, sizeof(s_maxinst), "unlimited");
                else snprintf(s_maxinst, sizeof(s_maxinst), "%lu", (unsigned long)maxinst);
                snprintf(s_type, sizeof(s_type), "%s, %s",
                         (flags & PIPE_TYPE_MESSAGE) ? "MESSAGE" : "BYTE",
                         (flags & PIPE_SERVER_END) ? "server-end-handle" : "client-end-handle");
                snprintf(s_buf, sizeof(s_buf), "in=%lu out=%lu",
                         (unsigned long)inbuf, (unsigned long)outbuf);
                snprintf(geo, sizeof(geo), "type=%s; buffers %s; maxInstances=%s",
                         s_type, s_buf, s_maxinst);
            }
        }

        GetNamedPipeServerProcessId(h, &spid);
        GetNamedPipeClientProcessId(h, &cpid);
        if (spid) {
            HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, spid);
            if (p) {
                DWORD sz = MAX_PATH;
                if (!QueryFullProcessImageNameA(p, 0, simg, &sz)) snprintf(simg, sizeof(simg), "(access denied)");
                CloseHandle(p);
            } else snprintf(simg, sizeof(simg), "(OpenProcess denied)");
            snprintf(s_server, sizeof(s_server), "PID %lu  %s", (unsigned long)spid, simg);
        }
        if (cpid) snprintf(s_client, sizeof(s_client), "PID %lu", (unsigned long)cpid);

        grade = grade_pipe_security(h, 1, sddl, sizeof(sddl), find_buf, sizeof(find_buf), owner, sizeof(owner));
        CloseHandle(h);
    }
    server_integrity(spid, servinteg, sizeof(servinteg));

    {
        HANDLE sq = CreateNamedPipeA(path,
                                     PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                                     PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                     1, 4096, 4096, 0, NULL);
        if (sq != INVALID_HANDLE_VALUE) {
            squat_sev = 2;
            snprintf(squat_short, sizeof(squat_short),
                     "YES - no first-instance owner (interceptable)");
            snprintf(squatv, sizeof(squatv),
                     "SQUATTABLE: no first-instance owner present; a malicious process "
                     "could pre-create this name and intercept clients.");
            CloseHandle(sq);
        } else {
            DWORD e = GetLastError();
            if (e == ERROR_ACCESS_DENIED) {
                squat_sev = 0;
                snprintf(squat_short, sizeof(squat_short),
                         "no - owned w/ FIRST_PIPE_INSTANCE (or denied)");
                snprintf(squatv, sizeof(squatv),
                         "Not squattable: name owned with FIRST_PIPE_INSTANCE (or access denied).");
            } else if (e == ERROR_PIPE_BUSY || e == ERROR_ALREADY_EXISTS) {
                squat_sev = 1;
                snprintf(squat_short, sizeof(squat_short),
                         "exists WITHOUT first-instance protection (err %lu)", (unsigned long)e);
                snprintf(squatv, sizeof(squatv),
                         "Instance exists WITHOUT first-instance protection (err %lu) - investigate race window.",
                         (unsigned long)e);
            } else {
                squat_sev = 0;
                snprintf(squat_short, sizeof(squat_short), "test error %lu", (unsigned long)e);
                snprintf(squatv, sizeof(squatv), "squat test error %lu", (unsigned long)e);
            }
        }
    }

    gtxt = grade >= 2 ? "DANGER (low-priv takeover / NULL DACL)"
         : grade == 1 ? "WARN (low-priv writable)"
         : grade == 0 ? "OK (no low-priv write)"
                      : "(SD unreadable)";
    printf("  %sAttribute     Value%s\n", CC(A_GRY), CC(A_RESET));
    printf("  %s------------  ------------------------------------------%s\n",
           CC(A_GRY), CC(A_RESET));
    printf("  %-12s  %s\n", "pipe",         path);
    printf("  %-12s  %s\n", "type",         s_type);
    printf("  %-12s  %s\n", "buffers",      s_buf);
    printf("  %-12s  %s\n", "maxInstances", s_maxinst);
    printf("  %-12s  %s\n", "server",       s_server);
    printf("  %-12s  %s\n", "client",       s_client);
    printf("  %-12s  %s%s%s\n", "owner",
           CC(A_CYN), owner[0] ? owner : "(unknown)", CC(A_RESET));
    printf("  %-12s  %s\n", "server integ", servinteg);
    printf("  %-12s  %s%s%s\n", "grade",
           CC(sev_ansi(grade)), gtxt, CC(A_RESET));
    printf("  %-12s  %s%s%s\n", "squattable",
           CC(sev_ansi(squat_sev)), squat_short, CC(A_RESET));
    printf("  %-12s  %s%s%s\n", "SDDL",
           CC(A_CYN), sddl[0] ? sddl : "(unreadable)", CC(A_RESET));

    if (find_buf[0]) {
        printf("\n  %sFindings:%s\n", CC(A_GRY), CC(A_RESET));
        print_findings_colored(find_buf);
    }

    if (!g_no_service)
        svc_sev = audit_service_surface(spid, simg, svc_html, sizeof svc_html);

    if (g_peek) {
        HANDLE ph;
        printf("\n  %s--- passive peek (payload format) ---%s\n", CC(A_GRY), CC(A_RESET));
        ph = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, 0, NULL);
        if (ph == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeA(path, 500))
            ph = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, 0, NULL);
        if (ph == INVALID_HANDLE_VALUE) {
            printf("  (could not open for read: err %lu)\n", (unsigned long)GetLastError());
        } else {
            static unsigned char pbuf[16384];
            DWORD avail = 0, rd = 0, waited = 0;
            while (waited < 1500) {
                if (PeekNamedPipe(ph, NULL, 0, NULL, &avail, NULL) && avail) {
                    ReadFile(ph, pbuf, avail > sizeof pbuf ? (DWORD)sizeof pbuf : avail, &rd, NULL);
                    break;
                }
                Sleep(100); waited += 100;
            }
            if (rd > 0) { printf("  server greeted with %lu unsolicited byte(s):\n", (unsigned long)rd);
                          dissect_auto(stdout, pbuf, rd); }
            else printf("  server sent no unsolicited data (request/response server) - use 'capture' or 'send' to elicit + classify its protocol\n");
            CloseHandle(ph);
        }
    }

    printf("\n");
    print_legend();

    if (htmlpath) {
        struct sbuf rows;
        char combined[8192];
        char nesc[1600], sesc[4096], fesc[16384], iesc[1100], oesc[300];
        int overall = grade > squat_sev ? grade : squat_sev;
        const char *cls, *lbl;
        if (svc_sev > overall) overall = svc_sev;
        cls = overall >= 2 ? "danger" : (overall == 1 ? "warn" : "ok");
        lbl = overall >= 2 ? "DANGER" : (overall == 1 ? "WARN" : "OK");
        sb_init(&rows);
        combined[0] = 0;
        appendf(combined, sizeof(combined), "%s", find_buf[0] ? find_buf : "(no flagged ACEs)\n");
        appendf(combined, sizeof(combined), "geometry: %s\n", geo[0] ? geo : "(n/a)");
        appendf(combined, sizeof(combined), "squattability: %s\n", squatv[0] ? squatv : "(n/a)");
        if (svc_html[0]) appendf(combined, sizeof(combined), "--- escalation surface ---\n%s", svc_html);
        html_escape(name, nesc, sizeof(nesc));
        html_escape(sddl[0] ? sddl : "-", sesc, sizeof(sesc));
        html_escape(combined, fesc, sizeof(fesc));
        html_escape(simg, iesc, sizeof(iesc));
        html_escape(owner[0] ? owner : "-", oesc, sizeof(oesc));
        sb_addf(&rows,
            "<tr class=\"%s\"><td><span class=\"badge %s\">%s</span></td>"
            "<td>%s</td><td>%lu</td><td>%s</td><td class=\"img\">%s</td>"
            "<td class=\"find\">%s</td><td><code>%s</code></td></tr>\n",
            cls, cls, lbl, nesc, (unsigned long)spid, oesc, iesc, fesc, sesc);
        write_html_report(htmlpath, &rows, 1,
                          grade >= 2 ? 1 : 0, grade == 1 ? 1 : 0, grade == 0 ? 1 : 0, 1);
        sb_free(&rows);
    }
    return 0;
}

static uint64_t g_rng;
static uint64_t rng_next(void)
{
    uint64_t x = g_rng;
    x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
    g_rng = x;
    return x * 0x2545F4914F6CDD1DULL;
}
static unsigned rng_u(unsigned mod) { return mod ? (unsigned)(rng_next() % mod) : 0; }

static unsigned char **g_corpus = NULL;
static size_t         *g_corpus_len = NULL;
static int             g_corpus_n = 0;
static int load_corpus(const char *file)
{
    FILE *f = fopen(file, "rb");
    size_t cap = 64;
    if (!f) return 0;
    g_corpus     = (unsigned char **)malloc(cap * sizeof(*g_corpus));
    g_corpus_len = (size_t *)malloc(cap * sizeof(*g_corpus_len));
    if (!g_corpus || !g_corpus_len) { fclose(f); return 0; }
    for (;;) {
        uint32_t l = 0;
        unsigned char *b;
        if (fread(&l, 4, 1, f) != 1) break;
        if (l == 0 || l > (16u << 20)) break;
        b = (unsigned char *)malloc(l);
        if (!b) break;
        if (fread(b, 1, l, f) != l) { free(b); break; }
        if (g_corpus_n == (int)cap) {
            cap *= 2;
            g_corpus     = (unsigned char **)realloc(g_corpus, cap * sizeof(*g_corpus));
            g_corpus_len = (size_t *)realloc(g_corpus_len, cap * sizeof(*g_corpus_len));
            if (!g_corpus || !g_corpus_len) { free(b); break; }
        }
        g_corpus[g_corpus_n]     = b;
        g_corpus_len[g_corpus_n] = l;
        g_corpus_n++;
    }
    fclose(f);
    return g_corpus_n;
}

enum frame_kind { FR_RAW, FR_LEN16LE, FR_LEN16BE, FR_LEN32LE, FR_LEN32BE, FR_CMD };

static enum frame_kind parse_frame(const char *s)
{
    if (!_stricmp(s, "raw"))     return FR_RAW;
    if (!_stricmp(s, "len16le")) return FR_LEN16LE;
    if (!_stricmp(s, "len16be")) return FR_LEN16BE;
    if (!_stricmp(s, "len32le")) return FR_LEN32LE;
    if (!_stricmp(s, "len32be")) return FR_LEN32BE;
    if (!_stricmp(s, "cmd"))     return FR_CMD;
    return FR_RAW;
}

static int mv_rdvar(const unsigned char *b, size_t n, size_t *i, uint64_t *out)
{
    int s = 0; uint64_t x = 0; size_t j = *i, start = *i;
    while (j < n && j - start < 10) { unsigned char c = b[j++]; x |= (uint64_t)(c & 0x7f) << s;
        if (!(c & 0x80)) { *out = x; *i = j; return 1; } s += 7; }
    return 0;
}
static void mv_wrvar(unsigned char *o, size_t *p, size_t cap, uint64_t v)
{ do { unsigned char c = (unsigned char)(v & 0x7f); v >>= 7; if (v) c |= 0x80; if (*p < cap) o[*p] = c; (*p)++; } while (v); }
static void mv_wr(unsigned char *o, size_t *p, size_t cap, const unsigned char *s, size_t n)
{ size_t k; for (k = 0; k < n; ++k) { if (*p < cap) o[*p] = s[k]; (*p)++; } }

static size_t mv_fuzz(unsigned char *out, size_t cap)
{
    unsigned i, n;
    switch (rng_u(6)) {
    case 0:  n = 16 + rng_u(4080); if (n > cap) n = (unsigned)cap; memset(out, 'A', n); return n;
    case 1:  { static const char *t = "%n%s%x%p%n%n%s"; n = 32 + rng_u(96); if (n > cap) n = (unsigned)cap;
               for (i = 0; i < n; ++i) out[i] = (unsigned char)t[i % 13]; return n; }
    case 2:  { static const char *t = "..\\..\\..\\..\\..\\windows\\win.ini"; size_t l = strlen(t);
               if (l > cap) l = cap; memcpy(out, t, l); return l; }
    case 3:  n = (unsigned)(cap < 65000 ? cap : 65000); memset(out, 0x41, n); return n;
    case 4:  return 0;
    default: n = 1 + rng_u(64); if (n > cap) n = (unsigned)cap; for (i = 0; i < n; ++i) out[i] = (unsigned char)rng_u(256); return n;
    }
}

static size_t pb_mutate_frame(const unsigned char *in, size_t inlen, unsigned char *out, size_t cap)
{
    static unsigned char env[1 << 17], fz[70000];
    const unsigned char *pl; size_t pn, i, eo = 0; int kiros = 0, nf = 0, pick, fi = 0;
    uint64_t k, l, v;
    if (inlen >= 16 && in[0] == 0 && in[1] == 0 && in[2] == 0 && in[3] == 8 && memcmp(in + 4, "protobuf", 8) == 0) {
        uint32_t p = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | in[15];
        if ((size_t)16 + p > inlen) return 0; pl = in + 16; pn = p; kiros = 1;
    } else { pl = in; pn = inlen; }
    i = 0;
    while (i < pn) {
        if (!mv_rdvar(pl, pn, &i, &k)) break;
        if ((k & 7) == 0) { if (!mv_rdvar(pl, pn, &i, &v)) break; }
        else if ((k & 7) == 2) { if (!mv_rdvar(pl, pn, &i, &l)) break; if (i + l > pn) break; i += (size_t)l; }
        else if ((k & 7) == 5) i += 4; else if ((k & 7) == 1) i += 8; else break;
        nf++;
    }
    if (nf == 0) return 0;
    pick = (int)rng_u((unsigned)nf);
    i = 0;
    while (i < pn) {
        if (!mv_rdvar(pl, pn, &i, &k)) break;
        if ((k & 7) == 0) {
            if (!mv_rdvar(pl, pn, &i, &v)) break;
            mv_wrvar(env, &eo, sizeof env, k);
            if (fi == pick) { uint64_t nv; switch (rng_u(4)) { case 0: nv = 0; break; case 1: nv = 0xffffffffULL; break;
                              case 2: nv = 0x7fffffffffffffffULL; break; default: nv = v ^ (1ULL << rng_u(63)); }
                              mv_wrvar(env, &eo, sizeof env, nv); }
            else mv_wrvar(env, &eo, sizeof env, v);
        } else if ((k & 7) == 2) {
            const unsigned char *vp; size_t vl;
            if (!mv_rdvar(pl, pn, &i, &l)) break; if (i + l > pn) break;
            vp = pl + i; vl = (size_t)l; i += vl;
            mv_wrvar(env, &eo, sizeof env, k);
            if (fi == pick) { size_t fl = mv_fuzz(fz, sizeof fz); mv_wrvar(env, &eo, sizeof env, fl); mv_wr(env, &eo, sizeof env, fz, fl); }
            else { mv_wrvar(env, &eo, sizeof env, vl); mv_wr(env, &eo, sizeof env, vp, vl); }
        } else if ((k & 7) == 5) { mv_wrvar(env, &eo, sizeof env, k); mv_wr(env, &eo, sizeof env, pl + i, 4); i += 4; }
        else if ((k & 7) == 1) { mv_wrvar(env, &eo, sizeof env, k); mv_wr(env, &eo, sizeof env, pl + i, 8); i += 8; }
        else break;
        fi++;
    }
    if (eo > sizeof env) return 0;
    if (kiros) {
        if (eo + 16 > cap) return 0;
        out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 8; memcpy(out + 4, "protobuf", 8);
        out[12] = (unsigned char)(eo >> 24); out[13] = (unsigned char)(eo >> 16);
        out[14] = (unsigned char)(eo >> 8);  out[15] = (unsigned char)eo;
        memcpy(out + 16, env, eo); return 16 + eo;
    }
    if (eo > cap) return 0; memcpy(out, env, eo); return eo;
}

static size_t dcerpc_mutate_frame(const unsigned char *in, size_t inlen, unsigned char *out, size_t cap)
{
    static unsigned char fz[70000];
    int le; size_t hdr, stub, fl, total;
    if (inlen < 16 || inlen > cap) return 0;
    le = (in[4] >> 4) & 1;
    hdr = (in[2] == 0 && inlen >= 24) ? 24 : 16;
    if (hdr > inlen) hdr = 16;
    stub = inlen - hdr;
    memcpy(out, in, hdr);
    if (rng_u(100) < 50 && stub > 0) {
        unsigned flips, j;
        if (stub > sizeof fz) stub = sizeof fz; memcpy(fz, in + hdr, stub); fl = stub;
        flips = 1 + rng_u(16); for (j = 0; j < flips && fl; ++j) fz[rng_u((unsigned)fl)] ^= (unsigned char)(1u << rng_u(8));
    } else fl = mv_fuzz(fz, sizeof fz);
    if (hdr + fl > cap) fl = cap - hdr;
    memcpy(out + hdr, fz, fl);
    total = hdr + fl;
    if (le) { out[8] = (unsigned char)(total & 0xff); out[9] = (unsigned char)((total >> 8) & 0xff); }
    else    { out[8] = (unsigned char)((total >> 8) & 0xff); out[9] = (unsigned char)(total & 0xff); }
    return total;
}

static size_t gen_payload(unsigned iter, unsigned maxlen, unsigned char *buf,
                          size_t bufcap, const char **desc, DWORD *lenlie)
{
    unsigned strat = iter % 7;
    size_t n = 0;
    *lenlie = (DWORD)-1;

    if (g_corpus_n > 0 && rng_u(100) < 65) {
        int idx = (int)rng_u((unsigned)g_corpus_n);
        const unsigned char *src = g_corpus[idx];
        size_t sl = g_corpus_len[idx], cl;
        unsigned flips, k;
        if (rng_u(100) < 55) {
            size_t m = 0;
            if (sl >= 16 && src[0] == 0 && src[1] == 0 && src[2] == 0 && src[3] == 8 && memcmp(src + 4, "protobuf", 8) == 0)
                { m = pb_mutate_frame(src, sl, buf, bufcap); if (m) { *desc = "proto-field"; return m; } }
            else if (sl >= 16 && src[0] == 5 && src[1] == 0 && src[2] <= 20)
                { m = dcerpc_mutate_frame(src, sl, buf, bufcap); if (m) { *desc = "rpc-stub"; return m; } }
        }
        cl = sl;
        if (cl > bufcap) cl = bufcap;
        memcpy(buf, src, cl);
        n = cl;
        if (n > 0) {
            flips = 1 + rng_u(16);
            for (k = 0; k < flips; ++k)
                buf[rng_u((unsigned)n)] ^= (unsigned char)(1u << rng_u(8));
            if (rng_u(100) < 20 && n > 4) n = 1 + rng_u((unsigned)n);
            else if (rng_u(100) < 20 && n + 64 < bufcap) {
                memset(buf + n, 'A', 64); n += 64;
            }
        }
        *desc = "corpus-havoc";
        return n;
    }

    switch (strat) {
    case 0: {
        size_t i;
        n = 1 + rng_u(maxlen ? maxlen : 256);
        if (n > bufcap) n = bufcap;
        for (i = 0; i < n; ++i) buf[i] = (unsigned char)rng_u(256);
        *desc = "random";
        break;
    }
    case 1: {
        static const size_t steps[] = {64,128,256,512,1024,4096,16384,65536};
        n = steps[(iter / 7) % (sizeof(steps)/sizeof(steps[0]))];
        if (n > bufcap) n = bufcap;
        memset(buf, 'A', n);
        *desc = "long-A (overflow probe)";
        break;
    }
    case 2: {
        static const char *tok = "%n%s%x%p%n%n%s%s";
        size_t tl = strlen(tok), i = 0;
        n = 64 + rng_u(192);
        if (n > bufcap) n = bufcap;
        while (i < n) { buf[i] = (unsigned char)tok[i % tl]; ++i; }
        *desc = "format-string";
        break;
    }
    case 3: {
        static const char *trav =
            "..\\..\\..\\..\\..\\..\\windows\\win.ini\x00/../../../../etc/passwd";
        size_t tl = 48;
        n = tl; if (n > bufcap) n = bufcap;
        memcpy(buf, trav, n);
        *desc = "path-traversal";
        break;
    }
    case 4: {
        n = 4 + rng_u(16);
        if (n > bufcap) n = bufcap;
        memset(buf, 'B', n);
        *lenlie = 0x7FFFFFFF;
        *desc = "length-lie (huge declared len)";
        break;
    }
    case 5: {
        size_t i;
        n = 32 + rng_u(96);
        if (n > bufcap) n = bufcap;
        for (i = 0; i < n; ++i) buf[i] = (iter & 1) ? 0xFF : 0x00;
        *desc = "boundary 0x00/0xFF";
        break;
    }
    default: {
        n = 1 + rng_u(8);
        if (n > bufcap) n = bufcap;
        memset(buf, 0, n);
        *lenlie = 0;
        *desc = "zero/short";
        break;
    }
    }
    return n;
}

static size_t frame_payload(enum frame_kind fr, const char *cmdprefix,
                            const unsigned char *payload, size_t plen,
                            DWORD lenlie, unsigned char *wire, size_t wirecap)
{
    DWORD declared = (lenlie == (DWORD)-1) ? (DWORD)plen : lenlie;
    size_t off = 0;
    switch (fr) {
    case FR_LEN16LE:
        if (wirecap < 2) return 0;
        wire[0] = (unsigned char)(declared & 0xFF);
        wire[1] = (unsigned char)((declared >> 8) & 0xFF);
        off = 2; break;
    case FR_LEN16BE:
        if (wirecap < 2) return 0;
        wire[0] = (unsigned char)((declared >> 8) & 0xFF);
        wire[1] = (unsigned char)(declared & 0xFF);
        off = 2; break;
    case FR_LEN32LE:
        if (wirecap < 4) return 0;
        wire[0]=(unsigned char)(declared&0xFF); wire[1]=(unsigned char)((declared>>8)&0xFF);
        wire[2]=(unsigned char)((declared>>16)&0xFF); wire[3]=(unsigned char)((declared>>24)&0xFF);
        off = 4; break;
    case FR_LEN32BE:
        if (wirecap < 4) return 0;
        wire[0]=(unsigned char)((declared>>24)&0xFF); wire[1]=(unsigned char)((declared>>16)&0xFF);
        wire[2]=(unsigned char)((declared>>8)&0xFF); wire[3]=(unsigned char)(declared&0xFF);
        off = 4; break;
    case FR_CMD: {
        size_t cl = strlen(cmdprefix);
        if (cl > wirecap) cl = wirecap;
        memcpy(wire, cmdprefix, cl);
        off = cl; break;
    }
    case FR_RAW:
    default:
        off = 0; break;
    }
    if (off + plen > wirecap) plen = wirecap - off;
    memcpy(wire + off, payload, plen);
    return off + plen;
}

static void hexdump_line(FILE *f, const unsigned char *b, size_t n, size_t cap)
{
    size_t i, lim = n < cap ? n : cap;
    for (i = 0; i < lim; ++i) fprintf(f, "%02x", b[i]);
    if (n > cap) fprintf(f, "...(%zu)", n);
}

static int pipe_alive(const char *path)
{
    if (WaitNamedPipeA(path, 100)) return 1;
    {
        DWORD e = GetLastError();
        if (e == ERROR_SEM_TIMEOUT || e == ERROR_PIPE_BUSY) return 1;
        if (e == ERROR_FILE_NOT_FOUND) return 0;
    }
    return 1;
}

static int mode_fuzz(const char *name, enum frame_kind fr, const char *cmdprefix,
                     unsigned iters, uint64_t seed, unsigned maxlen, unsigned delayms)
{
    char path[512];
    char logname[64];
    FILE *log;
    unsigned char *payload, *wire;
    size_t pcap = 1 << 20;
    size_t wcap = pcap + 64;
    unsigned i;
    time_t t = time(NULL);

    make_pipe_path(name, path, sizeof(path));
    g_rng = seed ? seed : 0xDEADBEEFCAFEBABEULL;

    snprintf(logname, sizeof(logname), "fifofox_fuzz_%lld.log", (long long)t);
    log = fopen(logname, "w");
    payload = (unsigned char *)malloc(pcap);
    wire = (unsigned char *)malloc(wcap);
    if (!log || !payload || !wire) {
        fprintf(stderr, "alloc/log failed\n");
        if (log) fclose(log);
        free(payload);
        free(wire);
        return 1;
    }

    printf("[*] Fuzzing %s  frame=%d iters=%u seed=0x%llX  log=%s\n",
           path, (int)fr, iters, (unsigned long long)g_rng, logname);
    fprintf(log, "# fifofox fuzz target=%s frame=%d seed=0x%llX iters=%u\n",
            path, (int)fr, (unsigned long long)g_rng, iters);

    for (i = 0; i < iters; ++i) {
        HANDLE h;
        const char *desc = "?";
        DWORD lenlie = (DWORD)-1, written = 0, e;
        size_t plen, wlen;
        unsigned char resp[512];
        DWORD avail = 0, rd = 0;

        h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            e = GetLastError();
            if (e == ERROR_PIPE_BUSY && WaitNamedPipeA(path, 1000))
                h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, 0, NULL);
        }
        if (h == INVALID_HANDLE_VALUE) {
            e = GetLastError();
            fprintf(log, "iter=%u CONNECT-FAIL err=%lu\n", i, (unsigned long)e);
            if (e == ERROR_FILE_NOT_FOUND) {
                printf("[!!] iter %u: pipe VANISHED (err %lu) -> possible crash. "
                       "Check the previous case in %s\n", i, (unsigned long)e, logname);
                break;
            }
            Sleep(delayms);
            continue;
        }

        plen = gen_payload(i, maxlen, payload, pcap, &desc, &lenlie);
        wlen = frame_payload(fr, cmdprefix, payload, plen, lenlie, wire, wcap);
        if (g_debug) dbg("iter %u strat=%s plen=%zu wire=%zu\n", i, desc, plen, wlen);
        else if (g_verbose && (i % 100 == 0)) vrb("fuzz progress: %u/%u\n", i, iters);

        fprintf(log, "iter=%u strat=%s plen=%zu declared=%s wire=%zu bytes=",
                i, desc, plen,
                lenlie == (DWORD)-1 ? "honest" : "LIE", wlen);
        hexdump_line(log, wire, wlen, 48);

        if (!WriteFile(h, wire, (DWORD)wlen, &written, NULL)) {
            fprintf(log, " WRITE-FAIL err=%lu\n", (unsigned long)GetLastError());
            CloseHandle(h);
        } else {
            Sleep(delayms ? delayms : 15);
            if (PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL) && avail) {
                DWORD want = avail > sizeof(resp) ? (DWORD)sizeof(resp) : avail;
                if (ReadFile(h, resp, want, &rd, NULL) && rd) {
                    fprintf(log, " resp=%lu:", (unsigned long)rd);
                    hexdump_line(log, resp, rd, 48);
                }
            }
            fprintf(log, "\n");
            CloseHandle(h);
        }
        fflush(log);

        if (!pipe_alive(path)) {
            printf("[!!] iter %u (%s): pipe no longer alive -> dumping repro.\n", i, desc);
            {
                char crashf[80];
                FILE *cf;
                snprintf(crashf, sizeof(crashf), "crash_%lld_%u.bin", (long long)t, i);
                cf = fopen(crashf, "wb");
                if (cf) { fwrite(wire, 1, wlen, cf); fclose(cf); }
                fprintf(log, "iter=%u SUSPECTED-CRASH repro=%s\n", i, crashf);
                printf("     wrote repro: %s\n", crashf);
            }
            break;
        }
    }

    printf("[*] Done. Log: %s\n", logname);
    fclose(log);
    free(payload);
    free(wire);
    return 0;
}

static unsigned char *read_file(const char *path, size_t *outlen)
{
    FILE *f = fopen(path, "rb");
    long sz;
    unsigned char *b;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    b = (unsigned char *)malloc((size_t)sz ? (size_t)sz : 1);
    if (b && fread(b, 1, (size_t)sz, f) != (size_t)sz) { free(b); b = NULL; }
    fclose(f);
    if (b) *outlen = (size_t)sz;
    return b;
}

static void dump_hex_ascii(const unsigned char *b, size_t n)
{
    size_t i, j;
    for (i = 0; i < n; i += 16) {
        printf("  %04zx  ", i);
        for (j = 0; j < 16; ++j) { if (i + j < n) printf("%02x ", b[i + j]); else printf("   "); }
        printf(" ");
        for (j = 0; j < 16 && i + j < n; ++j) { unsigned char c = b[i + j]; putchar((c >= 32 && c < 127) ? c : '.'); }
        printf("\n");
        if (i >= 1024) { printf("  ... (%zu bytes total)\n", n); break; }
    }
}

static void fhex_ascii(FILE *f, const unsigned char *b, size_t n, size_t cap)
{
    size_t i, j, lim = (cap && n > cap) ? cap : n;
    for (i = 0; i < lim; i += 16) {
        fprintf(f, "    %04zx  ", i);
        for (j = 0; j < 16; ++j) { if (i + j < lim) fprintf(f, "%02x ", b[i + j]); else fprintf(f, "   "); }
        fprintf(f, " ");
        for (j = 0; j < 16 && i + j < lim; ++j) { unsigned char c = b[i + j]; fputc((c >= 32 && c < 127) ? c : '.', f); }
        fprintf(f, "\n");
    }
    if (cap && n > cap) fprintf(f, "    ... (%zu bytes total)\n", n);
}

static int hexv(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t pb_varint(const unsigned char *b, size_t n, uint64_t *out)
{
    uint64_t v = 0; int shift = 0; size_t i = 0;
    while (i < n && i < 10) {
        unsigned char c = b[i++];
        v |= (uint64_t)(c & 0x7f) << shift;
        if (!(c & 0x80)) { *out = v; return i; }
        shift += 7;
    }
    return 0;
}

static int pb_is_message(const unsigned char *b, size_t n)
{
    size_t off = 0; int fields = 0;
    if (n == 0) return 0;
    while (off < n) {
        uint64_t key = 0, len = 0, v = 0; size_t k; int field, wire;
        k = pb_varint(b + off, n - off, &key); if (!k) return 0; off += k;
        field = (int)(key >> 3); wire = (int)(key & 7);
        if (field == 0) return 0;
        switch (wire) {
        case 0: k = pb_varint(b + off, n - off, &v); if (!k) return 0; off += k; break;
        case 1: if (off + 8 > n) return 0; off += 8; break;
        case 5: if (off + 4 > n) return 0; off += 4; break;
        case 2: k = pb_varint(b + off, n - off, &len); if (!k) return 0; off += k;
                if (len > n - off) return 0; off += (size_t)len; break;
        default: return 0;
        }
        fields++;
    }
    return (off == n && fields > 0);
}

static int looks_text(const unsigned char *b, size_t n)
{
    size_t i, pr = 0;
    if (n == 0) return 0;
    for (i = 0; i < n; ++i) {
        unsigned char c = b[i];
        if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) pr++;
    }
    return (pr * 100 >= n * 90);
}

static int is_clean_str(const unsigned char *b, size_t n)
{
    size_t i;
    if (n == 0) return 0;
    for (i = 0; i < n; ++i) {
        unsigned char c = b[i];
        if (c == 0 && i == n - 1) break;
        if (c < 0x20 || c > 0x7e) return 0;
    }
    return 1;
}

static void pb_dump(FILE *f, const unsigned char *b, size_t n, int depth)
{
    size_t off = 0;
    char ind[40]; int di = depth * 2;
    if (di > 36) di = 36;
    memset(ind, ' ', (size_t)di); ind[di] = 0;
    while (off < n) {
        uint64_t key = 0, v = 0, len = 0; size_t k; int field, wire;
        k = pb_varint(b + off, n - off, &key);
        if (!k) { fprintf(f, "%s<%zu undecodable byte(s)>\n", ind, n - off); return; }
        off += k; field = (int)(key >> 3); wire = (int)(key & 7);
        switch (wire) {
        case 0:
            k = pb_varint(b + off, n - off, &v); if (!k) return; off += k;
            fprintf(f, "%sf%d: varint %llu (0x%llx)\n", ind, field,
                    (unsigned long long)v, (unsigned long long)v);
            break;
        case 1:
            if (off + 8 > n) return;
            fprintf(f, "%sf%d: i64 0x", ind, field);
            { int j; for (j = 0; j < 8; ++j) fprintf(f, "%02x", b[off + j]); }
            fprintf(f, "\n"); off += 8; break;
        case 5:
            if (off + 4 > n) return;
            fprintf(f, "%sf%d: i32 0x", ind, field);
            { int j; for (j = 0; j < 4; ++j) fprintf(f, "%02x", b[off + j]); }
            fprintf(f, "\n"); off += 4; break;
        case 2: {
            const unsigned char *p; size_t pl;
            k = pb_varint(b + off, n - off, &len); if (!k) return; off += k;
            if (len > n - off) { fprintf(f, "%sf%d: <len-delim truncated>\n", ind, field); return; }
            p = b + off; pl = (size_t)len; off += pl;
            if (is_clean_str(p, pl)) {
                fprintf(f, "%sf%d: str[%zu] \"%.*s\"\n", ind, field, pl,
                        (int)(pl > 256 ? 256 : pl), (const char *)p);
            } else if (pl >= 2 && depth < 12 && pb_is_message(p, pl)) {
                fprintf(f, "%sf%d: msg[%zu] {\n", ind, field, pl);
                pb_dump(f, p, pl, depth + 1);
                fprintf(f, "%s}\n", ind);
            } else if (looks_text(p, pl)) {
                fprintf(f, "%sf%d: str[%zu] \"%.*s\"%s\n", ind, field, pl,
                        (int)(pl > 256 ? 256 : pl), (const char *)p, pl > 256 ? "..." : "");
            } else {
                fprintf(f, "%sf%d: bytes[%zu] ", ind, field, pl);
                { size_t j; for (j = 0; j < pl && j < 64; ++j) fprintf(f, "%02x", p[j]); }
                if (pl > 64) fprintf(f, "...");
                fprintf(f, "\n");
            }
            break; }
        default:
            fprintf(f, "%s<group/unknown wire %d at f%d - stop>\n", ind, wire, field);
            return;
        }
    }
}

static int is_magic_frame(const unsigned char *b, size_t n)
{
    return (n >= 16 && b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 8 &&
            memcmp(b + 4, "protobuf", 8) == 0);
}

static void frame_dissect2(FILE *f, const unsigned char *b, size_t n, int fdepth)
{
    if (is_magic_frame(b, n)) {
        uint32_t pl = ((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) |
                      ((uint32_t)b[14] << 8) | b[15];
        size_t avail = n - 16, use = (pl <= avail) ? pl : avail;
        fprintf(f, "  [frame] magic=\"protobuf\"  payloadlen=%u  (have %zu)\n", (unsigned)pl, avail);
        pb_dump(f, b + 16, use, 2);
        if (16 + use < n) fprintf(f, "  [+%zu trailing byte(s)]\n", n - 16 - use);
        return;
    }
    if (fdepth < 3 && n > 4) {
        uint32_t be = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
        uint32_t le = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
        const unsigned char *in = b + 4; size_t inl = n - 4;
        int inner_ok = is_magic_frame(in, inl) || pb_is_message(in, inl);
        if (le == inl && inner_ok) {
            fprintf(f, "  [frame] outer u32le length=%u\n", (unsigned)le);
            frame_dissect2(f, in, inl, fdepth + 1); return;
        }
        if (be == inl && inner_ok) {
            fprintf(f, "  [frame] outer u32be length=%u\n", (unsigned)be);
            frame_dissect2(f, in, inl, fdepth + 1); return;
        }
    }
    if (pb_is_message(b, n)) { fprintf(f, "  [raw protobuf, no framing]\n"); pb_dump(f, b, n, 2); return; }
    fprintf(f, "  [not protobuf - hex]\n");
    fhex_ascii(f, b, n, 512);
}

static void frame_dissect(FILE *f, const unsigned char *b, size_t n)
{
    frame_dissect2(f, b, n, 0);
}

enum payload_fmt { PF_HEX, PF_TEXT, PF_JSON, PF_XML, PF_PROTOBUF, PF_KIROS, PF_DCERPC, PF_DOTNET, PF_ASN1 };
static int g_force_fmt = -1;

static const char *fmt_name(int f)
{
    switch (f) {
    case PF_KIROS:    return "kiros-protobuf";
    case PF_PROTOBUF: return "protobuf";
    case PF_DCERPC:   return "DCE/RPC (MSRPC)";
    case PF_DOTNET:   return ".NET serialization";
    case PF_JSON:     return "JSON";
    case PF_XML:      return "XML";
    case PF_ASN1:     return "ASN.1/DER";
    case PF_TEXT:     return "text";
    default:          return "binary";
    }
}

static int parse_fmt(const char *s)
{
    if (!s) return -1;
    if (!_stricmp(s, "auto"))     return -1;
    if (!_stricmp(s, "protobuf")) return PF_PROTOBUF;
    if (!_stricmp(s, "kiros"))    return PF_KIROS;
    if (!_stricmp(s, "dcerpc") || !_stricmp(s, "rpc")) return PF_DCERPC;
    if (!_stricmp(s, "dotnet") || !_stricmp(s, "net")) return PF_DOTNET;
    if (!_stricmp(s, "json"))     return PF_JSON;
    if (!_stricmp(s, "xml"))      return PF_XML;
    if (!_stricmp(s, "asn1") || !_stricmp(s, "der")) return PF_ASN1;
    if (!_stricmp(s, "text"))     return PF_TEXT;
    if (!_stricmp(s, "hex") || !_stricmp(s, "binary")) return PF_HEX;
    return -1;
}

static int mostly_printable(const unsigned char *b, size_t n)
{
    size_t i, p = 0;
    if (!n) return 0;
    for (i = 0; i < n; ++i) { unsigned char c = b[i]; if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) p++; }
    return p * 100 >= n * 90;
}

static int der_len(const unsigned char *b, size_t n, size_t *outlen, int *hl)
{
    if (n < 1) return 0;
    if (b[0] < 0x80) { *outlen = b[0]; *hl = 1; return 1; }
    { int nb = b[0] & 0x7f, i; size_t v = 0;
      if (nb == 0 || nb > 4 || (size_t)nb + 1 > n) return 0;
      for (i = 0; i < nb; ++i) v = (v << 8) | b[1 + i];
      *outlen = v; *hl = 1 + nb; return 1; }
}

static int detect_fmt(const unsigned char *b, size_t n)
{
    size_t i = 0;
    if (n == 0) return PF_HEX;
    if (is_magic_frame(b, n)) return PF_KIROS;
    if (n >= 16 && b[0] == 5 && b[1] == 0 && b[2] <= 20) return PF_DCERPC;
    if (n >= 17 && b[0] == 0x00 && b[5] == 0xFF && b[6] == 0xFF && b[7] == 0xFF && b[8] == 0xFF && b[9] == 0x01)
        return PF_DOTNET;
    if (n >= 6 && b[0] == 0x00 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x01) return PF_DOTNET;
    while (i < n && (b[i] == ' ' || b[i] == '\t' || b[i] == '\r' || b[i] == '\n')) i++;
    if (i < n && (b[i] == '{' || b[i] == '[') && mostly_printable(b, n)) return PF_JSON;
    if (i < n && b[i] == '<' && mostly_printable(b, n)) return PF_XML;
    if (b[0] == 0x30 || b[0] == 0x31) { size_t l; int hl; if (der_len(b + 1, n - 1, &l, &hl) && (size_t)(1 + hl) + l <= n && l > 0) return PF_ASN1; }
    if (pb_is_message(b, n)) return PF_PROTOBUF;
    if (mostly_printable(b, n)) return PF_TEXT;
    return PF_HEX;
}

static const char *ptype_name(int t)
{
    static const char *nm[] = { "request", "ping", "response", "fault", "working", "nocall",
        "reject", "ack", "cl_cancel", "fack", "cancel_ack", "bind", "bind_ack", "bind_nak",
        "alter_context", "alter_context_resp", "shutdown", "co_cancel", "orphaned", "rts" };
    return (t >= 0 && t < 20) ? nm[t] : "?";
}

static const struct { const char *uuid; const char *name; } kRpcIf[] = {
    { "12345778-1234-abcd-ef00-0123456789ab", "samr" },
    { "12345778-1234-abcd-ef00-0123456789ac", "lsarpc" },
    { "367abb81-9844-35f1-ad32-98f038001003", "svcctl" },
    { "12345678-1234-abcd-ef00-0123456789ab", "spoolss (MS-RPRN)" },
    { "c681d488-d850-11d0-8c52-00c04fd90f7e", "efsrpc (lsarpc)" },
    { "df1941c5-fe89-4e79-bf10-463657acf44d", "efsrpc (MS-EFSR)" },
    { "338cd001-2244-31f1-aaaa-900038001003", "winreg" },
    { "4b324fc8-1670-01d3-1278-5a47bf6ee188", "srvsvc" },
    { NULL, NULL }
};

static void uuid_str(const unsigned char *p, int le, char *out)
{
    unsigned long d1; unsigned d2, d3;
    if (le) { d1 = p[0] | (p[1] << 8) | (p[2] << 16) | ((unsigned long)p[3] << 24); d2 = p[4] | (p[5] << 8); d3 = p[6] | (p[7] << 8); }
    else    { d1 = ((unsigned long)p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];  d2 = (p[4] << 8) | p[5]; d3 = (p[6] << 8) | p[7]; }
    sprintf(out, "%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            d1, d2, d3, p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
}

static void dcerpc_dump(FILE *f, const unsigned char *b, size_t n)
{
    int ptype = b[2], le = ((b[4] >> 4) & 1);
    unsigned frag = le ? (b[8] | (b[9] << 8)) : ((b[8] << 8) | b[9]);
    unsigned callid = (n >= 16) ? (le ? (b[12] | (b[13] << 8) | (b[14] << 16) | ((unsigned)b[15] << 24))
                                       : (((unsigned)b[12] << 24) | (b[13] << 16) | (b[14] << 8) | b[15])) : 0;
    fprintf(f, "  [DCE/RPC] v%u.%u  ptype=%d (%s)  flags=0x%02x  %s-endian  frag_len=%u  call_id=%u\n",
            b[0], b[1], ptype, ptype_name(ptype), b[3], le ? "little" : "big", frag, callid);
    if ((ptype == 11 || ptype == 14) && n >= 28 + 4 + 20) {
        const unsigned char *ab = b + 28 + 4; char u[40]; const char *who = "?"; int k;
        uuid_str(ab, le, u);
        for (k = 0; kRpcIf[k].uuid; ++k) if (_stricmp(kRpcIf[k].uuid, u) == 0) { who = kRpcIf[k].name; break; }
        fprintf(f, "    bind -> interface %s  (%s)  v%u\n", u, who, le ? (ab[16] | (ab[17] << 8)) : ((ab[16] << 8) | ab[17]));
    } else if (ptype == 0 && n >= 24) {
        unsigned opnum = le ? (b[22] | (b[23] << 8)) : ((b[22] << 8) | b[23]);
        fprintf(f, "    request opnum=%u  stub[%zu bytes]\n", opnum, n > 24 ? n - 24 : 0);
    }
    fhex_ascii(f, b, n, 192);
}

static void dotnet_dump(FILE *f, const unsigned char *b, size_t n)
{
    fprintf(f, "  [.NET serialization] BinaryFormatter / NetDataContractSerializer / NMF stream.\n");
    fprintf(f, "      >>> UNSAFE-DESERIALIZATION candidate: if a privileged endpoint deserializes this,\n");
    fprintf(f, "          it is very likely RCE. Extract the stream and weaponize with ysoserial.net.\n");
    fhex_ascii(f, b, n, 192);
}

static void asn1_dump(FILE *f, const unsigned char *b, size_t n, int depth)
{
    size_t off = 0; char ind[40]; int di = depth * 2;
    if (di > 36) di = 36; memset(ind, ' ', (size_t)di); ind[di] = 0;
    while (off + 2 <= n) {
        int tag = b[off], cls = (tag >> 6) & 3, cons = (tag >> 5) & 1, num = tag & 0x1f;
        size_t len, vs; int hl;
        const char *tn = num == 16 ? "SEQUENCE" : num == 17 ? "SET" : num == 2 ? "INTEGER" :
                         num == 4 ? "OCTET STRING" : num == 6 ? "OID" : num == 3 ? "BIT STRING" :
                         num == 5 ? "NULL" : "";
        if (!der_len(b + off + 1, n - off - 1, &len, &hl)) break;
        vs = off + 1 + hl;
        if (vs + len > n) break;
        fprintf(f, "%s[%s%s tag=%d len=%zu]\n", ind, cls == 2 ? "ctx-" : cls == 1 ? "app-" : "", tn[0] ? tn : "", num, len);
        if (cons) asn1_dump(f, b + vs, len, depth + 1);
        else if (len && len <= 48) { size_t i; fprintf(f, "%s  = ", ind); for (i = 0; i < len; ++i) fprintf(f, "%02x", b[vs + i]); fprintf(f, "\n"); }
        off = vs + len;
    }
}

static void text_dump(FILE *f, const unsigned char *b, size_t n)
{
    size_t i, lim = n < 4096 ? n : 4096;
    for (i = 0; i < lim; ++i) { unsigned char c = b[i]; fputc(((c >= 32 && c < 127) || c == 9 || c == 10 || c == 13) ? c : '.', f); }
    if (n > lim) fprintf(f, "\n  ...(%zu bytes total)", n);
    fprintf(f, "\n");
}

static void dissect_auto(FILE *f, const unsigned char *b, size_t n)
{
    int fmt = (g_force_fmt != -1) ? g_force_fmt : detect_fmt(b, n);
    fprintf(f, "  [format: %s]\n", fmt_name(fmt));
    switch (fmt) {
    case PF_KIROS: case PF_PROTOBUF: frame_dissect(f, b, n); break;
    case PF_DCERPC:                  dcerpc_dump(f, b, n);   break;
    case PF_DOTNET:                  dotnet_dump(f, b, n);   break;
    case PF_ASN1:                    asn1_dump(f, b, n, 2);  break;
    case PF_JSON: case PF_XML: case PF_TEXT: text_dump(f, b, n); break;
    default:                         fhex_ascii(f, b, n, 512); break;
    }
}

static int mode_decode(const char *path, int is_corpus, const char *hexstr)
{
    unsigned char *buf = NULL; size_t len = 0;

    if (hexstr) {
        size_t hl = strlen(hexstr), i = 0, j = 0;
        buf = (unsigned char *)malloc(hl / 2 + 1);
        if (!buf) return 1;
        for (;;) {
            int hi, lo;
            while (i < hl && hexv((unsigned char)hexstr[i]) < 0) i++;
            if (i >= hl) break; hi = hexv((unsigned char)hexstr[i++]);
            while (i < hl && hexv((unsigned char)hexstr[i]) < 0) i++;
            if (i >= hl) break; lo = hexv((unsigned char)hexstr[i++]);
            buf[j++] = (unsigned char)((hi << 4) | lo);
        }
        len = j;
        printf("[*] decoding %zu bytes from --hex\n", len);
        dissect_auto(stdout, buf, len);
        free(buf);
        return 0;
    }

    buf = read_file(path, &len);
    if (!buf) { fprintf(stderr, "cannot read %s\n", path); return 1; }

    if (is_corpus) {
        size_t off = 0; int idx = 0;
        printf("[*] corpus %s (%zu bytes): records are [u32le len][frame]\n", path, len);
        while (off + 4 <= len) {
            uint32_t fl = (uint32_t)buf[off] | ((uint32_t)buf[off+1] << 8) |
                          ((uint32_t)buf[off+2] << 16) | ((uint32_t)buf[off+3] << 24);
            off += 4;
            if (fl > len - off) { printf("  [frame %d truncated: wants %u, have %zu]\n", idx, (unsigned)fl, len - off); break; }
            printf("\n=== frame %d (%u bytes) ===\n", idx++, (unsigned)fl);
            dissect_auto(stdout, buf + off, fl);
            off += fl;
        }
        printf("\n[*] %d record(s) decoded.\n", idx);
    } else {
        printf("[*] decoding %s (%zu bytes)\n", path, len);
        dissect_auto(stdout, buf, len);
    }
    free(buf);
    return 0;
}

static void bput(unsigned char *b, size_t cap, size_t *o, unsigned char v)
{ if (*o < cap) b[*o] = v; (*o)++; }
static void bput_varint(unsigned char *b, size_t cap, size_t *o, uint64_t v)
{ do { unsigned char c = (unsigned char)(v & 0x7f); v >>= 7; if (v) c |= 0x80; bput(b, cap, o, c); } while (v); }
static void bput_bytes(unsigned char *b, size_t cap, size_t *o, const unsigned char *s, size_t n)
{ size_t i; for (i = 0; i < n; ++i) bput(b, cap, o, s[i]); }
static void bput_lenf(unsigned char *b, size_t cap, size_t *o, int field, const unsigned char *s, size_t n)
{ bput_varint(b, cap, o, ((uint64_t)field << 3) | 2); bput_varint(b, cap, o, n); bput_bytes(b, cap, o, s, n); }
static void bput_varf(unsigned char *b, size_t cap, size_t *o, int field, uint64_t v)
{ bput_varint(b, cap, o, ((uint64_t)field << 3) | 0); bput_varint(b, cap, o, v); }

static size_t build_kiros(const char *reqid, uint64_t verb, const char *path, const char *origin,
                          const char *type_url, const unsigned char *arg, size_t arglen,
                          unsigned char *out, size_t outcap)
{
    static unsigned char inner[16384], any[20480], env[40960];
    size_t io = 0, ao = 0, eo = 0, fo = 0;
    if (type_url && arg) bput_lenf(inner, sizeof inner, &io, 1, arg, arglen);
    if (type_url) {
        bput_lenf(any, sizeof any, &ao, 1, (const unsigned char *)type_url, strlen(type_url));
        bput_lenf(any, sizeof any, &ao, 2, inner, io);
    }
    bput_lenf(env, sizeof env, &eo, 1, (const unsigned char *)reqid, strlen(reqid));
    bput_varf(env, sizeof env, &eo, 2, verb);
    bput_lenf(env, sizeof env, &eo, 3, (const unsigned char *)path, strlen(path));
    bput_lenf(env, sizeof env, &eo, 4, (const unsigned char *)origin, strlen(origin));
    if (type_url) bput_lenf(env, sizeof env, &eo, 6, any, ao);
    bput(out, outcap, &fo, 0); bput(out, outcap, &fo, 0); bput(out, outcap, &fo, 0); bput(out, outcap, &fo, 8);
    bput_bytes(out, outcap, &fo, (const unsigned char *)"protobuf", 8);
    bput(out, outcap, &fo, (unsigned char)(eo >> 24)); bput(out, outcap, &fo, (unsigned char)(eo >> 16));
    bput(out, outcap, &fo, (unsigned char)(eo >> 8));  bput(out, outcap, &fo, (unsigned char)eo);
    bput_bytes(out, outcap, &fo, env, eo);
    return fo;
}

static size_t unhex(const char *s, unsigned char *out, size_t outcap)
{
    size_t i = 0, j = 0;
    for (;;) {
        int hi, lo;
        while (s[i] && hexv((unsigned char)s[i]) < 0) i++;
        if (!s[i]) break; hi = hexv((unsigned char)s[i++]);
        while (s[i] && hexv((unsigned char)s[i]) < 0) i++;
        if (!s[i]) break; lo = hexv((unsigned char)s[i++]);
        if (j < outcap) out[j++] = (unsigned char)((hi << 4) | lo);
    }
    return j;
}

static int mode_craft(const char *reqid, const char *verbs, const char *path, const char *origin,
                      const char *type_url, const char *arg, const char *argraw, const char *outfile)
{
    static unsigned char frame[65536], rawbuf[16384];
    const unsigned char *ap = NULL; size_t al = 0, fl;
    uint64_t verb = (uint64_t)strtoull(verbs ? verbs : "1", NULL, 0);
    if (!path) { fprintf(stderr, "craft: --path <topic> is required\n"); return 1; }
    if (argraw) { al = unhex(argraw, rawbuf, sizeof rawbuf); ap = rawbuf; }
    else if (arg) { ap = (const unsigned char *)arg; al = strlen(arg); }
    fl = build_kiros(reqid ? reqid : "9999", verb, path, origin ? origin : "backend",
                     type_url, ap, al, frame, sizeof frame);
    if (fl > sizeof frame) { fprintf(stderr, "craft: frame too large\n"); return 1; }
    printf("[*] crafted %zu-byte kiros frame  path=%s verb=%llu%s\n",
           fl, path, (unsigned long long)verb, type_url ? "" : "  (no Any payload)");
    if (outfile) {
        FILE *f = fopen(outfile, "wb");
        if (!f) { fprintf(stderr, "craft: cannot write %s\n", outfile); return 1; }
        fwrite(frame, 1, fl, f); fclose(f);
        printf("[+] wrote %s  (feed to: fifofox send <pipe> --authorized --data %s --frame raw,\n"
               "    or to the signed relay's trigger file for the SYSTEM updater)\n", outfile, outfile);
    }
    printf("[*] self-check decode:\n");
    frame_dissect(stdout, frame, fl);
    return 0;
}

static int mode_send(const char *name, enum frame_kind fr, int nl,
                     const unsigned char *msg, size_t mlen, unsigned readms)
{
    char path[512];
    HANDLE h;
    unsigned char *wire;
    static unsigned char resp[65536];
    size_t wcap, wlen, rtot = 0;
    DWORD written = 0, waited = 0;

    make_pipe_path(name, path, sizeof(path));
    vrb("send: connecting %s\n", path);
    h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeA(path, 2000))
        h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) { winerr("connect pipe", GetLastError()); return 1; }

    wcap = mlen + 16;
    wire = (unsigned char *)malloc(wcap);
    if (!wire) { CloseHandle(h); return 1; }
    wlen = frame_payload(fr, "", msg, mlen, (DWORD)-1, wire, wcap);
    if (nl && wlen < wcap) wire[wlen++] = '\n';

    printf("[*] sending %zu bytes (frame=%d nl=%d) to %s\n", wlen, (int)fr, nl, path);
    if (g_debug) { size_t i; printf("  wire: "); for (i = 0; i < wlen && i < 64; ++i) printf("%02x", wire[i]); printf("\n"); }

    if (!WriteFile(h, wire, (DWORD)wlen, &written, NULL)) {
        winerr("WriteFile", GetLastError());
        CloseHandle(h); free(wire); return 1;
    }

    Sleep(60);
    while (waited < readms && rtot < sizeof(resp)) {
        DWORD avail = 0, rd = 0;
        if (PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL) && avail) {
            DWORD want = (avail > (DWORD)(sizeof(resp) - rtot)) ? (DWORD)(sizeof(resp) - rtot) : avail;
            if (ReadFile(h, resp + rtot, want, &rd, NULL) && rd) rtot += rd;
            else break;
        } else { Sleep(50); waited += 50; }
    }

    if (rtot) {
        printf("[*] reply %zu bytes:\n", rtot); dump_hex_ascii(resp, rtot);
        if (g_decode) { printf("[*] decoded reply:\n"); dissect_auto(stdout, resp, rtot); }
    }
    else       printf("[*] no reply within %u ms (wrong framing/schema, or one-way topic)\n", readms);

    CloseHandle(h); free(wire);
    return 0;
}

static void relay_session(HANDLE cli, HANDLE up, FILE *log, FILE *corpus,
                          unsigned long *c2s_frames)
{
    unsigned char buf[8192];
    for (;;) {
        DWORD avail = 0, rd = 0, wr = 0;
        int did = 0;

        if (PeekNamedPipe(cli, NULL, 0, NULL, &avail, NULL) && avail) {
            DWORD want = avail > sizeof(buf) ? (DWORD)sizeof(buf) : avail;
            if (ReadFile(cli, buf, want, &rd, NULL) && rd) {
                fprintf(log, "C2S %lu: ", (unsigned long)rd);
                hexdump_line(log, buf, rd, 64);
                fprintf(log, "\n");
                if (g_decode) { fprintf(log, "  [C2S decode]\n"); dissect_auto(log, buf, rd); }
                if (corpus) {
                    uint32_t l = (uint32_t)rd;
                    fwrite(&l, 4, 1, corpus);
                    fwrite(buf, 1, rd, corpus);
                    fflush(corpus);
                }
                (*c2s_frames)++;
                if (!WriteFile(up, buf, rd, &wr, NULL)) break;
                did = 1;
            } else break;
        }

        if (PeekNamedPipe(up, NULL, 0, NULL, &avail, NULL) && avail) {
            DWORD want = avail > sizeof(buf) ? (DWORD)sizeof(buf) : avail;
            if (ReadFile(up, buf, want, &rd, NULL) && rd) {
                fprintf(log, "S2C %lu: ", (unsigned long)rd);
                hexdump_line(log, buf, rd, 64);
                fprintf(log, "\n");
                if (g_decode) { fprintf(log, "  [S2C decode]\n"); dissect_auto(log, buf, rd); }
                if (!WriteFile(cli, buf, rd, &wr, NULL)) break;
                did = 1;
            } else break;
        }

        fflush(log);
        if (!did) {
            DWORD e;
            if (!PeekNamedPipe(cli, NULL, 0, NULL, NULL, NULL)) {
                e = GetLastError();
                if (e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_NOT_CONNECTED) break;
            }
            if (!PeekNamedPipe(up, NULL, 0, NULL, NULL, NULL)) {
                e = GetLastError();
                if (e == ERROR_BROKEN_PIPE || e == ERROR_PIPE_NOT_CONNECTED) break;
            }
            Sleep(1);
        }
    }
}

static int mode_capture(const char *name, int count)
{
    char path[512];
    char logname[64], corpusname[64];
    FILE *log, *corpus;
    time_t t = time(NULL);
    int session;
    unsigned long total_c2s = 0;

    make_pipe_path(name, path, sizeof(path));
    snprintf(logname,    sizeof(logname),    "fifofox_capture_%lld.log", (long long)t);
    snprintf(corpusname, sizeof(corpusname), "fifofox_corpus_%lld.bin",  (long long)t);

    printf("[*] CAPTURE (instance-interception relay) on %s\n", path);
    printf("    NOTE: intrusive + EDR-visible. Only works if the real server did\n");
    printf("    NOT use FILE_FLAG_FIRST_PIPE_INSTANCE (run 'audit' first).\n\n");

    log    = fopen(logname, "w");
    corpus = fopen(corpusname, "wb");
    if (!log || !corpus) { fprintf(stderr, "log/corpus open failed\n"); return 1; }

    for (session = 0; session < count; ++session) {
        HANDLE hServer, hUp;
        DWORD e;

        hServer = CreateNamedPipeA(path, PIPE_ACCESS_DUPLEX,
                                   PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                   PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, NULL);
        if (hServer == INVALID_HANDLE_VALUE) {
            e = GetLastError();
            if (e == ERROR_ACCESS_DENIED)
                printf("[X] CreateNamedPipe denied -> server owns the name with\n"
                       "    FILE_FLAG_FIRST_PIPE_INSTANCE. Interception not possible\n"
                       "    (this is the secure configuration).\n");
            else
                winerr("CreateNamedPipe (relay instance)", e);
            break;
        }

        printf("[*] session %d: waiting for a victim client to land on our instance...\n",
               session);
        if (!ConnectNamedPipe(hServer, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
            winerr("ConnectNamedPipe", GetLastError());
            CloseHandle(hServer);
            break;
        }

        { DWORD cpid = 0;
          if (GetNamedPipeClientProcessId(hServer, &cpid))
              print_proc_image(cpid, "  intercepted client"); }

        hUp = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                          OPEN_EXISTING, 0, NULL);
        if (hUp == INVALID_HANDLE_VALUE && GetLastError() == ERROR_PIPE_BUSY) {
            if (WaitNamedPipeA(path, 2000))
                hUp = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_EXISTING, 0, NULL);
        }
        if (hUp == INVALID_HANDLE_VALUE) {
            winerr("connect upstream (real server)", GetLastError());
            DisconnectNamedPipe(hServer);
            CloseHandle(hServer);
            continue;
        }

        printf("[*] session %d: relaying (logging both directions)...\n", session);
        relay_session(hServer, hUp, log, corpus, &total_c2s);

        DisconnectNamedPipe(hServer);
        CloseHandle(hServer);
        CloseHandle(hUp);
        printf("[*] session %d ended (%lu client->server frames so far)\n",
               session, total_c2s);
    }

    fclose(log);
    fclose(corpus);
    printf("\n[*] Capture done. Transcript: %s   Corpus: %s (%lu frames)\n",
           logname, corpusname, total_c2s);
    printf("    Feed it back in:  fifofox fuzz %s --authorized --corpus %s\n",
           name, corpusname);
    return 0;
}

static int mode_squat(const char *name, int impersonate, int timeout_sec)
{
    char path[512];
    HANDLE pipe, ev;
    OVERLAPPED ov;
    int connected = 0;
    make_pipe_path(name, path, sizeof(path));

    printf("[*] SQUAT PoC on %s\n", path);
    printf("    NOTE: this is a noisy, EDR-detected technique. Authorized use only.\n\n");

    pipe = CreateNamedPipeA(path,
                            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED || e == ERROR_PIPE_BUSY || e == ERROR_ALREADY_EXISTS)
            printf("  [-] Cannot squat: name already owned (err %lu). The legitimate\n"
                   "      server holds it (good - FIRST_PIPE_INSTANCE / live instance).\n",
                   (unsigned long)e);
        else
            winerr("CreateNamedPipe", e);
        return 1;
    }

    ev = CreateEventA(NULL, TRUE, FALSE, NULL);
    if (!ev) { winerr("CreateEvent", GetLastError()); CloseHandle(pipe); return 1; }
    memset(&ov, 0, sizeof(ov));
    ov.hEvent = ev;

    if (timeout_sec > 0)
        printf("  [+] Squatted the name. Waiting up to %ds for a client to connect.\n"
               "      Trigger the real client now (e.g. start the service); Ctrl+C to abort.\n",
               timeout_sec);
    else
        printf("  [+] Squatted the name. Waiting (no timeout) for a client to connect.\n"
               "      Trigger the real client now (e.g. start the service); Ctrl+C to abort.\n");

    if (ConnectNamedPipe(pipe, &ov)) {
        connected = 1;
    } else {
        DWORD e = GetLastError();
        if (e == ERROR_PIPE_CONNECTED) {
            connected = 1;
        } else if (e == ERROR_IO_PENDING) {
            DWORD ms = (timeout_sec > 0) ? (DWORD)timeout_sec * 1000u : INFINITE;
            DWORD w  = WaitForSingleObject(ev, ms);
            if (w == WAIT_OBJECT_0) {
                DWORD nb = 0;
                connected = GetOverlappedResult(pipe, &ov, &nb, FALSE) ? 1 : 0;
            } else if (w == WAIT_TIMEOUT) {
                printf("  [-] No client connected within %ds - nothing to impersonate.\n"
                       "      Squatting only yields a token when a (privileged) client\n"
                       "      actually connects. Trigger the client, then re-run.\n",
                       timeout_sec);
                CancelIoEx(pipe, &ov);
            } else {
                winerr("WaitForSingleObject", GetLastError());
                CancelIoEx(pipe, &ov);
            }
        } else {
            winerr("ConnectNamedPipe", e);
        }
    }

    if (!connected) { CloseHandle(ev); CloseHandle(pipe); return 1; }
    printf("  [+] Client connected.\n");

    {
        DWORD cpid = 0;
        if (GetNamedPipeClientProcessId(pipe, &cpid))
            print_proc_image(cpid, "connecting client");
    }

    if (impersonate) {
        printf("\n  --- impersonation ---\n");
        if (!ImpersonateNamedPipeClient(pipe)) {
            winerr("ImpersonateNamedPipeClient", GetLastError());
        } else {
            HANDLE tok = NULL;
            if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &tok)) {
                printf("  [+] Impersonating client. Token identity:\n");
                print_token_identity(tok, "  impersonated");
                printf("  -> If this shows a privileged user (SYSTEM/High) and you hold\n");
                printf("     SeImpersonatePrivilege, this token can be leveraged for EoP.\n");
                CloseHandle(tok);
            } else {
                winerr("OpenThreadToken", GetLastError());
            }
            RevertToSelf();
        }
    } else {
        printf("  (run with --impersonate to assume the connecting client's token)\n");
    }

    DisconnectNamedPipe(pipe);
    CloseHandle(ev);
    CloseHandle(pipe);
    return 0;
}

static void banner(void)
{
    fprintf(stderr,
        "%s"
        "  ____ _ ____ ____ ____ ____ _  _\n"
        "  |___ | |___ |  | |___ |  |  \\/ \n"
        "  |    | |    |__| |    |__| _/\\_%s\n"
        "  %sFIFOFox v%s - Windows named-pipe security auditor and fuzzer\n"
        "  Zero Science Lab - https://zeroscience.mk - @zeroscience%s\n\n",
        CC(A_MAG), CC(A_RESET), CC(A_GRY), FIFOFOX_VERSION, CC(A_RESET));
}

static void usage(const char *argv0)
{
    printf(
        "Usage:\n"
        "  %s enum    [--all] [--squat] [--html <file>]\n"
        "  %s listeners [--all]   (loopback/wildcard TCP IPC endpoints + owner/privilege)\n"
        "  %s audit   <pipe> [--html <file>]\n"
        "  %s capture <pipe> --authorized [--count N]\n"
        "  %s fuzz    <pipe> --authorized [options]\n"
        "  %s squat   <pipe> --authorized [--impersonate] [--timeout <sec>]\n"
        "  %s send    <pipe> --authorized (--str|--json <txt>|--data <f>) [--frame F] [--nl]\n"
        "  %s decode  <file> [--corpus]  |  decode --hex <hexbytes>\n"
        "  %s craft   --path <topic> [--type <type_url> --arg <s>] [--out <f>]\n"
        "  %s version | help\n\n"
        "<pipe> = bare name (e.g. cowork-vm-service) or full \\\\.\\pipe\\name\n\n"
        "global flags (any position):\n"
        "  -v, --verbose   narrate each step to stderr\n"
        "      --debug     verbose + handles, error codes, per-iteration detail\n"
        "      --color     force ANSI color (default: auto; off when redirected)\n"
        "      --no-color  disable ANSI color\n"
        "      --no-banner suppress the startup banner\n"
        "      --no-decode (alias --raw) print raw hex only; skip protobuf dissection\n"
        "      --no-service  audit: skip the owning-service / unquoted-path / dir-ACL check\n"
        "      --peek        audit: passively read any unsolicited server data and detect its format\n"
        "      --format <f>  force the payload dissector for decode/send/capture:\n"
        "                    auto (default) | protobuf | dcerpc | dotnet | json | xml | asn1 | text | hex\n\n"
        "enum options:\n"
        "  --all           include readable OK pipes and unreadable ones, not just flagged\n"
        "  --squat         active probe: also flag squattable pipes as DANGER\n"
        "  --html <file>   also write a standalone HTML security-overview report\n\n"
        "capture: instance-interception relay; records both directions and writes\n"
        "  a client->server corpus (.bin) for fuzz reuse. Needs the server to lack\n"
        "  FILE_FLAG_FIRST_PIPE_INSTANCE (check with 'audit').\n\n"
        "fuzz options:\n"
        "  --frame  raw|len16le|len16be|len32le|len32be|cmd   (default raw)\n"
        "  --cmd    <prefix>   command prefix for --frame cmd   (default \"3 \")\n"
        "  --corpus <file>     seed mutations from a capture corpus; format-aware (keeps\n"
        "                      protobuf/DCE-RPC frames valid and fuzzes the inner fields/stub)\n"
        "  --iters  <N>        number of test cases             (default 500)\n"
        "  --seed   <hex|dec>  PRNG seed for reproducible runs  (default fixed)\n"
        "  --maxlen <N>        max random payload length        (default 4096)\n"
        "  --delay  <ms>       inter-iteration delay            (default 15)\n\n"
        "send options (precise delivery / framing probe):\n"
        "  --str <t> | --json <t> | --data <f>   message body (pick one)\n"
        "  --frame raw|len16le|len16be|len32le|len32be   length framing (default raw)\n"
        "  --nl                append a newline (line-delimited protocols)\n"
        "  --read <ms>         wait this long for a reply        (default 1500)\n"
        "  (replies are auto-dissected: framing + protobuf field tree; --raw to disable)\n\n"
        "decode: offline protocol dissection of captured bytes (no connection).\n"
        "  AUTO-DETECTS the payload format and routes to the right dissector:\n"
        "    protobuf/kiros (field tree + Any{}), DCE/RPC (header + interface UUID + opnum),\n"
        "    .NET serialization (flagged as unsafe-deserialization candidate), JSON, XML,\n"
        "    ASN.1/DER, text, or hex. Override with --format <f>.\n"
        "  <file>          a single captured frame (e.g. trigger_reinstall.bin)\n"
        "  --corpus        <file> is a capture corpus ([u32le len][frame] records)\n"
        "  --hex <bytes>   decode an inline hex string instead of a file\n\n"
        "craft: build a Logitech 'kiros' request frame (and send it with send --kiros).\n"
        "  --path <topic>  route, e.g. /updates/depot/info            (required)\n"
        "  --type <url>    google.protobuf.Any type_url (the typed request message)\n"
        "  --arg <text>    the request message's f1 string (e.g. a depot name)\n"
        "  --argraw <hex>  raw bytes for the Any value instead of --arg\n"
        "  --verb <n>      message verb (default 1=request)\n"
        "  --reqid <s> --origin <s>   envelope msg_id (default 9999) / origin (backend)\n"
        "  --out <file>    write the frame (feed to send --data or the signed relay)\n"
        "  send --kiros <same flags>  builds the frame and delivers it in one step\n\n"
        "Examples:\n"
        "  %s enum --all --html report.html\n"
        "  %s audit cowork-vm-service --html pipe.html\n"
        "  %s capture cowork-vm-service --authorized --count 5\n"
        "  %s fuzz cowork-vm-service --authorized --corpus fifofox_corpus_123.bin -v\n"
        "  %s send logitech_kiros_updater --authorized --str /updates/channel --frame len32le\n"
        "  %s decode trigger_reinstall.bin\n"
        "  %s send logitech_kiros_agent-<id> --authorized --kiros --path /updates/depot/info \\\n"
        "       --type type.googleapis.com/logi.protocol.updates.Depot.Info --arg logioptionsplus\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0,
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

static int has_flag(int argc, char **argv, const char *flag)
{
    int i;
    for (i = 2; i < argc; ++i) if (!strcmp(argv[i], flag)) return 1;
    return 0;
}

static const char *opt_val(int argc, char **argv, const char *flag, const char *def)
{
    int i;
    for (i = 2; i < argc - 1; ++i) if (!strcmp(argv[i], flag)) return argv[i + 1];
    return def;
}

#pragma comment(lib, "iphlpapi.lib")
typedef struct { DWORD st, la, lp, ra, rp, pid; } FFX_TCPROW;
typedef struct { DWORD n; FFX_TCPROW t[1]; }       FFX_TCPTBL;
typedef struct { UCHAR la[16]; DWORD lsid, lp; UCHAR ra[16]; DWORD rsid, rp, st, pid; } FFX_TCP6ROW;
typedef struct { DWORD n; FFX_TCP6ROW t[1]; }      FFX_TCP6TBL;
DWORD WINAPI GetExtendedTcpTable(PVOID, PDWORD, BOOL, ULONG, int, ULONG);
#define FFX_LISTENER_CLASS 3
#define FFX_STATE_LISTEN   2

static int ci_contains(const char *hay, const char *needle)
{
    size_t hl = strlen(hay), nl = strlen(needle), i, j;
    if (nl == 0) return 1; if (nl > hl) return 0;
    for (i = 0; i + nl <= hl; ++i) { int ok = 1;
        for (j = 0; j < nl; ++j) { char a = hay[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a += 32; if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) { ok = 0; break; } }
        if (ok) return 1; }
    return 0;
}

static void pid_name(DWORD pid, char *out, size_t cap)
{
    HANDLE s; PROCESSENTRY32 pe; pe.dwSize = sizeof pe;
    snprintf(out, cap, "(pid %lu)", (unsigned long)pid);
    s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE) return;
    if (Process32First(s, &pe)) do { if (pe.th32ProcessID == pid) { snprintf(out, cap, "%s", pe.szExeFile); break; } }
        while (Process32Next(s, &pe));
    CloseHandle(s);
}

static void proc_owner(DWORD pid, char *out, size_t cap)
{
    char svc[256], disp[256], image[1024], acct[256]; int shared; HANDLE p, tok;
    out[0] = 0;
    if (svc_find_by_pid(pid, svc, sizeof svc, disp, sizeof disp, &shared)
        && svc_query_config(svc, image, sizeof image, acct, sizeof acct) && acct[0]) {
        snprintf(out, cap, "%s [svc:%s]", acct, svc); return;
    }
    p = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!p) p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (p) {
        if (OpenProcessToken(p, TOKEN_QUERY, &tok)) {
            DWORD len = 0; GetTokenInformation(tok, TokenUser, NULL, 0, &len);
            if (len) { TOKEN_USER *tu = (TOKEN_USER *)malloc(len);
                if (tu && GetTokenInformation(tok, TokenUser, tu, len, &len)) {
                    char nm[256], dm[256]; DWORD nl = sizeof nm, dl = sizeof dm; SID_NAME_USE use;
                    if (LookupAccountSidA(NULL, tu->User.Sid, nm, &nl, dm, &dl, &use)) snprintf(out, cap, "%s\\%s", dm, nm);
                    else { char *ss = NULL; if (ConvertSidToStringSidA(tu->User.Sid, &ss)) { snprintf(out, cap, "%s", ss); LocalFree(ss); } }
                }
                free(tu); }
            CloseHandle(tok);
        }
        CloseHandle(p);
    }
    if (!out[0]) snprintf(out, cap, "(owner not resolvable - higher IL)");
}

static int listener_grade(const char *owner)
{
    if (ci_contains(owner, "system")) return 2;
    if (ci_contains(owner, "local service") || ci_contains(owner, "network service") ||
        ci_contains(owner, "localservice") || ci_contains(owner, "networkservice")) return 1;
    return 0;
}

static void listener_row(const char *endpoint, const char *scope, DWORD pid,
                         int *danger, int *warn, int *okc)
{
    char pname[MAX_PATH] = "", owner[400] = ""; int g; const char *sev;
    pid_name(pid, pname, sizeof pname);
    proc_owner(pid, owner, sizeof owner);
    g = listener_grade(owner);
    if (g >= 2) (*danger)++; else if (g == 1) (*warn)++; else (*okc)++;
    sev = g >= 2 ? "DANGER" : (g == 1 ? " WARN " : "  ok  ");
    printf("[%s%s%s] %s%-22s%s %s(%s)%s  %sPID %-6lu%s %-26s  owner: %s%s%s\n",
           CC(sev_ansi(g)), sev, CC(A_RESET), CC(A_BOLD), endpoint, CC(A_RESET),
           CC(A_GRY), scope, CC(A_RESET), CC(A_GRY), (unsigned long)pid, CC(A_RESET),
           pname, CC(g >= 2 ? A_RED : A_RESET), owner, CC(A_RESET));
}

static int mode_listeners(int show_all)
{
    DWORD sz = 0, i; int danger = 0, warn = 0, okc = 0, total = 0;
    printf("[*] Enumerating local TCP listeners ...\n\n");

    GetExtendedTcpTable(NULL, &sz, FALSE, 2, FFX_LISTENER_CLASS, 0);
    if (sz) {
        FFX_TCPTBL *t = (FFX_TCPTBL *)malloc(sz);
        if (t && GetExtendedTcpTable(t, &sz, FALSE, 2, FFX_LISTENER_CLASS, 0) == 0) {
            for (i = 0; i < t->n; ++i) {
                DWORD a = t->t[i].la; unsigned port; char ep[48]; int loop, wild;
                if (t->t[i].st != FFX_STATE_LISTEN) continue;
                loop = (a == 0x0100007F); wild = (a == 0);
                if (!loop && !wild && !show_all) continue;
                total++;
                port = ((t->t[i].lp & 0xff) << 8) | ((t->t[i].lp >> 8) & 0xff);
                snprintf(ep, sizeof ep, "%lu.%lu.%lu.%lu:%u",
                         (unsigned long)(a & 0xff), (unsigned long)((a >> 8) & 0xff),
                         (unsigned long)((a >> 16) & 0xff), (unsigned long)((a >> 24) & 0xff), port);
                listener_row(ep, loop ? "loopback" : (wild ? "all-ifaces" : "iface"), t->t[i].pid, &danger, &warn, &okc);
            }
        }
        free(t);
    }

    sz = 0; GetExtendedTcpTable(NULL, &sz, FALSE, 23, FFX_LISTENER_CLASS, 0);
    if (sz) {
        FFX_TCP6TBL *t = (FFX_TCP6TBL *)malloc(sz);
        if (t && GetExtendedTcpTable(t, &sz, FALSE, 23, FFX_LISTENER_CLASS, 0) == 0) {
            for (i = 0; i < t->n; ++i) {
                const UCHAR *a = t->t[i].la; unsigned port; char ep[48]; int j, zero = 1, loop, wild;
                if (t->t[i].st != FFX_STATE_LISTEN) continue;
                for (j = 0; j < 15; ++j) if (a[j]) { zero = 0; break; }
                loop = (zero && a[15] == 1); wild = (zero && a[15] == 0);
                if (!loop && !wild && !show_all) continue;
                total++;
                port = ((t->t[i].lp & 0xff) << 8) | ((t->t[i].lp >> 8) & 0xff);
                snprintf(ep, sizeof ep, "[%s]:%u", loop ? "::1" : (wild ? "::" : "v6"), port);
                listener_row(ep, loop ? "loopback" : (wild ? "all-ifaces" : "iface"), t->t[i].pid, &danger, &warn, &okc);
            }
        }
        free(t);
    }

    printf("\n------------------------------------------------------------\n");
    printf("[*] %d listener(s): %s%d danger%s, %s%d warn%s, %s%d ok%s%s\n", total,
           CC(A_RED), danger, CC(A_RESET), CC(A_YEL), warn, CC(A_RESET),
           CC(A_GRN), okc, CC(A_RESET), show_all ? "" : "  (loopback/wildcard only; --all for every interface)");
    print_legend();
    printf("    Note: ANY local user can connect to a loopback/wildcard listener - TCP has no\n");
    printf("    DACL. The risk is the OWNER's privilege: a SYSTEM-owned listener is a privileged\n");
    printf("    local-IPC endpoint (the auto-updater surface). Probe its protocol with a client.\n");
    return 0;
}

int main(int argc, char **argv)
{
    int i;
    int no_banner = 0;

    {
        int color_want = 0;
        for (i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v")) g_verbose = 1;
            else if (!strcmp(argv[i], "--debug")) { g_debug = 1; g_verbose = 1; }
            else if (!strcmp(argv[i], "--color")) color_want = 1;
            else if (!strcmp(argv[i], "--no-color")) color_want = -1;
            else if (!strcmp(argv[i], "--no-banner")) no_banner = 1;
            else if (!strcmp(argv[i], "--no-decode") || !strcmp(argv[i], "--raw")) g_decode = 0;
            else if (!strcmp(argv[i], "--no-service")) g_no_service = 1;
            else if (!strcmp(argv[i], "--peek")) g_peek = 1;
            else if (!strcmp(argv[i], "--format") && i + 1 < argc) g_force_fmt = parse_fmt(argv[i + 1]);
        }
        enable_color(color_want);
    }
    if (!no_banner) banner();

    if (argc < 2 ||
        !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "help")) {
        usage(argv[0]);
        return (argc < 2) ? 1 : 0;
    }
    if (!strcmp(argv[1], "--version") || !strcmp(argv[1], "version")) {
        printf("FIFOFox %s\n", FIFOFOX_VERSION);
        return 0;
    }

    vrb("FIFOFox %s  mode=%s\n", FIFOFOX_VERSION, argv[1]);

    if (!strcmp(argv[1], "enum"))
        return mode_enum(has_flag(argc, argv, "--all"),
                         has_flag(argc, argv, "--squat"),
                         opt_val(argc, argv, "--html", NULL));

    if (!strcmp(argv[1], "listeners") || !strcmp(argv[1], "tcp"))
        return mode_listeners(has_flag(argc, argv, "--all"));

    if (!strcmp(argv[1], "audit")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        return mode_audit(argv[2], opt_val(argc, argv, "--html", NULL));
    }

    if (!strcmp(argv[1], "fuzz")) {
        enum frame_kind fr;
        const char *cmd, *frs;
        unsigned iters, maxlen, delay;
        uint64_t seed;
        if (argc < 3) { usage(argv[0]); return 1; }
        if (!has_flag(argc, argv, "--authorized")) {
            fprintf(stderr, "[X] fuzz requires --authorized (you affirm you have perms).\n");
            return 2;
        }
        frs    = opt_val(argc, argv, "--frame", "raw");
        cmd    = opt_val(argc, argv, "--cmd", "3 ");
        iters  = (unsigned)strtoul(opt_val(argc, argv, "--iters", "500"), NULL, 0);
        maxlen = (unsigned)strtoul(opt_val(argc, argv, "--maxlen", "4096"), NULL, 0);
        delay  = (unsigned)strtoul(opt_val(argc, argv, "--delay", "15"), NULL, 0);
        seed   = (uint64_t)strtoull(opt_val(argc, argv, "--seed", "0"), NULL, 0);
        fr     = parse_frame(frs);
        {
            const char *corpusf = opt_val(argc, argv, "--corpus", NULL);
            if (corpusf) {
                int n = load_corpus(corpusf);
                if (n > 0) {
                    printf("[*] Loaded %d corpus frames from %s (structure-aware mode)\n", n, corpusf);
                    if (g_corpus_n > 0)
                        printf("[*] corpus payload format (frame 0): %s%s\n",
                               fmt_name(detect_fmt(g_corpus[0], g_corpus_len[0])),
                               g_force_fmt != -1 ? " (overridden by --format)" : "");
                }
                else fprintf(stderr, "[!] --corpus %s: no records loaded, falling back to blind fuzzing\n",
                             corpusf);
            }
        }
        return mode_fuzz(argv[2], fr, cmd, iters, seed, maxlen, delay);
    }

    if (!strcmp(argv[1], "send")) {
        enum frame_kind fr;
        const char *dataf, *str, *json;
        int nl, r;
        unsigned readms;
        const unsigned char *m;
        size_t mlen = 0;
        unsigned char *fb = NULL;
        if (argc < 3) { usage(argv[0]); return 1; }
        if (!has_flag(argc, argv, "--authorized")) {
            fprintf(stderr, "[X] send requires --authorized (you affirm you have permission).\n");
            return 2;
        }
        fr     = parse_frame(opt_val(argc, argv, "--frame", "raw"));
        nl     = has_flag(argc, argv, "--nl");
        readms = (unsigned)strtoul(opt_val(argc, argv, "--read", "1500"), NULL, 0);
        if (has_flag(argc, argv, "--kiros")) {
            static unsigned char kbuf[65536], kraw[16384];
            const char *kpath = opt_val(argc, argv, "--path", NULL);
            const char *ktype = opt_val(argc, argv, "--type", NULL);
            const char *karg  = opt_val(argc, argv, "--arg", NULL);
            const char *kargr = opt_val(argc, argv, "--argraw", NULL);
            const unsigned char *ap = NULL; size_t al = 0, kl;
            if (!kpath) { fprintf(stderr, "send --kiros: --path <topic> required\n"); return 1; }
            if (kargr)      { al = unhex(kargr, kraw, sizeof kraw); ap = kraw; }
            else if (karg)  { ap = (const unsigned char *)karg; al = strlen(karg); }
            kl = build_kiros(opt_val(argc, argv, "--reqid", "9999"),
                             (uint64_t)strtoull(opt_val(argc, argv, "--verb", "1"), NULL, 0),
                             kpath, opt_val(argc, argv, "--origin", "backend"),
                             ktype, ap, al, kbuf, sizeof kbuf);
            m = kbuf; mlen = kl; fr = FR_RAW;
            printf("[*] kiros frame: %zu bytes  path=%s\n", mlen, kpath);
        } else {
            dataf  = opt_val(argc, argv, "--data", NULL);
            json   = opt_val(argc, argv, "--json", NULL);
            str    = opt_val(argc, argv, "--str", NULL);
            if (dataf)     { fb = read_file(dataf, &mlen); if (!fb) { fprintf(stderr, "cannot read %s\n", dataf); return 1; } m = fb; }
            else if (json) { m = (const unsigned char *)json; mlen = strlen(json); }
            else if (str)  { m = (const unsigned char *)str;  mlen = strlen(str);  }
            else { fprintf(stderr, "send: need --kiros --path ... | --data <file> | --str <text> | --json <text>\n"); return 1; }
        }
        r = mode_send(argv[2], fr, nl, m, mlen, readms);
        if (fb) free(fb);
        return r;
    }

    if (!strcmp(argv[1], "capture")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        if (!has_flag(argc, argv, "--authorized")) {
            fprintf(stderr, "[X] capture requires --authorized (you affirm you have perms).\n");
            return 2;
        }
        return mode_capture(argv[2],
                            (int)strtoul(opt_val(argc, argv, "--count", "1"), NULL, 0));
    }

    if (!strcmp(argv[1], "decode")) {
        const char *hex = opt_val(argc, argv, "--hex", NULL);
        if (!hex && argc < 3) { usage(argv[0]); return 1; }
        return mode_decode(hex ? NULL : argv[2], has_flag(argc, argv, "--corpus"), hex);
    }

    if (!strcmp(argv[1], "craft")) {
        return mode_craft(opt_val(argc, argv, "--reqid", NULL),
                          opt_val(argc, argv, "--verb", NULL),
                          opt_val(argc, argv, "--path", NULL),
                          opt_val(argc, argv, "--origin", NULL),
                          opt_val(argc, argv, "--type", NULL),
                          opt_val(argc, argv, "--arg", NULL),
                          opt_val(argc, argv, "--argraw", NULL),
                          opt_val(argc, argv, "--out", NULL));
    }

    if (!strcmp(argv[1], "squat")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        if (!has_flag(argc, argv, "--authorized")) {
            fprintf(stderr, "[X] squat requires --authorized (you affirm you have perms).\n");
            return 2;
        }
        return mode_squat(argv[2], has_flag(argc, argv, "--impersonate"),
                          (int)strtoul(opt_val(argc, argv, "--timeout", "30"), NULL, 0));
    }

    usage(argv[0]);
    return 1;
}
