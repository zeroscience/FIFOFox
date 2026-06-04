/*
 * fifofox.c  -  Windows named-pipe security auditor and fuzzer
 * ----------------------------------------------------------------------------
 * Warning: The fuzz/squat modes can crash services and the squat+impersonate
 * path is exactly the behavior EDR rules (e.g. Elastic "Privilege Escalation
 * via Named Pipe Impersonation") flag.
 *
 * Modes
 *   enum                         List every \\.\pipe\ object, decode its DACL
 *                                to SDDL, and GRADE it (flags low-priv writers
 *                                / object-takeover ACEs / NULL DACLs).
 *   audit  <pipe>                Deep single-pipe report: GetNamedPipeInfo
 *                                flags, server/client PID + image path, SDDL,
 *                                ACE-by-ACE grading, and a live squattability
 *                                test (FILE_FLAG_FIRST_PIPE_INSTANCE).
 *   fuzz   <pipe> --authorized   Connect as a client and send mutated frames
 *                                (raw / length-prefixed / command-prefixed),
 *                                with liveness/crash detection and repro logs.
 *   squat  <pipe> --authorized   Defensive PoC: claim the pipe name first and
 *               [--impersonate]   optionally ImpersonateNamedPipeClient() to
 *                                demonstrate the squat->impersonation risk.
 *
 * <pipe> may be a bare name ("cowork-vm-service") or a full "\\.\pipe\name".
 *
 * Build (MSVC):   cl /W3 /O2 /D_CRT_SECURE_NO_WARNINGS fifofox.c
 * Build (MinGW):  gcc -O2 -Wall -o fifofox.exe fifofox.c -ladvapi32
 *
 * Does NOT require administrator rights: enum/audit/fuzz/capture/squat all run
 * as a standard user against pipes whose DACL grants the caller access (which
 * is exactly the low-priv attack surface you want to assess). Admin only adds
 * visibility (resolving other-user/SYSTEM server image paths, reading
 * restrictive SDs); a service context with SeImpersonatePrivilege is needed
 * only to *weaponize* squat+impersonate into SYSTEM. See the manual.
 *
 * Dependencies: advapi32 (SDDL/ACL/SID/token), kernel32 (pipe APIs). No others.
 * 
 * lqwrm (c) 2026
 * ----------------------------------------------------------------------------
 */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>//
#include <stdlib.h>///
#include <string.h>///
#include <stdint.h>///
#include <aclapi.h>///
#include <stdarg.h>///
#include <stdio.h>////
#include <sddl.h>/////
#include <time.h>/////

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
                               char *find_out, size_t find_cap)
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
"  footer{color:var(--mut);font-size:12px;margin-top:18px;}\n</style></head><body>\n"
"<h1>Named-Pipe Security Report</h1>\n"
"<div class=\"sub\">FIFOFox v%s &middot; host <b>%s</b> &middot; generated %s</div>\n"
"<div class=\"cards\">\n"
"  <div class=\"c\"><div class=\"n\">%d</div><div class=\"l\">Pipes</div></div>\n"
"  <div class=\"c\"><div class=\"n\" style=\"color:#f85149\">%d</div><div class=\"l\">Danger</div></div>\n"
"  <div class=\"c\"><div class=\"n\" style=\"color:#d29922\">%d</div><div class=\"l\">Warn</div></div>\n"
"  <div class=\"c\"><div class=\"n\" style=\"color:#3fb950\">%d</div><div class=\"l\">OK</div></div>\n"
"</div>\n"
"<table>\n<colgroup><col style=\"width:96px\"><col style=\"width:15%%\">"
"<col style=\"width:64px\"><col style=\"width:22%%\"><col style=\"width:32%%\"><col></colgroup>\n"
"<thead><tr><th>Severity</th><th>Pipe</th><th>Server PID</th>"
"<th>Server image</th><th>Findings</th><th>SDDL</th></tr></thead>\n<tbody>\n",
        host, FIFOFOX_VERSION, host, when, total, danger, warn, okc);

    if (rows->p && rows->len) fputs(rows->p, f);
    else fputs("<tr><td colspan=\"6\">No rows (nothing flagged; run with --all to include OK pipes).</td></tr>\n", f);

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
        char path[512], sddl[2048], find_buf[4096];
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
                        "<td>%s</td><td>-</td><td>-</td>"
                        "<td>SD not readable as this user (err %lu)</td>"
                        "<td><code>-</code></td></tr>\n", nesc, (unsigned long)e);
                    shown++;
                }
            }
            continue;
        }

        GetNamedPipeServerProcessId(h, &spid);
        grade = grade_pipe_security(h, show_all, sddl, sizeof(sddl), find_buf, sizeof(find_buf));

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
            printf("[%s%s%s] %s%s%s  %s(server PID %lu)%s\n",
                   CC(sev_ansi(grade)), sev, CC(A_RESET),
                   CC(A_BOLD), fd.cFileName, CC(A_RESET),
                   CC(A_GRY), (unsigned long)spid, CC(A_RESET));
            if (sddl[0])     printf("  %sSDDL:%s %s%s%s\n",
                                    CC(A_GRY), CC(A_RESET), CC(A_CYN), sddl, CC(A_RESET));
            if (find_buf[0]) print_findings_colored(find_buf);
            printf("\n");

            if (want_html) {
                char nesc[1600], sesc[4096], fesc[8192], iesc[1100];
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
                sb_addf(&rows,
                    "<tr class=\"%s\"><td><span class=\"badge %s\">%s</span></td>"
                    "<td>%s</td><td>%lu</td><td class=\"img\">%s</td>"
                    "<td class=\"find\">%s</td><td><code>%s</code></td></tr>\n",
                    cls, cls, lbl, nesc, (unsigned long)spid, iesc, fesc, sesc);
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

        grade = grade_pipe_security(h, 1, sddl, sizeof(sddl), find_buf, sizeof(find_buf));
        CloseHandle(h);
    }

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
    printf("\n");
    print_legend();

    if (htmlpath) {
        struct sbuf rows;
        char combined[5120];
        char nesc[1600], sesc[4096], fesc[8192], iesc[1100];
        int overall = grade > squat_sev ? grade : squat_sev;
        const char *cls = overall >= 2 ? "danger" : (overall == 1 ? "warn" : "ok");
        const char *lbl = overall >= 2 ? "DANGER" : (overall == 1 ? "WARN" : "OK");
        sb_init(&rows);
        combined[0] = 0;
        appendf(combined, sizeof(combined), "%s", find_buf[0] ? find_buf : "(no flagged ACEs)\n");
        appendf(combined, sizeof(combined), "geometry: %s\n", geo[0] ? geo : "(n/a)");
        appendf(combined, sizeof(combined), "squattability: %s\n", squatv[0] ? squatv : "(n/a)");
        html_escape(name, nesc, sizeof(nesc));
        html_escape(sddl[0] ? sddl : "-", sesc, sizeof(sesc));
        html_escape(combined, fesc, sizeof(fesc));
        html_escape(simg, iesc, sizeof(iesc));
        sb_addf(&rows,
            "<tr class=\"%s\"><td><span class=\"badge %s\">%s</span></td>"
            "<td>%s</td><td>%lu</td><td class=\"img\">%s</td>"
            "<td class=\"find\">%s</td><td><code>%s</code></td></tr>\n",
            cls, cls, lbl, nesc, (unsigned long)spid, iesc, fesc, sesc);
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

static size_t gen_payload(unsigned iter, unsigned maxlen, unsigned char *buf,
                          size_t bufcap, const char **desc, DWORD *lenlie)
{
    unsigned strat = iter % 7;
    size_t n = 0;
    *lenlie = (DWORD)-1;

    if (g_corpus_n > 0 && rng_u(100) < 65) {
        int idx = (int)rng_u((unsigned)g_corpus_n);
        size_t cl = g_corpus_len[idx];
        unsigned flips, k;
        if (cl > bufcap) cl = bufcap;
        memcpy(buf, g_corpus[idx], cl);
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

//Frame the payload into the wire buffer. Returns total bytes to send.
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

//squatting
static int mode_squat(const char *name, int impersonate)
{
    char path[512];
    HANDLE pipe;
    make_pipe_path(name, path, sizeof(path));

    printf("[*] SQUAT PoC on %s\n", path);
    printf("    NOTE: this is a noisy, EDR-detected technique. Authorized use only.\n\n");

    pipe = CreateNamedPipeA(path,
                            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                            PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, NULL);
    if (pipe == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        if (e == ERROR_ACCESS_DENIED || e == ERROR_PIPE_BUSY || e == ERROR_ALREADY_EXISTS)
            printf("  [-] Cannot squat: name already owned (err %lu). The legitimate\n"
                   "      server got there first (good - FIRST_PIPE_INSTANCE works).\n",
                   (unsigned long)e);
        else
            winerr("CreateNamedPipe", e);
        return 1;
    }

    printf("  [+] Squatted the name. Waiting up to 30s for a client to connect...\n");
    if (!ConnectNamedPipe(pipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        winerr("ConnectNamedPipe", GetLastError());
        CloseHandle(pipe);
        return 1;
    }
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
        "  %sFIFOFox v%s  - Windows named-pipe security auditor and fuzzer\n"
        "  Zero Science Lab - https://zeroscience.mk - @zeroscience%s\n\n",
        CC(A_MAG), CC(A_RESET), CC(A_GRY), FIFOFOX_VERSION, CC(A_RESET));
}

static void usage(const char *argv0)
{
    printf(
        "Usage:\n"
        "  %s enum    [--all] [--squat] [--html <file>]\n"
        "  %s audit   <pipe> [--html <file>]\n"
        "  %s capture <pipe> --authorized [--count N]\n"
        "  %s fuzz    <pipe> --authorized [options]\n"
        "  %s squat   <pipe> --authorized [--impersonate]\n"
        "  %s version | help\n\n"
        "<pipe> = bare name (e.g. cowork-vm-service) or full \\\\.\\pipe\\name\n\n"
        "global flags (any position):\n"
        "  -v, --verbose   narrate each step to stderr\n"
        "      --debug     verbose + handles, error codes, per-iteration detail\n"
        "      --color     force ANSI color (default: auto; off when redirected)\n"
        "      --no-color  disable ANSI color\n"
        "      --no-banner suppress the startup banner\n\n"
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
        "  --corpus <file>     seed mutations from a capture corpus (structure-aware)\n"
        "  --iters  <N>        number of test cases             (default 500)\n"
        "  --seed   <hex|dec>  PRNG seed for reproducible runs  (default fixed)\n"
        "  --maxlen <N>        max random payload length        (default 4096)\n"
        "  --delay  <ms>       inter-iteration delay            (default 15)\n\n"
        "Examples:\n"
        "  %s enum --all --html report.html\n"
        "  %s audit cowork-vm-service --html pipe.html\n"
        "  %s capture cowork-vm-service --authorized --count 5\n"
        "  %s fuzz cowork-vm-service --authorized --corpus fifofox_corpus_123.bin -v\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
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

int main(int argc, char **argv)
{
    int i;
    int no_banner = 0;

    {
        int color_want = 0; //0 auto, 1 force on, -1 force off
        for (i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "--verbose") || !strcmp(argv[i], "-v")) g_verbose = 1;
            else if (!strcmp(argv[i], "--debug")) { g_debug = 1; g_verbose = 1; }
            else if (!strcmp(argv[i], "--color")) color_want = 1;
            else if (!strcmp(argv[i], "--no-color")) color_want = -1;
            else if (!strcmp(argv[i], "--no-banner")) no_banner = 1;
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
                if (n > 0) printf("[*] Loaded %d corpus frames from %s (structure-aware mode)\n",
                                  n, corpusf);
                else fprintf(stderr, "[!] --corpus %s: no records loaded, falling back to blind fuzzing\n",
                             corpusf);
            }
        }
        return mode_fuzz(argv[2], fr, cmd, iters, seed, maxlen, delay);
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

    if (!strcmp(argv[1], "squat")) {
        if (argc < 3) { usage(argv[0]); return 1; }
        if (!has_flag(argc, argv, "--authorized")) {
            fprintf(stderr, "[X] squat requires --authorized (you affirm you have perms).\n");
            return 2;
        }
        return mode_squat(argv[2], has_flag(argc, argv, "--impersonate"));
    }

    usage(argv[0]);
    return 1;
}
