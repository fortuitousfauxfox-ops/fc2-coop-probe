/*
 * fc2-coop-probe: a dinput8.dll proxy for TEST COPIES of Far Cry 2 (Steam 1.03, Dunia engine).
 * Logs network, file and exit calls of Dunia.dll, runs Lua 4.0 and native commands inside the
 * game, finds the player's Havok body and exchanges its position between two copies over its own
 * UDP socket (research prototype; see README.md). MIT licence, see LICENSE.
 * Addresses (RVAs) below are for Dunia.dll SHA-256 6353936a...2765 only.
 */
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>

static FILE *g_log;
static CRITICAL_SECTION g_cs;
static HMODULE g_self;

static void logf_(const char *fmt, ...)
{
    va_list ap;
    if (!g_log) return;
    EnterCriticalSection(&g_cs);
    fprintf(g_log, "[%8lu T%04lu] ", GetTickCount(), GetCurrentThreadId());
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
    fflush(g_log);
    LeaveCriticalSection(&g_cs);
}

static void addr_str(const struct sockaddr *a, char *out, size_t n)
{
    if (a && a->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)a;
        snprintf(out, n, "%s:%u", inet_ntoa(s->sin_addr), ntohs(s->sin_port));
    } else {
        snprintf(out, n, "af%d", a ? a->sa_family : -1);
    }
}

static void hex_str(const char *b, int len, char *out, size_t n)
{
    int i, m = len < 16 ? len : 16;
    size_t o = 0;
    for (i = 0; i < m && o + 3 < n; i++) o += snprintf(out + o, n - o, "%02x", (unsigned char)b[i]);
    out[o] = 0;
}

#ifndef GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 2
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 4
#endif
WINBASEAPI BOOL WINAPI GetModuleHandleExA(DWORD, LPCSTR, HMODULE *);
static const char *caller_str(void *a, char *out, size_t n)
{
    HMODULE m = NULL;
    char path[MAX_PATH];
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)a, &m)
        && GetModuleFileNameA(m, path, MAX_PATH)) {
        char *s = strrchr(path, '\\');
        snprintf(out, n, "%s+0x%lx", s ? s + 1 : path, (unsigned long)((BYTE *)a - (BYTE *)m));
    } else {
        snprintf(out, n, "%p", a);
    }
    return out;
}
#define CALLER(buf) caller_str(__builtin_return_address(0), buf, sizeof buf)

/* originals */
static int (WINAPI *o_WSASendTo)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr *, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static int (WINAPI *o_WSARecvFrom)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, struct sockaddr *, LPINT, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
static int (WINAPI *o_getaddrinfo)(const char *, const char *, const void *, void **);
static struct hostent *(WINAPI *o_gethostbyname)(const char *);
static int (WINAPI *o_sendto)(SOCKET, const char *, int, int, const struct sockaddr *, int);
static int (WINAPI *o_recvfrom)(SOCKET, char *, int, int, struct sockaddr *, int *);
static int (WINAPI *o_bind)(SOCKET, const struct sockaddr *, int);
static int (WINAPI *o_connect)(SOCKET, const struct sockaddr *, int);
static VOID (WINAPI *o_ExitProcess)(UINT);
static VOID (WINAPI *o_PostQuitMessage)(int);

/* lanfwd: copies of our broadcasts also go to this address (two copies on different interfaces can find each
 * other's LAN matches); 0 = off */
static unsigned long g_lanfwd;
static int WINAPI h_sendto(SOCKET s, const char *b, int l, int f, const struct sockaddr *to, int tl)
{
    char a[40], h[40];
    int r = o_sendto(s, b, l, f, to, tl); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    static unsigned n, fw;
    if (g_lanfwd && to && to->sa_family == AF_INET && (((const struct sockaddr_in *)to)->sin_addr.s_addr | 0x00FFFFFFu) == 0xFFFFFFFFu) {
        struct sockaddr_in d = *(const struct sockaddr_in *)to;
        d.sin_addr.s_addr = g_lanfwd;
        o_sendto(s, b, l, f, (struct sockaddr *)&d, sizeof d);
        if (++fw <= 20) logf_("lanfwd: broadcast to port %u (len %d) copied to %s", ntohs(d.sin_port), l, inet_ntoa(d.sin_addr));
    }
    /* the game's own traffic (MP sessions) is busy: log the first 40 packets, then every 500th */
    if (++n <= 40 || n % 500 == 0) {
        addr_str(to, a, sizeof a); hex_str(b, l, h, sizeof h);
        logf_("sendto #%u s=%u -> %s len=%d ret=%d data=%s", n, (unsigned)s, a, l, r, h);
    }
    SetLastError(le);
    return r;
}
static int WINAPI h_recvfrom(SOCKET s, char *b, int l, int f, struct sockaddr *from, int *fl)
{
    int r = o_recvfrom(s, b, l, f, from, fl); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    static unsigned n;
    if (r > 0 && (++n <= 40 || n % 500 == 0)) {
        char a[40], h[40];
        addr_str(from, a, sizeof a); hex_str(b, r, h, sizeof h);
        logf_("recvfrom #%u s=%u <- %s len=%d data=%s", n, (unsigned)s, a, r, h);
    }
    SetLastError(le);
    return r;
}
static int WINAPI h_WSASendTo(SOCKET s, LPWSABUF b, DWORD c, LPDWORD sent, DWORD f, const struct sockaddr *to, int tl, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    char a[40], h[40] = "", cs[96];
    int r = o_WSASendTo(s, b, c, sent, f, to, tl, o, cr); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    addr_str(to, a, sizeof a);
    if (c) hex_str(b[0].buf, (int)b[0].len, h, sizeof h);
    logf_("WSASendTo s=%u -> %s len=%lu ret=%d data=%s from %s", (unsigned)s, a, c ? b[0].len : 0, r, h, CALLER(cs));
    SetLastError(le);
    return r;
}
static int WINAPI h_WSARecvFrom(SOCKET s, LPWSABUF b, DWORD c, LPDWORD got, LPDWORD f, struct sockaddr *from, LPINT fl, LPWSAOVERLAPPED o, LPWSAOVERLAPPED_COMPLETION_ROUTINE cr)
{
    int r = o_WSARecvFrom(s, b, c, got, f, from, fl, o, cr); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    if (r == 0 && got && *got) {
        char a[40], h[40];
        addr_str(from, a, sizeof a); hex_str(b[0].buf, (int)*got, h, sizeof h);
        logf_("WSARecvFrom s=%u <- %s len=%lu data=%s", (unsigned)s, a, *got, h);
    }
    SetLastError(le);
    return r;
}
static int WINAPI h_getaddrinfo(const char *n, const char *sv, const void *hints, void **res)
{
    char cs[96];
    int r = o_getaddrinfo(n, sv, hints, res); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    logf_("getaddrinfo(%s, %s) ret=%d from %s", n ? n : "(null)", sv ? sv : "(null)", r, CALLER(cs));
    SetLastError(le);
    return r;
}
static struct hostent *WINAPI h_gethostbyname(const char *n)
{
    char cs[96];
    struct hostent *r = o_gethostbyname(n); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    logf_("gethostbyname(%s) ret=%s from %s", n ? n : "(null)", r ? "ok" : "null", CALLER(cs));
    SetLastError(le);
    return r;
}
static int WINAPI h_bind(SOCKET s, const struct sockaddr *n, int l)
{
    char a[40];
    int r = o_bind(s, n, l); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    addr_str(n, a, sizeof a);
    logf_("bind s=%u %s ret=%d", (unsigned)s, a, r);
    SetLastError(le);
    return r;
}
static int WINAPI h_connect(SOCKET s, const struct sockaddr *n, int l)
{
    char a[40], cs[96];
    int r = o_connect(s, n, l); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    addr_str(n, a, sizeof a);
    logf_("connect s=%u %s ret=%d from %s", (unsigned)s, a, r, CALLER(cs));
    SetLastError(le);
    return r;
}
static VOID WINAPI h_ExitProcess(UINT c)
{
    logf_("ExitProcess(%u) caller=%p", c, __builtin_return_address(0));
    o_ExitProcess(c);
}
static VOID WINAPI h_PostQuitMessage(int c)
{
    logf_("PostQuitMessage(%d) caller=%p", c, __builtin_return_address(0));
    o_PostQuitMessage(c);
}

static BOOL (WINAPI *o_PeekMessageA)(LPMSG, HWND, UINT, UINT, UINT);
static BOOL (WINAPI *o_PeekMessageW)(LPMSG, HWND, UINT, UINT, UINT);
static BOOL WINAPI h_PeekMessageA(LPMSG, HWND, UINT, UINT, UINT);
static BOOL WINAPI h_PeekMessageW(LPMSG, HWND, UINT, UINT, UINT);

static HANDLE (WINAPI *o_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static HANDLE (WINAPI *o_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
static HANDLE WINAPI h_CreateFileA(LPCSTR n, DWORD a, DWORD sh, LPSECURITY_ATTRIBUTES sa, DWORD cd, DWORD fl, HANDLE t)
{
    HANDLE h = o_CreateFileA(n, a, sh, sa, cd, fl, t); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    if (n && (strstr(n, "av") || strstr(n, "Saved") || strstr(n, "Documents") || strstr(n, "Profile"))) logf_("CreateFileA %s acc=%lx disp=%lu -> %s", n, a, cd, h == INVALID_HANDLE_VALUE ? "FAIL" : "ok");
    SetLastError(le);
    return h;
}
static DWORD g_sav_tick;   /* when the game first opened a save (coop_auto.txt runs a few seconds later) */
static BYTE *g_base;
static int safe_read(const void *addr, void *buf, size_t n);
static HANDLE WINAPI h_CreateFileW(LPCWSTR n, DWORD a, DWORD sh, LPSECURITY_ATTRIBUTES sa, DWORD cd, DWORD fl, HANDLE t)
{
    HANDLE h = o_CreateFileW(n, a, sh, sa, cd, fl, t); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    if (n && (wcsstr(n, L"av") || wcsstr(n, L"Saved") || wcsstr(n, L"Documents") || wcsstr(n, L"Profile"))) logf_("CreateFileW %ls acc=%lx disp=%lu -> %s", n, a, cd, h == INVALID_HANDLE_VALUE ? "FAIL" : "ok");
    if (n && !g_sav_tick && wcsstr(n, L".sav") && h != INVALID_HANDLE_VALUE) g_sav_tick = GetTickCount() | 1;
    if (n && g_base && wcsstr(n, L".sav")) {
        /* who reads or writes a save: return addresses into Dunia.dll on the stack (to find the engine's save/load) */
        DWORD *sp = (DWORD *)__builtin_frame_address(0), v;
        char line[1000];
        int k, c = 0, o = snprintf(line, sizeof line, "  .sav %s stack (thread %lu):", (a & (GENERIC_WRITE | FILE_WRITE_DATA)) ? "write" : "read", GetCurrentThreadId());
        for (k = 0; k < 8192 && c < 64 && o < (int)sizeof line - 16; k++) {
            if (!safe_read(sp + k, &v, 4)) break;
            if (v >= (DWORD)(ULONG_PTR)g_base + 0x1000 && v < (DWORD)(ULONG_PTR)g_base + 0x1000000) { o += snprintf(line + o, sizeof line - o, " D+%lx", v - (DWORD)(ULONG_PTR)g_base); c++; }
        }
        logf_("%s", line);
    }
    SetLastError(le);
    return h;
}

/* the game's startup HeapCreate (128 MB committed, sound init FUN_10d16530) failed in a second copy: log failures */
static HANDLE (WINAPI *o_HeapCreate)(DWORD, SIZE_T, SIZE_T);
static HANDLE WINAPI h_HeapCreate(DWORD o, SIZE_T i, SIZE_T m)
{
    HANDLE h = o_HeapCreate(o, i, m); DWORD le = GetLastError();
    if (!h) {
        MEMORY_BASIC_INFORMATION mbi;
        BYTE *p = NULL;
        SIZE_T best = 0, fr = 0;
        while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi) {
            if (mbi.State == MEM_FREE) { fr += mbi.RegionSize; if (mbi.RegionSize > best) best = mbi.RegionSize; }
            p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
            if ((ULONG_PTR)p < (ULONG_PTR)mbi.BaseAddress) break;
        }
        logf_("HeapCreate(%lx, %lu MB, %lu MB) FAILED, error %lu; free address space %lu MB, largest free block %lu MB", o, (unsigned long)(i >> 20),
              (unsigned long)(m >> 20), le, (unsigned long)(fr >> 20), (unsigned long)(best >> 20));
        /* what holds the address space: allocations of 8 MB and more, by type and owner */
        p = NULL;
        while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi) {
            BYTE *ab = (BYTE *)mbi.AllocationBase, *q = ab;
            SIZE_T tot = 0;
            MEMORY_BASIC_INFORMATION m2;
            if (mbi.State != MEM_FREE && ab == mbi.BaseAddress) {
                while (VirtualQuery(q, &m2, sizeof m2) == sizeof m2 && m2.AllocationBase == ab) { tot += m2.RegionSize; q = (BYTE *)m2.BaseAddress + m2.RegionSize; }
                if (tot >= (8u << 20)) {
                    char fn[MAX_PATH] = "";
                    HMODULE hm = NULL;
                    if (mbi.Type == MEM_IMAGE && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)ab, &hm))
                        GetModuleFileNameA(hm, fn, sizeof fn);
                    logf_("  %p %4lu MB %s%s %s", ab, (unsigned long)(tot >> 20), mbi.Type == MEM_IMAGE ? "image" : mbi.Type == MEM_MAPPED ? "mapped" : "private",
                          mbi.State == MEM_RESERVE ? " (reserved)" : "", fn);
                }
            }
            p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
            if ((ULONG_PTR)p < (ULONG_PTR)mbi.BaseAddress) break;
        }
    }
    SetLastError(le);
    return h;
}

typedef struct { const char *dll, *name; void **orig; void *hook; } Target;
static Target g_targets[] = {
    { "ws2_32.dll", "sendto", (void **)&o_sendto, h_sendto },
    { "ws2_32.dll", "recvfrom", (void **)&o_recvfrom, h_recvfrom },
    { "ws2_32.dll", "bind", (void **)&o_bind, h_bind },
    { "ws2_32.dll", "connect", (void **)&o_connect, h_connect },
    { "ws2_32.dll", "WSASendTo", (void **)&o_WSASendTo, h_WSASendTo },
    { "ws2_32.dll", "WSARecvFrom", (void **)&o_WSARecvFrom, h_WSARecvFrom },
    { "ws2_32.dll", "getaddrinfo", (void **)&o_getaddrinfo, h_getaddrinfo },
    { "ws2_32.dll", "gethostbyname", (void **)&o_gethostbyname, h_gethostbyname },
    { "user32.dll", "PeekMessageA", (void **)&o_PeekMessageA, h_PeekMessageA },
    { "user32.dll", "PeekMessageW", (void **)&o_PeekMessageW, h_PeekMessageW },
    { "kernel32.dll", "CreateFileA", (void **)&o_CreateFileA, h_CreateFileA },
    { "kernel32.dll", "CreateFileW", (void **)&o_CreateFileW, h_CreateFileW },
    { "kernel32.dll", "ExitProcess", (void **)&o_ExitProcess, h_ExitProcess },
    { "user32.dll", "PostQuitMessage", (void **)&o_PostQuitMessage, h_PostQuitMessage },
    { "kernel32.dll", "HeapCreate", (void **)&o_HeapCreate, h_HeapCreate },
};
#define NT (sizeof g_targets / sizeof g_targets[0])

static int g_npc_role;            /* npcsync: 1 host, 2 join (declared here for coop_flags.txt) */
static int patch_iat(HMODULE m)
{
    BYTE *base = (BYTE *)m;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_IMPORT_DESCRIPTOR *d = (IMAGE_IMPORT_DESCRIPTOR *)(base + dd->VirtualAddress);
    void *want[NT];
    size_t i;
    int patched = 0;
    char flags[128] = "";
    {
        /* coop_flags.txt next to the probe: "nopeek" leaves PeekMessage alone, "nonet" the winsock functions,
         * "nofile" CreateFile (for bisecting side effects such as broken text input in the MP menus) */
        char fp[MAX_PATH], *s;
        FILE *f;
        GetModuleFileNameA(g_self, fp, MAX_PATH);
        if ((s = strrchr(fp, '\\'))) strcpy(s + 1, "coop_flags.txt");
        if ((f = fopen(fp, "rb"))) { size_t n = fread(flags, 1, sizeof flags - 1, f); flags[n] = 0; fclose(f); logf_("probe flags: %s", flags); }
        /* "npchost" / "npcjoin": the NPC sync role from the start, so a joiner's NPCs never get to act on their own
         * while the world loads and the session connects (they started idle actions the host never saw) */
        if (strstr(flags, "npchost")) g_npc_role = 1;
        if (strstr(flags, "npcjoin")) g_npc_role = 2;
    }
    for (i = 0; i < NT; i++) {
        HMODULE h = GetModuleHandleA(g_targets[i].dll);
        int skip = (strstr(flags, "nopeek") && strstr(g_targets[i].name, "PeekMessage")) ||
                   (strstr(flags, "nonet") && !strcmp(g_targets[i].dll, "ws2_32.dll")) ||
                   (strstr(flags, "nofile") && strstr(g_targets[i].name, "CreateFile"));
        if (!h) h = LoadLibraryA(g_targets[i].dll);
        want[i] = (h && !skip) ? (void *)GetProcAddress(h, g_targets[i].name) : NULL;
        *g_targets[i].orig = h ? (void *)GetProcAddress(h, g_targets[i].name) : NULL;
    }
    for (; d->Name; d++) {
        void **t = (void **)(base + d->FirstThunk);
        for (; *t; t++) {
            for (i = 0; i < NT; i++) {
                if (want[i] && *t == want[i]) {
                    DWORD old;
                    VirtualProtect(t, sizeof(void *), PAGE_READWRITE, &old);
                    *t = g_targets[i].hook;
                    VirtualProtect(t, sizeof(void *), old, &old);
                    logf_("hooked %s via IAT of %s", g_targets[i].name, (char *)(base + d->Name));
                    patched++;
                }
            }
        }
    }
    return patched;
}

/* ---- Lua 4.0 access (Dunia.dll, RVAs from the Steam v1.03 build) ---- */
#define RVA_GETTOP    0x2aa9c0
#define RVA_SETTOP    0x2aa9e0
#define RVA_DOBUFFER  0x2ab600
#define RVA_CHECKLSTR 0x2d24b0
#define RVA_ALERT     0x2c3500
#define RVA_GETGLOBAL 0x2aaf90

static BYTE *g_base;
static int (__cdecl *o_gettop)(void *);
static int (__cdecl *lua_settop_)(void *, int);
static int (__cdecl *lua_dobuffer_)(void *, const char *, size_t, const char *);
static const char *(__cdecl *lua_checklstr_)(void *, int, size_t *);
static void (__cdecl *lua_getglobal_)(void *, const char *);

#define MAXL 8
static struct { void *L; unsigned long thread; unsigned long hits; } g_states[MAXL];
static int g_nstates;
static char g_cmdpath[MAX_PATH];
static volatile LONG g_busy;
static DWORD g_lastpoll;

static void *make_detour(BYTE *target, int stolen, void *hook, int keep_original)
{
    DWORD old;
    BYTE *tramp = NULL;
    if (keep_original) {
        tramp = (BYTE *)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(tramp, target, stolen);
        tramp[stolen] = 0xE9;
        *(DWORD *)(tramp + stolen + 1) = (DWORD)(target + stolen) - (DWORD)(tramp + stolen + 5);
    }
    VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &old);
    target[0] = 0xE9;
    *(DWORD *)(target + 1) = (DWORD)hook - (DWORD)(target + 5);
    VirtualProtect(target, 8, old, &old);
    FlushInstructionCache(GetCurrentProcess(), target, 8);
    return tramp;
}

static int __cdecl h_alert(void *L)
{
    const char *s = lua_checklstr_(L, 1, NULL);
    logf_("LUA: %s", s ? s : "(nil)");
    return 0;
}

static void run_cmd(void *L)
{
    FILE *f = fopen(g_cmdpath, "rb");
    long n;
    char *buf;
    int top, st;
    if (!f) return;
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    buf = (char *)malloc(n + 1);
    if (fread(buf, 1, n, f) != (size_t)n) n = 0;
    fclose(f);
    buf[n] = 0;
    remove(g_cmdpath);
    top = o_gettop(L);
    lua_dobuffer_(L, "__out = ''", 10, "coop_pre");
    st = lua_dobuffer_(L, buf, (size_t)n, "coop_cmd");
    lua_getglobal_(L, "__out");
    {
        size_t ol = 0;
        const char *o = lua_checklstr_(L, o_gettop(L), &ol);
        logf_("cmd executed (%ld bytes) status=%d out(%u)=%s", n, st, (unsigned)ol, o ? o : "(null)");
    }
    lua_settop_(L, top);
    free(buf);
}


static int lua_eval(const char *code, char *out, size_t on)
{
    void *L;
    int top, st;
    size_t ol = 0;
    const char *o;
    out[0] = 0;
    if (g_nstates == 0) return -1;
    L = g_states[0].L;
    top = o_gettop(L);
    lua_dobuffer_(L, "__out = ''", 10, "coop_pre");
    st = lua_dobuffer_(L, code, strlen(code), "coop_eval");
    lua_getglobal_(L, "__out");
    o = lua_checklstr_(L, o_gettop(L), &ol);
    if (o) { strncpy(out, o, on - 1); out[on - 1] = 0; }
    lua_settop_(L, top);
    return st;
}


/* ---- native peek commands (file coop_native.txt, run on the main thread) ---- */
#define RVA_ENTMGR_PTR 0x1644e80
#define RVA_GETENTITY  0x55820
typedef void *(__attribute__((thiscall)) *getent_t)(void *mgr, void **out, unsigned lo, unsigned hi);
#define RVA_BODY_VTABLE 0xE67658
static BYTE *g_body, *g_bodymat;
static BYTE **g_av_body_p;
static int g_walk;
static float g_walk_c[3], g_walk_r, g_walk_secs, g_walk_speed;
/* avatar mode state, defined with the avatar code below (used by the `avmode` command) */
static int g_av_np;
static char g_av_arch[96];
static float g_av_yawoff, g_av_off[2];
static unsigned long long g_av_id;
static int g_npc_role;            /* npcsync: 1 host, 2 join */
static float g_npc_rad = 80.0f;
static void stim_install(unsigned long long id, int slot);
static void npc_stat(void);
static void npc_join_tick(DWORD now);
static int g_hitsync = 1, g_st_verbose, g_npcev_left;
static int g_npcanim = 1;           /* npcanim: puppets take the host NPCs' animation graph inputs */
static int g_npcrespawn;            /* npcrespawn 1: replace puppets that run an action of their own (off: replacements are
                                     * spawned from the generic archetype and look different, and actions still differed) */
static void npc_anim_apply(BYTE *mb);
static unsigned long long g_dd_id;   /* dumpd: NPC whose desired-state block is logged */
static DWORD g_dd_until;  /* hit sync on by default; stimlog turns on event logging */
static void av_remove(void);
static void *np_slot(BYTE *obj, int slot, unsigned k0, unsigned k1, unsigned k2);
static int g_ws_role;
static BYTE *env_obj(void);
static int g_mf_on;
static void *g_xh_vt[64], *g_xh_orig, *g_xh_obj;
static int g_xh_n;
/* watchd: per-frame change log of an observed pawn's memento state and DesiredData flags */
static unsigned long long g_wd_id;
static unsigned g_wd_n;
static BYTE *entity_obj(unsigned long long id, void **holder_out);
static void watchd_tick(void)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    static unsigned last[8];
    void *holder = NULL;
    BYTE *obj, *pawn, *m = NULL;
    unsigned cur[8];
    int k;
    if (!g_wd_id || g_wd_n > 400) return;
    obj = entity_obj(g_wd_id, &holder);
    if (holder) (*(int *)((BYTE *)holder + 8))--;
    if (!obj) return;
    pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
    {
        void **cs = *(void ***)(obj + 0x9C);
        int n = *(int *)(obj + 0xA0);
        for (k = 0; cs && k < n && k < 64; k++)
            if (cs[k] && !IsBadReadPtr(cs[k], 0x174) && *(DWORD *)cs[k] == (DWORD)(g_base + 0xE1AE00)) { m = *(BYTE **)((BYTE *)cs[k] + 0x170); break; }
    }
    if (!pawn) return;
    cur[0] = *(unsigned *)(pawn + 0x144); cur[1] = pawn[0x140 + 0xA4];
    cur[2] = m ? m[0x104] : 0xEE; cur[3] = m ? m[0x110] : 0xEE; cur[4] = m ? m[0x11C] : 0xEE;
    cur[5] = m ? *(unsigned *)(m + 0x264) : 0; cur[6] = m ? *(unsigned *)(m + 0x1A0) : 0; cur[7] = pawn[0xD8 + 0x52];
    if (memcmp(cur, last, sizeof cur)) {
        g_wd_n++;
        logf_("watchd %u: D+4..7 %08x D+A4 %u | mem 104=%u 110=%u 11C=%u 264=%08x 1A0=%08x | pawn+D8+52 %u", GetTickCount(), cur[0], cur[1],
              cur[2], cur[3], cur[4], cur[5], cur[6], cur[7]);
        memcpy(last, cur, sizeof cur);
    }
}

/* evlog: event types seen by an observed pawn's base beautifier */
static void *g_ev_vt[64], *g_ev_orig;
static unsigned g_ev_ids[64], g_ev_cnt[64];
static int g_ev_n;
static unsigned __attribute__((thiscall)) ev_hook(void *self, int *ev)
{
    if (ev && !IsBadReadPtr(ev, 8)) {
        typedef BYTE *(__attribute__((thiscall)) *type_t)(void *o);
        BYTE *ty = ((type_t)(*(void ***)ev)[1])(ev);
        if (ty && !IsBadReadPtr(ty, 0x20)) {
            unsigned depth = *(unsigned *)(ty + 4), last = depth >= 1 && depth < 6 ? *(unsigned *)(ty + 4 + 4 * depth) : 0;
            int i;
            for (i = 0; i < g_ev_n && g_ev_ids[i] != last; i++) ;
            if (i == g_ev_n && g_ev_n < 64) { g_ev_ids[g_ev_n] = last; g_ev_cnt[g_ev_n++] = 0;
                logf_("evlog: new event type %08x (depth %u, ids %08x %08x %08x %08x %08x), event %p", last, depth, *(unsigned *)(ty + 8),
                      *(unsigned *)(ty + 0xC), *(unsigned *)(ty + 0x10), *(unsigned *)(ty + 0x14), *(unsigned *)(ty + 0x18), ev); }
            if (i < 64 && ++g_ev_cnt[i] % 50 == 0) logf_("evlog: type %08x seen %u times", last, g_ev_cnt[i]);
        }
    }
    return ((unsigned (__attribute__((thiscall)) *)(void *, int *))g_ev_orig)(self, ev);
}
static void __attribute__((thiscall)) xshot_hook(void *self, void *pawn);
static unsigned g_xh_calls;
static float g_av_kp = 0.0f;           /* avatar position-error gain (avkp <k>), 0 = off (did not help, see notes) */
static unsigned g_av_directfire = 2; /* 0 state (not working yet), 1 direct: weapon vf+0x80 + event, 2 event only */
static int g_av_fake;
static float g_av_fake_c[3], g_av_fake_r, g_av_fake_secs, g_av_fake_speed;
static DWORD g_av_fake_t0, g_av_fake_last;
static DWORD g_walk_t0;
static int g_net_cfg;  /* 1 = start requested, 2 = running */
static unsigned g_net_lport, g_net_pport;
static char g_net_pip[32];
static unsigned long long g_net_id;
static char g_natpath[MAX_PATH];
static int g_hold;
static unsigned long long g_hold_id;
static float g_hold_pos[3];
static unsigned long g_hold_ticks;

static void hexdump_(const BYTE *p, int len)
{
    int i, j;
    for (i = 0; i < len; i += 16) {
        char line[256];
        int o = snprintf(line, sizeof line, "%08lx:", (unsigned long)(p + i));
        for (j = 0; j < 16 && i + j + 4 <= len; j += 4) {
            unsigned v = *(const unsigned *)(p + i + j);
            float f = *(const float *)(p + i + j);
            if (f > -1e6f && f < 1e6f && (f > 1e-3f || f < -1e-3f)) o += snprintf(line + o, sizeof line - o, " %08x(%.3f)", v, f);
            else o += snprintf(line + o, sizeof line - o, " %08x", v);
        }
        logf_("%s", line);
    }
}


static int safe_read(const void *addr, void *buf, size_t n)
{
    SIZE_T got = 0;
    return ReadProcessMemory(GetCurrentProcess(), addr, buf, n, &got) && got == n;
}

static LONG WINAPI crash_filter(EXCEPTION_POINTERS *ep)
{
    char mod[96];
    caller_str(ep->ExceptionRecord->ExceptionAddress, mod, sizeof mod);
    logf_("CRASH: code %08lx at %s (access address %p)", (unsigned long)ep->ExceptionRecord->ExceptionCode, mod,
          ep->ExceptionRecord->NumberParameters > 1 ? (void *)ep->ExceptionRecord->ExceptionInformation[1] : NULL);
    return EXCEPTION_CONTINUE_SEARCH;
}
WINBASEAPI PVOID WINAPI AddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
static LONG WINAPI veh_filter(EXCEPTION_POINTERS *ep)
{
    static int n;
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005 && n < 30) {
        char mod[96];
        n++;
        caller_str(ep->ExceptionRecord->ExceptionAddress, mod, sizeof mod);
        logf_("ACCESS VIOLATION #%d at %s, %s address %p", n, mod, ep->ExceptionRecord->ExceptionInformation[0] ? "write" : "read",
              (void *)ep->ExceptionRecord->ExceptionInformation[1]);
        if (n <= 3) {
            /* stack: values on the stack that point into Dunia.dll or the probe are likely return addresses */
            DWORD *sp = (DWORD *)ep->ContextRecord->Esp, v, me;
            char line[600];
            MEMORY_BASIC_INFORMATION mi;
            VirtualQuery((void *)&veh_filter, &mi, sizeof mi);
            me = (DWORD)(ULONG_PTR)mi.AllocationBase;
            int k, c = 0, o = snprintf(line, sizeof line, "  regs eax %08lx ebx %08lx ecx %08lx edx %08lx esi %08lx edi %08lx esp %08lx ebp %08lx; stack:",
                                       ep->ContextRecord->Eax, ep->ContextRecord->Ebx, ep->ContextRecord->Ecx, ep->ContextRecord->Edx,
                                       ep->ContextRecord->Esi, ep->ContextRecord->Edi, ep->ContextRecord->Esp, ep->ContextRecord->Ebp);
            for (k = 0; k < 1024 && c < 24 && o < (int)sizeof line - 24; k++) {
                if (!safe_read(sp + k, &v, 4)) break;
                if (v >= (DWORD)(ULONG_PTR)g_base + 0x1000 && v < (DWORD)(ULONG_PTR)g_base + 0x1000000) { o += snprintf(line + o, sizeof line - o, " D+%lx", v - (DWORD)(ULONG_PTR)g_base); c++; }
                else if (v - me < 0x80000u) { o += snprintf(line + o, sizeof line - o, " P+%lx", v - me); c++; }
            }
            logf_("%s", line);
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static BYTE *entity_obj(unsigned long long id, void **holder_out);
/* exclude: a body to skip (the local player's when binding the avatar: both stand on the same spot
 * after loading the same save, so the nearest body would otherwise be the player's own) */
static int find_body(unsigned long long id, BYTE **body_out, BYTE **mat_out, const BYTE *exclude)
{
    void *holder = NULL;
    BYTE *obj = entity_obj(id, &holder);
    float ex, ey, ez, best = 1.0f;
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *p = NULL;
    int found = 0;
    unsigned vt = (unsigned)(g_base + RVA_BODY_VTABLE);
    if (!obj) { logf_("findbody %llu: no entity", id); return 0; }
    ex = *(float *)(obj + 0x60); ey = *(float *)(obj + 0x64); ez = *(float *)(obj + 0x68);
    if (holder) (*(int *)((BYTE *)holder + 8))--;
    *body_out = NULL; *mat_out = NULL;
    {
        static BYTE chunk[0x10000 + 0x40];
        while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi) {
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize < 0x20000000) {
                BYTE *base = (BYTE *)mbi.BaseAddress, *rend = base + mbi.RegionSize;
                BYTE *c;
                for (c = base; c < rend; c += 0x10000) {
                    size_t n = (size_t)(rend - c);
                    size_t k;
                    if (n > sizeof chunk) n = sizeof chunk;
                    if (!safe_read(c, chunk, n)) continue;
                    for (k = 0; k + 4 <= n && k < 0x10000; k += 4) {
                        if (*(unsigned *)(chunk + k) == vt && k + 0x1C <= n && c + k != exclude) {
                            BYTE *m = *(BYTE **)(chunk + k + 0x18);
                            float f[3];
                            if (safe_read(m + 0x30, f, sizeof f)) {
                                float d = fabsf(f[0] - ex) + fabsf(f[1] - ey) + fabsf(f[2] - ez);
                                if (d < 1.0f) {
                                    logf_("findbody: body %p matrix %p pos %.3f %.3f %.3f (dist %.3f)", c + k, m, f[0], f[1], f[2], d);
                                    found++;
                                    if (d < best) { best = d; *body_out = c + k; *mat_out = m; }
                                }
                            }
                        }
                    }
                }
            }
            p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        }
    }
    logf_("findbody done: %d match(es) near entity %.3f %.3f %.3f, nearest dist %.3f", found, ex, ey, ez, *body_out ? best : -1.0f);
    return *body_out != NULL;
}
/* give the NetPlayer avatar a weapon the way the Lua AddWeapon handler (LAB_109f9310) does for the local player:
 * spawn the weapon entity, CWeapon comp (key FE01F8), category = *(vf+0x8C()), inventory = FUN_1007e140(pawn comp),
 * the old weapon of that category FUN_10129de0 -> FUN_1012e3e0(old, 0) and its entity removed, FUN_101289f0(weapon),
 * then select it like SelectWeapon (FUN_1012ce80 -> FUN_1012b9b0: inventory weapon mode +0x78 = 1, current weapon) */
static int pawn_give_weapon(BYTE *obj, const char *arch, const char *who);
static int av_give_weapon(const char *arch)
{
    void *holder = NULL;
    BYTE *obj = g_av_id ? entity_obj(g_av_id, &holder) : NULL;
    if (holder) (*(int *)((BYTE *)holder + 8))--;
    if (!obj) { logf_("avweapon: no avatar"); return 0; }
    return pawn_give_weapon(obj, arch, "avweapon");
}
/* the same for any pawn entity (the avatar, NPC puppets); who prefixes the log lines */
static int pawn_give_weapon(BYTE *obj, const char *arch, const char *who)
{
    typedef void *(__fastcall *inv_t)(void *pawn);
    typedef unsigned (__attribute__((thiscall)) *slot_t)(void *weapon);
    typedef void *(__attribute__((thiscall)) *inslot_t)(void *inv, unsigned slot);
    typedef void (__attribute__((thiscall)) *drop_t)(void *inv, void *weapon, int f);
    typedef void (__attribute__((thiscall)) *add_t)(void *inv, void *weapon);
    typedef void *(__attribute__((thiscall)) *cur_t)(void *inv);
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    char code[256], out[64];
    void *wholder = NULL, *pawn, *wc, *inv, *old;
    BYTE *wobj;
    unsigned long long wid;
    unsigned slot;
    snprintf(code, sizeof code, "__out = tostring(SpawnEntityFromArchetype('%s', %.3f, %.3f, %.3f, 0, 0, 0))", arch,
             *(float *)(obj + 0x60), *(float *)(obj + 0x64), *(float *)(obj + 0x68) + 1.0f);
    lua_eval(code, out, sizeof out);
    wid = strtoull(out, NULL, 10);
    wobj = (wid && wid != 0xFFFFFFFFFFFFFFFFull) ? entity_obj(wid, &wholder) : NULL;
    if (wholder) (*(int *)((BYTE *)wholder + 8))--;
    if (!wobj) { logf_("%s: spawn of %s failed (%s)", who, arch, out); return 0; }
    pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
    wc = ((gcomp_t)(g_base + 0x4E2CC0))(wobj, (void *)(g_base + 0xFE01F8));
    if (!pawn || !wc) { logf_("%s: pawn %p weapon comp %p (weapon entity %llu)", who, pawn, wc, wid); return 0; }
    slot = ((slot_t)(*(void ***)wc)[0x8C / 4])(wc);
    inv = ((inv_t)(g_base + 0x7E140))(pawn);
    if (!inv) { logf_("%s: pawn has no inventory", who); return 0; }
    old = ((inslot_t)(g_base + 0x129DE0))(inv, slot);
    if (old) { void *oh = *(void **)((BYTE *)old + 8); ((drop_t)(g_base + 0x12E3E0))(inv, old, 0); if (oh) { snprintf(code, sizeof code, "RemoveEntity('%llu') __out = 'ok'", *(unsigned long long *)oh); lua_eval(code, out, sizeof out); } }
    ((add_t)(g_base + 0x1289F0))(inv, wc);
    /* select it like the Lua SelectWeapon (FUN_1012ce80 -> FUN_1012b9b0 with the weapon's category hash, the value
     * at the vf+0x8C pointer): this switches the inventory to weapon mode (+0x78 = 1) and makes it current */
    {
        typedef void (__attribute__((thiscall)) *sel_t)(void *inv, unsigned *cat);
        unsigned cat = IsBadReadPtr((void *)slot, 4) ? 0 : *(unsigned *)slot;
        if (cat) ((sel_t)(g_base + 0x12CE80))(inv, &cat);
        logf_("%s: %s entity %llu weapon %p category %08x -> inventory %p (old %p), current weapon now %p", who, arch, wid, wc,
              cat, inv, old, ((cur_t)(g_base + 0x127DA0))(inv));
    }
    return 1;
}

static void native_cmd(const char *ln)
{
    unsigned long long id;
    unsigned long a, pv, k0, k1;
    float fx, fy, fz;
    int n;
    if (sscanf(ln, "peek %lx %d", &a, &n) == 2) {
        if (IsBadReadPtr((void *)a, n)) logf_("peek %lx: unreadable", a);
        else hexdump_((const BYTE *)a, n);
    } else if (sscanf(ln, "ent %llu %d", &id, &n) == 2) {
        void **pm = (void **)(g_base + RVA_ENTMGR_PTR);
        void *holder = NULL;
        void *obj;
        if (IsBadReadPtr(pm, 4) || !*pm) { logf_("ent: entity manager null"); return; }
        ((getent_t)(g_base + RVA_GETENTITY))(*pm, &holder, (unsigned)id, (unsigned)(id >> 32));
        if (!holder || IsBadReadPtr(holder, 16)) { logf_("ent %llu: no holder", id); return; }
        obj = *(void **)((BYTE *)holder + 0xC);
        logf_("ent %llu: holder=%p obj=%p refs=%d", id, holder, obj, *(int *)((BYTE *)holder + 8));
        if (obj && !IsBadReadPtr(obj, n)) { logf_("vtable=%p", *(void **)obj); hexdump_((const BYTE *)obj, n); }
    } else if (sscanf(ln, "pos %llu", &id) == 1) {
        void **pm = (void **)(g_base + RVA_ENTMGR_PTR);
        void *holder = NULL;
        BYTE *obj;
        if (IsBadReadPtr(pm, 4) || !*pm) { logf_("pos: entity manager null"); return; }
        ((getent_t)(g_base + RVA_GETENTITY))(*pm, &holder, (unsigned)id, (unsigned)(id >> 32));
        if (!holder || IsBadReadPtr(holder, 16) || !*(void **)((BYTE *)holder + 0xC)) { logf_("pos %llu: no entity", id); return; }
        obj = *(BYTE **)((BYTE *)holder + 0xC);
        logf_("pos %llu: x=%.3f y=%.3f z=%.3f dir=(%.3f,%.3f)", id, *(float *)(obj + 0x60), *(float *)(obj + 0x64), *(float *)(obj + 0x68), *(float *)(obj + 0x30), *(float *)(obj + 0x34));
    } else if (sscanf(ln, "setpos %llu %f %f %f", &id, &fx, &fy, &fz) == 4) {
        void **pm = (void **)(g_base + RVA_ENTMGR_PTR);
        void *holder = NULL;
        BYTE *obj;
        if (IsBadReadPtr(pm, 4) || !*pm) { logf_("setpos: entity manager null"); return; }
        ((getent_t)(g_base + RVA_GETENTITY))(*pm, &holder, (unsigned)id, (unsigned)(id >> 32));
        if (!holder || IsBadReadPtr(holder, 16) || !*(void **)((BYTE *)holder + 0xC)) { logf_("setpos %llu: no entity", id); return; }
        obj = *(BYTE **)((BYTE *)holder + 0xC);
        *(float *)(obj + 0x60) = fx; *(float *)(obj + 0x64) = fy; *(float *)(obj + 0x68) = fz;
        logf_("setpos %llu: wrote %.3f %.3f %.3f", id, fx, fy, fz);
    } else if (sscanf(ln, "netstart %u %31s %u %llu", &g_net_lport, g_net_pip, &g_net_pport, &g_net_id) == 4) {
        g_net_cfg = 1;
        logf_("netstart requested: local %u peer %s:%u entity %llu", g_net_lport, g_net_pip, g_net_pport, g_net_id);
    } else if (strncmp(ln, "netstop", 7) == 0) {
        g_net_cfg = 0;
        logf_("netstop");
    } else if (sscanf(ln, "walk %f %f %f", &fx, &fy, &fz) == 3) {
        if (!g_bodymat || IsBadReadPtr(g_bodymat, 0x40)) { logf_("walk: no cached body"); return; }
        g_walk_c[0] = *(float *)(g_bodymat + 0x30); g_walk_c[1] = *(float *)(g_bodymat + 0x34); g_walk_c[2] = *(float *)(g_bodymat + 0x38);
        g_walk_r = fx; g_walk_secs = fy; g_walk_speed = fz; g_walk_t0 = GetTickCount(); g_walk = 1;
        logf_("walk: radius %.2f for %.1f s at %.2f m/s around %.2f %.2f %.2f (start on circle edge)", fx, fy, fz, g_walk_c[0], g_walk_c[1], g_walk_c[2]);
    } else if (sscanf(ln, "bodyvel %f %f %f %lx", &fx, &fy, &fz, &a) == 4) {
        if (!g_body || IsBadWritePtr(g_body + a, 12)) { logf_("bodyvel: bad body/offset"); return; }
        *(float *)(g_body + a) = fx; *(float *)(g_body + a + 4) = fy; *(float *)(g_body + a + 8) = fz;
        logf_("bodyvel: wrote %.2f %.2f %.2f at body+0x%lx", fx, fy, fz, a);
    } else if (sscanf(ln, "avvel %f %f %f %lx", &fx, &fy, &fz, &a) == 4) {
        if (!g_av_body_p || !*g_av_body_p || IsBadWritePtr(*g_av_body_p + a, 12)) { logf_("avvel: no avatar body"); return; }
        *(float *)(*g_av_body_p + a) = fx; *(float *)(*g_av_body_p + a + 4) = fy; *(float *)(*g_av_body_p + a + 8) = fz;
        logf_("avvel: wrote %.2f %.2f %.2f at avatar body+0x%lx", fx, fy, fz, a);
    } else if (sscanf(ln, "findvt %lx %lx", &a, &pv) == 2) {
        /* findvt <vtable rva> <back offset> [match]: list objects whose first word is base+rva (chunked, fault-safe
         * reads like findbody) and the 4 words at object-back (e.g. the owner struct around an embedded object);
         * with match, only objects where one of those 4 words equals it */
        static BYTE chunk[0x10000 + 0x40];
        MEMORY_BASIC_INFORMATION mbi;
        BYTE *p = NULL;
        unsigned vt = (unsigned)(g_base + a);
        unsigned long match = 0;
        int found = 0, has_match = sscanf(ln, "findvt %*x %*x %lx", &match) == 1;
        while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi && found < 64) {
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize < 0x20000000) {
                BYTE *rb = (BYTE *)mbi.BaseAddress, *rend = rb + mbi.RegionSize, *c;
                for (c = rb; c < rend && found < 64; c += 0x10000) {
                    size_t n = (size_t)(rend - c), k;
                    if (n > sizeof chunk) n = sizeof chunk;
                    if (!safe_read(c, chunk, n)) continue;
                    for (k = 0; k + 4 <= n && k < 0x10000 && found < 64; k += 4) {
                        if (*(unsigned *)(chunk + k) == vt) {
                            unsigned w[4] = { 0, 0, 0, 0 };
                            safe_read(c + k - pv, w, sizeof w);
                            if (has_match && w[0] != match && w[1] != match && w[2] != match && w[3] != match) continue;
                            logf_("findvt: object %p, at -0x%lx: %08x %08x %08x %08x", c + k, pv, w[0], w[1], w[2], w[3]);
                            found++;
                        }
                    }
                }
            }
            p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        }
        logf_("findvt done: %d object(s) with vtable RVA %lx", found, a);
    } else if (sscanf(ln, "addcomp %llu %lx", &id, &a) == 2) {
        /* addcomp <entity id> <factory rva>: create a component with the engine factory (no args) and attach it
         * with the engine's AddComponent (thiscall on the entity object, RVA 4E0D80: set owner, push, init, activate) */
        typedef void *(*factory_t)(void);
        typedef void (__attribute__((thiscall)) *addcomp_t)(void *ent, void *comp);
        void **pm = (void **)(g_base + RVA_ENTMGR_PTR);
        void *holder = NULL, *comp;
        BYTE *obj;
        if (IsBadReadPtr(pm, 4) || !*pm) { logf_("addcomp: entity manager null"); return; }
        ((getent_t)(g_base + RVA_GETENTITY))(*pm, &holder, (unsigned)id, (unsigned)(id >> 32));
        if (!holder || IsBadReadPtr(holder, 16) || !*(void **)((BYTE *)holder + 0xC)) { logf_("addcomp %llu: no entity", id); return; }
        obj = *(BYTE **)((BYTE *)holder + 0xC);
        logf_("addcomp %llu: entity %p, %u component(s) before", id, obj, *(unsigned *)(obj + 0xA0));
        comp = ((factory_t)(g_base + a))();
        if (!comp) { logf_("addcomp: factory %lx returned null", a); return; }
        logf_("addcomp: factory %lx -> %p (vtable %08x)", a, comp, *(unsigned *)comp);
        ((addcomp_t)(g_base + 0x4E0D80))(obj, comp);
        logf_("addcomp: attached %p, %u component(s) after, comp+8 = %08x", comp, *(unsigned *)(obj + 0xA0), *(unsigned *)((BYTE *)comp + 8));
    } else if (sscanf(ln, "netcompstart %lx %lx", &a, &pv) == 2) {
        /* netcompstart <component address> <remote>: the engine's net component start (thiscall RVA 4EB820) that the
         * net layer calls with 1 for objects announced by a remote station */
        typedef void (__attribute__((thiscall)) *start_t)(void *comp, int remote);
        BYTE *comp = (BYTE *)a;
        if (IsBadReadPtr(comp, 0x190)) { logf_("netcompstart: %lx not readable", a); return; }
        logf_("netcompstart %p: vtable %08x, started byte %u, calling start(%lu)", comp, *(unsigned *)comp, comp[0x44], pv);
        ((start_t)(g_base + 0x4EB820))(comp, (int)pv);
        logf_("netcompstart %p: +40 %08x, chans %08x %08x %08x, roles %u %u %u, mementos %08x %08x %08x %08x, helper %08x",
              comp, *(unsigned *)(comp + 0x40), *(unsigned *)(comp + 0x150), *(unsigned *)(comp + 0x154), *(unsigned *)(comp + 0x158),
              *(unsigned *)(comp + 0x15C), *(unsigned *)(comp + 0x160), *(unsigned *)(comp + 0x164),
              *(unsigned *)(comp + 0x168), *(unsigned *)(comp + 0x16C), *(unsigned *)(comp + 0x170), *(unsigned *)(comp + 0x174),
              *(unsigned *)(comp + 0x180));
    } else if (sscanf(ln, "avfake %f %f %f %f %f %f %f", &g_av_fake_c[0], &g_av_fake_c[1], &g_av_fake_c[2], &g_av_fake_r, &g_av_fake_secs, &g_av_fake_speed, &fx) >= 6) {
        /* avfake <cx> <cy> <cz> <radius> <secs> <speed>: replace the peer's data by a point walking a circle (needs netstart) */
        g_av_fake_t0 = GetTickCount(); g_av_fake_last = 0; g_av_fake = 1;
        logf_("avfake: circle r %.1f around %.2f %.2f %.2f for %.0f s at %.2f m/s", g_av_fake_r, g_av_fake_c[0], g_av_fake_c[1], g_av_fake_c[2], g_av_fake_secs, g_av_fake_speed);
    } else if (strncmp(ln, "avweapon ", 9) == 0) {
        /* avweapon <weapon archetype>: spawn the weapon entity and put it into the avatar's inventory the way the Lua
         * AddWeapon handler (LAB_109f9310) does for the local player: CWeapon comp (key FE01F8), slot = vf+0x8C,
         * inventory = FUN_1007e140(pawn comp), old weapon in that slot FUN_10129de0 -> FUN_1012e3e0(old, 0), then
         * FUN_101289f0(weapon) */
        char arch[96];
        if (sscanf(ln + 9, "%95s", arch) == 1) av_give_weapon(arch);
    } else if (strncmp(ln, "npcs", 4) == 0 && (ln[4] == 0 || ln[4] == ' ')) {
        /* npcs [radius] (read-only census): every AI pawn agent (CPawnAgent, vtable RVA EC5078; agent+4 = pawn entity
         * holder) with entity id, position, distance to our player, health (counters +0x44 -> +0x10 / +0x14) and
         * archetype name (Lua GetEntityName) for those within the radius (default 120 m) */
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        static BYTE chunk[0x10000];
        MEMORY_BASIC_INFORMATION mbi;
        BYTE *p = NULL, *me;
        void *mh = NULL;
        unsigned vt = (unsigned)(g_base + 0xEC5078);
        float rad = 120.0f, mp[3] = { 0, 0, 0 };
        int found = 0, close = 0;
        sscanf(ln + 4, "%f", &rad);
        if (!g_net_id) { char o[32]; lua_eval("__out = tostring(GetLocalPlayerId())", o, sizeof o); g_net_id = strtoull(o, NULL, 10); }
        me = entity_obj(g_net_id, &mh);
        if (mh) (*(int *)((BYTE *)mh + 8))--;
        if (me) memcpy(mp, me + 0x60, sizeof mp);
        while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi && found < 400) {
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize < 0x20000000) {
                BYTE *rb = (BYTE *)mbi.BaseAddress, *rend = rb + mbi.RegionSize, *c;
                for (c = rb; c < rend && found < 400; c += sizeof chunk) {
                    size_t n = (size_t)(rend - c), k;
                    if (n > sizeof chunk) n = sizeof chunk;
                    if (!safe_read(c, chunk, n)) continue;
                    for (k = 0; k + 8 <= n && found < 400; k += 4) {
                        BYTE *ag = c + k, *holder, *obj, *cc, *hc;
                        float d, hp = -1, hpmax = -1;
                        char code[96], name[80] = "";
                        if (*(unsigned *)(chunk + k) != vt) continue;
                        holder = *(BYTE **)(chunk + k + 4);
                        if (!holder || IsBadReadPtr(holder, 16) || !(obj = *(BYTE **)(holder + 0xC)) || IsBadReadPtr(obj, 0x70)) continue;
                        found++;
                        d = sqrtf((*(float *)(obj + 0x60) - mp[0]) * (*(float *)(obj + 0x60) - mp[0]) +
                                  (*(float *)(obj + 0x64) - mp[1]) * (*(float *)(obj + 0x64) - mp[1]));
                        if (d > rad) continue;
                        close++;
                        cc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDF9A8));
                        if (cc && !IsBadReadPtr(cc + 0x44, 4) && (hc = *(BYTE **)(cc + 0x44)) && !IsBadReadPtr(hc, 0x18)) { hp = *(float *)(hc + 0x10); hpmax = *(float *)(hc + 0x14); }
                        snprintf(code, sizeof code, "__out = tostring(GetEntityName('%llu'))", *(unsigned long long *)holder);
                        lua_eval(code, name, sizeof name);
                        logf_("npc %llu: %s pos (%.1f %.1f %.1f) dist %.1f hp %.0f/%.0f agent %p", *(unsigned long long *)holder, name,
                              *(float *)(obj + 0x60), *(float *)(obj + 0x64), *(float *)(obj + 0x68), d, hp, hpmax, ag);
                    }
                }
            }
            p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        }
        logf_("npcs done: %d agents, %d within %.0f m", found, close, rad);
    } else if (strcmp(ln, "pawns") == 0) {
        /* pawns (read-only): every pawn net component (vtable RVA E1AE00) with its entity id, position, role bytes,
         * mementos, beautifier slots and current weapon - to compare a real MP remote player with our avatar */
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        typedef void *(__fastcall *inv_t)(void *pawn);
        typedef void *(__attribute__((thiscall)) *cur_t)(void *inv);
        static BYTE chunk[0x10000];
        MEMORY_BASIC_INFORMATION mbi;
        BYTE *p = NULL;
        unsigned vt = (unsigned)(g_base + 0xE1AE00);
        int found = 0;
        while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi && found < 32) {
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize < 0x20000000) {
                BYTE *rb = (BYTE *)mbi.BaseAddress, *rend = rb + mbi.RegionSize, *c;
                for (c = rb; c < rend && found < 32; c += sizeof chunk) {
                    size_t n = (size_t)(rend - c), k;
                    if (n > sizeof chunk) n = sizeof chunk;
                    if (!safe_read(c, chunk, n)) continue;
                    for (k = 0; k + 4 <= n && found < 32; k += 4) {
                        BYTE *comp = c + k, *holder, *obj, *bc, *pawn, *inv, *wc;
                        if (*(unsigned *)(chunk + k) != vt || IsBadReadPtr(comp, 0x190)) continue;
                        holder = *(BYTE **)(comp + 8);
                        if (!holder || IsBadReadPtr(holder, 16) || !(obj = *(BYTE **)(holder + 0xC)) || IsBadReadPtr(obj, 0xA4)) continue;
                        found++;
                        bc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4));
                        pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
                        inv = pawn ? ((inv_t)(g_base + 0x7E140))(pawn) : NULL;
                        wc = inv ? ((cur_t)(g_base + 0x127DA0))(inv) : NULL;
                        logf_("pawn %llu: comp %p pos (%.1f %.1f %.1f) +40 %u roles %u/%u/%u mementos %08x %08x %08x equip %08x wstate %08x | "
                              "beautifier main vt %08x base vt %08x | weapon %p", *(unsigned long long *)holder, comp,
                              *(float *)(obj + 0x60), *(float *)(obj + 0x64), *(float *)(obj + 0x68), *(unsigned *)(comp + 0x40),
                              *(unsigned *)(comp + 0x15C), *(unsigned *)(comp + 0x160), *(unsigned *)(comp + 0x164),
                              *(unsigned *)(comp + 0x168), *(unsigned *)(comp + 0x16C), *(unsigned *)(comp + 0x170),
                              *(unsigned *)(comp + 0x178), *(unsigned *)(comp + 0x184),
                              bc && *(void **)(bc + 0x28) ? **(unsigned **)(bc + 0x28) : 0, bc && *(void **)(bc + 0x2C) ? **(unsigned **)(bc + 0x2C) : 0, wc);
                    }
                }
            }
            p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        }
        logf_("pawns done: %d", found);
    } else if (sscanf(ln, "watchd %llu", &id) == 1) {
        /* watchd <entity id> (observation): every frame, log changes of that pawn's ThirdParty memento state bytes
         * (+0x104 bit, +0x110 flag, +0x11C mode, +0x264 fire mode, +0x1A0) and of its DesiredData flags (pawn comp
         * +0x140: +4..+7, +0xA4) - how a real remote player's fire / stance arrive */
        g_wd_id = id; g_wd_n = 0;
        logf_("watchd: watching %llu", id);
    } else if (sscanf(ln, "evlog %llu", &id) == 1) {
        /* evlog <entity id> (observation): a private vtable copy for that pawn's base beautifier whose event slot
         * (vf+0x54) counts every event type it receives and logs each new type, then calls the original */
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        void *holder = NULL;
        BYTE *obj = entity_obj(id, &holder), *bc, *bt;
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        bc = obj ? ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4)) : NULL;
        bt = bc ? *(BYTE **)(bc + 0x2C) : NULL;
        if (!bt || IsBadReadPtr(*(void **)bt, sizeof g_ev_vt)) { logf_("evlog %llu: no base beautifier", id); return; }
        if (*(void ***)bt != g_ev_vt) {
            memcpy(g_ev_vt, *(void **)bt, sizeof g_ev_vt);
            g_ev_orig = g_ev_vt[0x54 / 4]; g_ev_vt[0x54 / 4] = (void *)ev_hook;
            *(void ***)bt = g_ev_vt;
        }
        logf_("evlog %llu: base beautifier %p hooked (fire-bullet type id %08x)", id, bt, *(unsigned *)(g_base + 0xFE15F8));
    } else if (sscanf(ln, "avmpflag %d", &n) == 1) {
        g_mf_on = n != 0;
        logf_("avmpflag: avatar main beautifier updates %s the MP flag", g_mf_on ? "with" : "without");
    } else if (strcmp(ln, "npcstat") == 0) {
        npc_stat();
    } else if (strncmp(ln, "npcsync ", 8) == 0) {
        float rad = 0;
        g_npc_role = strstr(ln, "host") ? 1 : strstr(ln, "join") ? 2 : 0;
        if (sscanf(ln + 8, "%*s %f", &rad) == 1 && rad > 0) g_npc_rad = rad;
        logf_("npcsync: %s (radius %.0f m)", g_npc_role == 1 ? "host (sending the NPCs around us)" : g_npc_role == 2 ? "join (NPCs follow the host)" : "off", g_npc_rad);
    } else if (strncmp(ln, "worldsync ", 10) == 0) {
        g_ws_role = strstr(ln + 10, "host") ? 1 : strstr(ln + 10, "join") ? 2 : 0;
        logf_("worldsync: %s", g_ws_role == 1 ? "host (sending time of day)" : g_ws_role == 2 ? "join (following the host's time)" : "off");
        if (g_ws_role) env_obj();
    } else if (sscanf(ln, "settod %f", &fx) == 1) {
        BYTE *env = env_obj();
        if (env) { *(float *)(env + 0x260) = fx; ((void (__attribute__((thiscall)) *)(void *))(g_base + 0x11AC10))(env);
                   ((void (__attribute__((thiscall)) *)(void *))(g_base + 0x11D450))(env); logf_("settod: time set to %.4f", fx); }
    } else if (sscanf(ln, "avkp %f", &fx) == 1) {
        g_av_kp = fx;
        logf_("avkp: avatar position-error gain %.2f%s", g_av_kp, g_av_kp > 0 ? "" : " (off: game velocity only)");
    } else if (strncmp(ln, "avfiremode ", 11) == 0) {
        g_av_directfire = strstr(ln + 11, "direct") ? 1 : strstr(ln + 11, "event") ? 2 : 0;
        logf_("avfiremode: %s", g_av_directfire == 1 ? "direct (weapon vf+0x80 + event 0x121ADE93)" : g_av_directfire == 2 ? "event only (0x121ADE93)" :
              "state (weapon graph from the replicated fire bit)");
    } else if (strncmp(ln, "lanfwd ", 7) == 0) {
        g_lanfwd = inet_addr(ln + 7);
        if (g_lanfwd == INADDR_NONE) g_lanfwd = 0;
        logf_("lanfwd: broadcasts also go to %s", g_lanfwd ? ln + 7 : "(off)");
    } else if (strncmp(ln, "dumpd ", 6) == 0) {
        int secs = 60;
        g_dd_id = strtoull(ln + 6, NULL, 10);
        { const char *sp = strchr(ln + 6, ' '); if (sp) secs = atoi(sp + 1); }
        g_dd_until = GetTickCount() + secs * 1000u;
        logf_("dumpd: NPC %llu for %d s", g_dd_id, secs);
    } else if (strncmp(ln, "savegame", 8) == 0) {
        /* the pause menu's save button: FUN_10735f20(char), a method of the menu page (vtable slot at RVA E9E104) that
         * takes its context from the game's globals and returns with RET 4; 0 saves as "quicksave.<n>", the game names
         * the file (random number). Runs on the main thread like the button. */
        int arg = atoi(ln + 8);
        logf_("savegame: calling the menu's save (%d)", arg);
        ((void (__stdcall *)(char))(g_base + 0x735F20))((char)arg);
        logf_("savegame: returned");
    } else if (strncmp(ln, "npcrespawn ", 11) == 0) {
        g_npcrespawn = atoi(ln + 11) != 0;
        logf_("npcrespawn: %s", g_npcrespawn ? "on" : "off");
    } else if (strncmp(ln, "npcanim ", 8) == 0) {
        g_npcanim = atoi(ln + 8) != 0;
        logf_("npcanim: NPC animation graph inputs %s", g_npcanim ? "follow the host" : "are the puppets' own");
    } else if (strncmp(ln, "npcev ", 6) == 0) {
        g_npcev_left = atoi(ln + 6);
        logf_("npcev: logging the next %d events on synced NPCs", g_npcev_left);
    } else if (strncmp(ln, "hitsync ", 8) == 0) {
        g_hitsync = atoi(ln + 8) != 0;
        logf_("hitsync: %s", g_hitsync ? "on (the shooter's window decides hits between players)" : "off (the avatar's replayed shots hurt us)");
    } else if (strncmp(ln, "stimlog", 7) == 0) {
        unsigned long long sid = strtoull(ln + 7, NULL, 10);
        g_st_verbose = 1;
        if (strstr(ln, "avatar")) stim_install(g_av_id, 0);
        else if (strstr(ln, "me") || !sid) stim_install(g_net_id, 1);
        else stim_install(sid, 0);
    } else if (strncmp(ln, "xhook", 5) == 0) {
        /* xhook [avatar | <entity id>]: hook the shot method of the current weapon object X of our player (default), the
         * avatar, or any pawn entity (e.g. a remote MP player) */
        typedef void *(__fastcall *inv_t)(void *pawn);
        typedef void *(__attribute__((thiscall)) *cur_t)(void *inv);
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        void *holder = NULL, *pawn, *inv, *wc;
        unsigned long long xid = strstr(ln, "avatar") ? g_av_id : strtoull(ln + 5, NULL, 10) ? strtoull(ln + 5, NULL, 10) : g_net_id;
        BYTE *obj = entity_obj(xid, &holder), *x;
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        pawn = obj ? ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)) : NULL;
        inv = pawn ? ((inv_t)(g_base + 0x7E140))(pawn) : NULL;
        wc = inv ? ((cur_t)(g_base + 0x127DA0))(inv) : NULL;
        x = wc ? *(BYTE **)(*(BYTE **)((BYTE *)wc + 0x24) + 0x54) : NULL;
        if (!x || IsBadReadPtr(*(void **)x, sizeof g_xh_vt)) { logf_("xhook: no weapon object (weapon %p)", wc); return; }
        if (*(void ***)x != g_xh_vt) {
            memcpy(g_xh_vt, *(void **)x, sizeof g_xh_vt);
            g_xh_orig = g_xh_vt[0x20 / 4];
            g_xh_vt[0x20 / 4] = (void *)xshot_hook;
            *(void ***)x = g_xh_vt; g_xh_obj = x; g_xh_n = 0;
        }
        logf_("xhook: weapon %p object %p, original shot slot %p", wc, x, g_xh_orig);
    } else if (strcmp(ln, "avdraw") == 0) {
        /* avdraw: draw the avatar's weapon like the Lua DrawWeapon handler (FUN_109f8460) does for the local player:
         * inventory mode FUN_10125f40 == 1 and no current weapon -> FUN_10129d90 (pending?) or FUN_1012b310 (select),
         * then event 0x2A47E3A3 to the pawn (vf+0x78 -> FUN_1029da10) */
        typedef void *(__fastcall *inv_t)(void *pawn);
        typedef int (__attribute__((thiscall)) *iget_t)(void *inv);
        typedef char (__attribute__((thiscall)) *sel_t)(void *inv);
        typedef void *(__attribute__((thiscall)) *tags_t)(void *pawn);
        typedef void (__attribute__((thiscall)) *ev_t)(void *tags, unsigned ev);
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        void *holder = NULL, *pawn, *inv, *tags;
        BYTE *obj = g_av_id ? entity_obj(g_av_id, &holder) : NULL;
        int mode, cur, pend = -1;
        char ok = 0;
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        pawn = obj ? ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)) : NULL;
        inv = pawn ? ((inv_t)(g_base + 0x7E140))(pawn) : NULL;
        if (!inv) { logf_("avdraw: no avatar inventory"); return; }
        mode = ((iget_t)(g_base + 0x125F40))(inv);
        cur = ((iget_t)(g_base + 0x127DA0))(inv);
        if (mode == 1 && !cur) {
            pend = ((iget_t)(g_base + 0x129D90))(inv);
            ok = pend ? 1 : ((sel_t)(g_base + 0x12B310))(inv);
        }
        if (ok) {
            tags = ((tags_t)(*(void ***)pawn)[0x78 / 4])(pawn);
            if (tags) ((ev_t)(g_base + 0x29DA10))(tags, 0x2A47E3A3u);
        }
        logf_("avdraw: inventory %p mode %d current %08x pending %08x select %d -> current now %08x", inv, mode, cur, pend, ok,
              ((iget_t)(g_base + 0x127DA0))(inv));
    } else if (sscanf(ln, "npslot %lx %lx %lx %lx", &a, &pv, &k0, &k1) == 4) {
        /* npslot <slot +28|+2C> <k0> <profile> <pose> (hex, ffffffff = none): put that repository beautifier in a slot of
         * the NetPlayer avatar */
        void *holder = NULL;
        BYTE *obj = g_av_id ? entity_obj(g_av_id, &holder) : NULL;
        unsigned k2 = 0xFFFFFFFFu;
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        sscanf(ln, "npslot %*x %*x %*x %x", &k2);
        if (!obj) logf_("npslot: no avatar");
        else np_slot(obj, (int)a, (unsigned)pv, (unsigned)k0, k2);
    } else if (strncmp(ln, "avmode", 6) == 0) {
        /* avmode np [archetype] [yaw offset] [offset x] [offset y] | avmode body: how the network avatar is shown */
        char arch[96] = "";
        float yo = 0, ox = 0, oy = 0;
        if (strncmp(ln + 6, " np", 3) == 0) {
            if (sscanf(ln + 9, "%95s %f %f %f", arch, &yo, &ox, &oy) >= 1 && arch[0]) strcpy(g_av_arch, arch);
            g_av_yawoff = yo; g_av_off[0] = ox; g_av_off[1] = oy;
            g_av_np = 1;
        } else g_av_np = 0;
        if (g_av_id) av_remove();
        logf_("avmode: %s (archetype %s, yaw offset %.1f, test offset %.2f %.2f)", g_av_np ? "netplayer" : "body", g_av_arch, g_av_yawoff, g_av_off[0], g_av_off[1]);
    } else if (sscanf(ln, "getcomp %llu %lx", &id, &a) == 2) {
        /* getcomp <entity id> <type key rva>: find a component by type (FUN_104e2cc0) and log its address, the object
         * at +0x44 and the first 0x60 bytes of both (e.g. key FDF9A8 = CCountersComponentGO) */
        typedef void *(__attribute__((thiscall)) *gc_t)(void *ent, void *key);
        void *holder = NULL;
        BYTE *obj = entity_obj(id, &holder), *c, *sub;
        int k;
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        if (!obj) { logf_("getcomp %llu: no entity", id); return; }
        c = ((gc_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + a));
        logf_("getcomp %llu %lx: component %p", id, a, c);
        if (!c || IsBadReadPtr(c, 0x60)) return;
        for (k = 0; k < 0x60; k += 16) logf_("  comp+%02x: %08x %08x %08x %08x", k, *(unsigned *)(c + k), *(unsigned *)(c + k + 4), *(unsigned *)(c + k + 8), *(unsigned *)(c + k + 12));
        sub = *(BYTE **)(c + 0x44);
        if (!sub || IsBadReadPtr(sub, 0x60)) return;
        for (k = 0; k < 0x60; k += 16) logf_("  sub+%02x: %08x %08x %08x %08x", k, *(unsigned *)(sub + k), *(unsigned *)(sub + k + 4), *(unsigned *)(sub + k + 8), *(unsigned *)(sub + k + 12));
    } else if (sscanf(ln, "tpbuild %lx", &a) == 1) {
        /* tpbuild <component address>: give a not-started pawn net component only the ThirdParty pieces that the
         * NetPlayer beautifier reads (remote flag, started flag, +0x164 = 1, ThirdParty memento at +0x170) */
        typedef void *(*factory_t)(void);
        BYTE *comp = (BYTE *)a;
        void *mem;
        if (IsBadWritePtr(comp, 0x190) || *(unsigned *)comp != (unsigned)(g_base + 0xE1AE00)) { logf_("tpbuild: %lx is not a pawn net component", a); return; }
        if (comp[0x44]) { logf_("tpbuild: %p already started", comp); return; }
        mem = ((factory_t)(g_base + 0x40110))();
        if (!mem) { logf_("tpbuild: memento factory returned null"); return; }
        *(unsigned *)(comp + 0x40) = 1;
        comp[0x44] = 1;
        *(unsigned *)(comp + 0x164) = 1;
        *(void **)(comp + 0x170) = mem;
        logf_("tpbuild %p: memento %p (vtable %08x), +164 = 1, started", comp, mem, *(unsigned *)mem);
    } else if (sscanf(ln, "tppos %lx %lx %f %f %f", &a, &pv, &fx, &fy, &fz) == 5) {
        /* tppos <memento> <block offset> <x> <y> <z>: write a position into a ThirdParty memento in the quantized form
         * FUN_100a5040 reads (per axis: cell*4 + frac*scale/(2^bits-1); frac at +14/+28/+3C, bits at +1C/+30/+44, cell at
         * +50/+5C/+68 from the block), keeping the bit counts the memento constructor chose; marks the fields dirty */
        static const unsigned fo[3] = { 0x14, 0x28, 0x3C }, bo[3] = { 0x1C, 0x30, 0x44 }, co[3] = { 0x50, 0x5C, 0x68 };
        static const unsigned dirty[6] = { 0x10, 0x24, 0x38, 0x4C, 0x58, 0x64 };
        BYTE *blk = (BYTE *)a + pv;
        float v[3], scale = *(float *)(g_base + 0xE98754);
        int k;
        v[0] = fx; v[1] = fy; v[2] = fz;
        if (IsBadWritePtr(blk, 0x70)) { logf_("tppos: %p not writable", blk); return; }
        for (k = 0; k < 3; k++) {
            unsigned bits = *(unsigned *)(blk + bo[k]), maxv;
            int cell = (int)floorf(v[k] / 4.0f);
            float rem = v[k] - cell * 4.0f;
            if (bits == 0 || bits > 31) { logf_("tppos: axis %d has %u bits, not writing", k, bits); return; }
            maxv = (1u << bits) - 1;
            *(int *)(blk + co[k]) = cell;
            *(int *)(blk + fo[k]) = (int)(rem / scale * maxv + 0.5f);
        }
        for (k = 0; k < 6; k++) blk[dirty[k]] = 1;
        logf_("tppos %p+%lx: scale %.3f, bits %u %u %u, cells %d %d %d, fracs %d %d %d", (void *)a, pv, scale,
              *(unsigned *)(blk + 0x1C), *(unsigned *)(blk + 0x30), *(unsigned *)(blk + 0x44),
              *(int *)(blk + 0x50), *(int *)(blk + 0x5C), *(int *)(blk + 0x68),
              *(int *)(blk + 0x14), *(int *)(blk + 0x28), *(int *)(blk + 0x3C));
    } else if (strncmp(ln, "tpvec ", 6) == 0) {
        /* tpvec <memento> <block offset> <scale rva> <n> <v0> [v1 [v2]]: write n quantized floats (frac at block+8+0x14*i,
         * bits at block+0x10+0x14*i, dirty at block+4+0x14*i; value = frac*scale/(2^bits-1)) ??? velocity block 0x70 with
         * scale RVA ED9D34, aim angles block 0xAC / 0xD4 with scale RVA E11D38 */
        unsigned long mb, off, srva;
        int n = 0, k;
        float vv[3] = { 0, 0, 0 }, scale;
        BYTE *blk;
        if (sscanf(ln + 6, "%lx %lx %lx %d %f %f %f", &mb, &off, &srva, &n, &vv[0], &vv[1], &vv[2]) < 5 || n < 1 || n > 3) { logf_("tpvec: bad args"); return; }
        blk = (BYTE *)mb + off;
        scale = *(float *)(g_base + srva);
        if (IsBadWritePtr(blk, 0x40) || scale == 0.0f) { logf_("tpvec: bad block %p or scale %f", blk, scale); return; }
        for (k = 0; k < n; k++) {
            BYTE *f = blk + 0x14 * k;
            unsigned bits = *(unsigned *)(f + 0x10);
            if (bits == 0 || bits > 31) { logf_("tpvec: field %d has %u bits, not writing", k, bits); return; }
            *(int *)(f + 8) = (int)lrintf(vv[k] / scale * (float)((1u << bits) - 1));
            f[4] = 1;
        }
        logf_("tpvec %p+%lx: scale %.4f, n %d, values %.3f %.3f %.3f -> %d %d %d", (void *)mb, off, scale, n, vv[0], vv[1], vv[2],
              *(int *)(blk + 8), n > 1 ? *(int *)(blk + 0x1C) : 0, n > 2 ? *(int *)(blk + 0x30) : 0);
    } else if (sscanf(ln, "beautnet %llu", &id) == 1) {
        /* beautnet <entity id>: replace the pawn's BASE beautifier (CPawnBeautifierComponent +0x2C) with a clone of the
         * repository prototype for {network, -, -} (CPawnBeautifierNetPlayer), the way FUN_100e9380 installs one */
        typedef void *(__attribute__((thiscall)) *getcomp_t)(void *ent, void *key);
        typedef void *(*getrepo_t)(void);
        typedef void *(__attribute__((thiscall)) *find_t)(void *repo, unsigned *key);
        typedef void (__attribute__((thiscall)) *vf0_t)(void *self);
        typedef void (__attribute__((thiscall)) *vfdel_t)(void *self, int flags);
        typedef void *(__attribute__((thiscall)) *vfclone_t)(void *self);
        typedef void (__attribute__((thiscall)) *vfbind_t)(void *self, void *pawn, void *bcomp);
        void **pm = (void **)(g_base + RVA_ENTMGR_PTR);
        void *holder = NULL, *bc, *pawn, *repo, *proto, *old, *nb;
        unsigned key[3];
        BYTE *obj;
        if (IsBadReadPtr(pm, 4) || !*pm) { logf_("beautnet: entity manager null"); return; }
        ((getent_t)(g_base + RVA_GETENTITY))(*pm, &holder, (unsigned)id, (unsigned)(id >> 32));
        if (!holder || IsBadReadPtr(holder, 16) || !*(void **)((BYTE *)holder + 0xC)) { logf_("beautnet %llu: no entity", id); return; }
        obj = *(BYTE **)((BYTE *)holder + 0xC);
        bc = ((getcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4));
        pawn = ((getcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
        repo = ((getrepo_t)(g_base + 0xD4710))();
        if (!bc || !pawn || !repo) { logf_("beautnet: beautifier comp %p, pawn %p, repository %p", bc, pawn, repo); return; }
        key[0] = 0x608487bc; key[1] = key[2] = *(unsigned *)(g_base + 0xE2C55C);
        proto = ((find_t)(g_base + 0xD3DB0))(repo, key);
        old = *(void **)((BYTE *)bc + 0x2C);
        logf_("beautnet %llu: comp %p (main %p, base %p, key %08x %08x %08x), pawn %p, network proto %p",
              id, bc, *(void **)((BYTE *)bc + 0x28), old, *(unsigned *)((BYTE *)bc + 0x1C), *(unsigned *)((BYTE *)bc + 0x20),
              *(unsigned *)((BYTE *)bc + 0x24), pawn, proto);
        if (!proto) return;
        if (old) {
            ((vf0_t)(*(void ***)old)[0x88 / 4])(old);
            ((vfdel_t)(*(void ***)old)[0])(old, 1);
        }
        nb = ((vfclone_t)(*(void ***)proto)[0x78 / 4])(proto);
        *(void **)((BYTE *)bc + 0x2C) = nb;
        if (nb) {
            ((vfbind_t)(*(void ***)nb)[0x8C / 4])(nb, pawn, bc);
            ((vf0_t)(*(void ***)nb)[0x84 / 4])(nb);
        }
        logf_("beautnet %llu: base beautifier now %p (vtable %08x)", id, nb, nb ? *(unsigned *)nb : 0);
    } else if (sscanf(ln, "findbody %llu", &id) == 1) {
        find_body(id, &g_body, &g_bodymat, NULL);
    } else if (strncmp(ln, "posb", 4) == 0) {
        if (!g_bodymat || IsBadReadPtr(g_bodymat, 0x40) || *(unsigned *)g_body != (unsigned)(g_base + RVA_BODY_VTABLE)) logf_("posb: no valid cached body");
        else logf_("posb: %.3f %.3f %.3f", *(float *)(g_bodymat + 0x30), *(float *)(g_bodymat + 0x34), *(float *)(g_bodymat + 0x38));
    } else if (sscanf(ln, "tpb %f %f %f", &fx, &fy, &fz) == 3) {
        if (!g_bodymat || IsBadWritePtr(g_bodymat, 0x40) || *(unsigned *)g_body != (unsigned)(g_base + RVA_BODY_VTABLE)) logf_("tpb: no valid cached body");
        else {
            *(float *)(g_bodymat + 0x30) = fx; *(float *)(g_bodymat + 0x34) = fy; *(float *)(g_bodymat + 0x38) = fz;
            logf_("tpb: wrote %.3f %.3f %.3f", fx, fy, fz);
        }
    } else if (strncmp(ln, "follow ", 7) == 0 || strncmp(ln, "tp ", 3) == 0) {
        int tp = ln[0] == 't';
        char *c = (char *)ln + (tp ? 3 : 7);
        void *holder = NULL;
        BYTE *obj, *cur;
        unsigned long long eid = strtoull(c, &c, 10);
        float v[3] = { 0, 0, 0 };
        int nv = 0, ok = 1;
        unsigned long offs[12];
        int no = 0, k;
        if (tp) { for (nv = 0; nv < 3; nv++) v[nv] = strtof(c, &c); }
        while (*c && no < 12) { char *e; unsigned long o = strtoul(c, &e, 16); if (e == c) break; offs[no++] = o; c = e; }
        obj = entity_obj(eid, &holder);
        cur = obj;
        for (k = 0; k < no && cur && ok; k++) {
            if (IsBadReadPtr(cur + offs[k], 4)) { ok = 0; break; }
            cur = *(BYTE **)(cur + offs[k]);
        }
        if (!cur || !ok || IsBadReadPtr(cur, 0x40)) logf_("%s %llu: chain broken at step %d", tp ? "tp" : "follow", eid, k);
        else if (tp) {
            *(float *)(cur + 0x30) = v[0]; *(float *)(cur + 0x34) = v[1]; *(float *)(cur + 0x38) = v[2];
            logf_("tp %llu: wrote %.3f %.3f %.3f at %p+0x30", eid, v[0], v[1], v[2], cur);
        } else {
            float *f = (float *)(cur + 0x30);
            logf_("follow %llu: end %p pos %.3f %.3f %.3f (entity %.3f %.3f %.3f)", eid, cur, f[0], f[1], f[2], *(float *)(obj + 0x60), *(float *)(obj + 0x64), *(float *)(obj + 0x68));
        }
        if (holder) (*(int *)((BYTE *)holder + 8))--;
    } else if (sscanf(ln, "scan %f %f", &fx, &fy) == 2) {
        MEMORY_BASIC_INFORMATION mbi;
        BYTE *p = NULL;
        int found = 0;
        logf_("scan for x=%.3f y=%.3f", fx, fy);
        while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi) {
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && mbi.RegionSize < 0x20000000) {
                BYTE *q = (BYTE *)mbi.BaseAddress;
                BYTE *end = q + mbi.RegionSize - 24;
                for (; q < end; q += 4) {
                    if (fabsf(*(float *)q - fx) < 0.01f) {
                        int k;
                        for (k = 4; k <= 16; k += 4) {
                            if (fabsf(*(float *)(q + k) - fy) < 0.01f) {
                                logf_("SCAN %p y@+%d z=%.3f %s", q, k, *(float *)(q + 8), (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) ? "rw" : "ro");
                                found++;
                                break;
                            }
                        }
                    }
                }
            }
            p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
            if (found > 2000) break;
        }
        logf_("scan done, %d hits", found);
    } else if (sscanf(ln, "pokef %lx %f", &a, &fx) == 2) {
        if (IsBadWritePtr((void *)a, 4)) logf_("pokef %lx: not writable", a);
        else { *(float *)a = fx; logf_("pokef %lx = %.3f", a, fx); }
    } else if (sscanf(ln, "hold %llu %f %f %f", &id, &fx, &fy, &fz) == 4) {
        g_hold_id = id; g_hold_pos[0] = fx; g_hold_pos[1] = fy; g_hold_pos[2] = fz; g_hold_ticks = 0; g_hold = 1;
        logf_("hold on: %llu -> %.3f %.3f %.3f", id, fx, fy, fz);
    } else if (strncmp(ln, "unhold", 6) == 0) {
        g_hold = 0;
        logf_("hold off after %lu ticks", g_hold_ticks);
    } else if (sscanf(ln, "poke %lx %lx", &a, &pv) == 2) {
        if (IsBadWritePtr((void *)a, 4)) logf_("poke %lx: not writable", a);
        else { *(unsigned long *)a = pv; logf_("poke %lx = %08lx", a, pv); }
    } else logf_("native: unknown command: %s", ln);
}

static void run_native(void)
{
    FILE *f = fopen(g_natpath, "rb");
    char ln[256];
    if (!f) return;
    while (fgets(ln, sizeof ln, f)) {
        ln[strcspn(ln, "\r\n")] = 0;
        if (ln[0]) native_cmd(ln);
    }
    fclose(f);
    remove(g_natpath);
    logf_("native commands done");
}


/* ---- per-frame position hold (test) ---- */
static BYTE *entity_obj(unsigned long long id, void **holder_out)
{
    void **pm = (void **)(g_base + RVA_ENTMGR_PTR);
    void *holder = NULL;
    if (IsBadReadPtr(pm, 4) || !*pm) return NULL;
    ((getent_t)(g_base + RVA_GETENTITY))(*pm, &holder, (unsigned)id, (unsigned)(id >> 32));
    if (!holder || IsBadReadPtr(holder, 16)) return NULL;
    *holder_out = holder;
    return *(BYTE **)((BYTE *)holder + 0xC);
}

static void hold_tick(void)
{
    void *holder = NULL;
    BYTE *obj;
    if (!g_hold || g_nstates == 0 || GetCurrentThreadId() != g_states[0].thread) return;
    obj = entity_obj(g_hold_id, &holder);
    if (obj) {
        float *p = (float *)(obj + 0x60);
        g_hold_ticks++;
        if (g_hold_ticks <= 10 || g_hold_ticks % 120 == 0)
            logf_("hold tick %lu: engine left %.3f %.3f %.3f", g_hold_ticks, p[0], p[1], p[2]);
        p[0] = g_hold_pos[0]; p[1] = g_hold_pos[1]; p[2] = g_hold_pos[2];
    }
    if (holder) (*(int *)((BYTE *)holder + 8))--;
}

/* ---- own UDP transport: position exchange between two copies ---- */
#pragma pack(push, 1)
typedef struct { unsigned magic, seq; float pos[3]; float dir[2]; } NetPkt;
/* extended packet: NetPkt plus raw fields of the game's own ThirdParty memento for the sender's player, filled by the
 * game's encoder FUN_100a6ec0 (velocity and aim angles as quantized ints, both sides use the same bit counts), and
 * the stance bit (+0x104), move mode (+0x11C) and flag (+0x110). Old 28-byte packets are still accepted. */
typedef struct { NetPkt b; int vel[3]; int aim[4]; unsigned char s104, s11c, s110, valid; } NetPktX;
/* v2: plus the archetype name of the weapon in the sender's hands ("" = none / holstered); v3: plus the last bullet
 * the sender fired (CWeaponEventFireBullet: sequence, point +0x40, target point +0x4C, mode +0x64) */
typedef struct { NetPktX x; char weap[48]; } NetPktX2;
typedef struct { NetPktX2 w; unsigned shot_seq; float shot_p[3], shot_t[3]; int shot_mode; } NetPktX3;
/* v4: plus world state from the host (worldsync host): time of day (environment object +0x260, fraction of a day)
 * and day counter (+0x4EC); world_valid = 1 when sent by a host */
typedef struct { NetPktX3 s; float tod; int day; int world_valid; } NetPktX4;
#pragma pack(pop)
#define NET_MAGIC 0x43324346u
static SOCKET g_ns = INVALID_SOCKET;
static struct sockaddr_in g_peer;
static DWORD g_net_lastsend, g_net_lastlog, g_net_lastfind, g_net_lastrx;
static unsigned g_net_seq, g_net_tx, g_net_rx, g_net_drop;
static NetPkt g_remote;
static NetPktX g_rx_ext;          /* last extended fields from the peer (valid = 0 when the peer sends old packets) */
static BYTE *g_tx_mem, g_tx_this[0x40], *g_av_comp;
static void *g_tx_wcur;                     /* sender: weapon component last seen in our hands */
static char g_tx_weap[48], g_rx_weap[48], g_av_weap[48];
/* shots: our player's bullets seen by the hooked beautifier event slot, and the peer's last bullet */
static unsigned g_shot_seq, g_rx_shot_seq, g_av_shot_seq;
static float g_shot_p[3], g_shot_t[3], g_rx_shot_p[3], g_rx_shot_t[3];
static int g_shot_mode, g_rx_shot_mode;
static void *g_shot_bt, *g_shot_vt[64], *g_shot_orig;
static DWORD g_av_weap_try;
static void np_watch(void);
static unsigned g_tx_ok, g_tx_lastlog;
/* world sync: the host sends its time of day and day counter, the joiner follows (worldsync host | join | off) */
static int g_ws_role, g_rx_world, g_rx_day;
static float g_rx_tod;
static BYTE *g_env;
static BYTE *env_obj(void)
{
    /* the environment / time-of-day object (ctor FUN_10123d00, vtable RVA E1F190, second vtable E1F168) */
    MEMORY_BASIC_INFORMATION mbi;
    BYTE *p = NULL;
    static BYTE chunk[0x10000];
    unsigned v1 = (unsigned)(g_base + 0xE1F190), v2 = (unsigned)(g_base + 0xE1F168);
    if (g_env && !IsBadReadPtr(g_env, 0x500) && *(unsigned *)g_env == v1) return g_env;
    g_env = NULL;
    while (!g_env && VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize < 0x20000000) {
            BYTE *rb = (BYTE *)mbi.BaseAddress, *rend = rb + mbi.RegionSize, *c;
            for (c = rb; c < rend && !g_env; c += sizeof chunk) {
                size_t n = (size_t)(rend - c), k;
                if (n > sizeof chunk) n = sizeof chunk;
                if (!safe_read(c, chunk, n)) continue;
                for (k = 0; k + 8 <= n; k += 4)
                    if (*(unsigned *)(chunk + k) == v1 && *(unsigned *)(chunk + k + 4) == v2) { g_env = c + k; break; }
            }
        }
        p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }
    if (g_env) logf_("worldsync: environment object %p (time %.4f, day %d)", g_env, *(float *)(g_env + 0x260), *(int *)(g_env + 0x4EC));
    return g_env;
}
static void world_tick(DWORD now)
{
    /* joiner: follow the host's time when it differs by more than ~2 game minutes; FUN_1011ac10 / FUN_1011d450 are
     * what the time setter FUN_1011da90 calls after writing +0x260 (sky / lighting refresh) */
    static DWORD last;
    BYTE *env;
    float d;
    if (g_ws_role != 2 || !g_rx_world || now - last < 1000) return;
    last = now;
    if (!(env = env_obj())) return;
    d = *(float *)(env + 0x260) - g_rx_tod;
    if (d < 0) d = -d;
    if (d > 43200.0f) d = 86400.0f - d;  /* +0x260 is game seconds since midnight */
    if (d > 60.0f || *(int *)(env + 0x4EC) != g_rx_day) {
        logf_("worldsync: time %.4f day %d -> host %.4f day %d", *(float *)(env + 0x260), *(int *)(env + 0x4EC), g_rx_tod, g_rx_day);
        *(float *)(env + 0x260) = g_rx_tod; *(int *)(env + 0x4EC) = g_rx_day;
        ((void (__attribute__((thiscall)) *)(void *))(g_base + 0x11AC10))(env);
        ((void (__attribute__((thiscall)) *)(void *))(g_base + 0x11D450))(env);
    }
}
/* fire state: the encoder copies "state +4 bit 3" (on while the trigger fires) into ThirdParty +0x104, but it is sampled
 * only at send time (20 Hz) and a shot sets it for a frame or two, so the sender latches it every frame; the receiver
 * either lets the weapon graph fire from that state (default) or fires directly (`avfiremode direct`) */
static BYTE *g_tx_pawn;
static unsigned g_tx_latch, g_tx_latched, g_av_directfire;
static void fire_latch_tick(void)
{
    if (g_tx_pawn && !IsBadReadPtr(g_tx_pawn + 0x2D0, 8) && (g_tx_pawn[0x2D0 + 4] & 8)) g_tx_latch = 1;
}
static unsigned long long g_av_id;
static BYTE *g_av_body, *g_av_mat;
static void av_init_ptr(void) { g_av_body_p = &g_av_body; }
static float g_av_cur[3], g_av_dir[2];
static int g_av_have;
static DWORD g_av_lastspawn, g_av_lastfind;

/* NetPlayer avatar mode (`avmode np [archetype] [yaw offset deg] [offset x] [offset y]`): the avatar is a buddy-archetype
 * pawn with an added pawn net component in the ThirdParty role and the CPawnBeautifierNetPlayer base beautifier, and
 * the probe writes the ThirdParty memento every tick the way the net layer would (see local notes for the layout) */
static int g_av_np;
static char g_av_arch[96] = "buddies.UFLL.UFLL_HQDoorman";
static float g_av_yawoff, g_av_off[2];
static BYTE *g_av_mem;
static int g_av_npstate;
static float g_av_lastpos[3], g_av_vel[3], g_av_logpos[3];
static DWORD g_av_lastlog;
static float g_av_hp;
static unsigned g_av_hpmax;
static int g_av_smhave;
static unsigned g_av_lastseq;
static DWORD g_av_lastt;

typedef void *(*np_factory_t)(void);
typedef void (__attribute__((thiscall)) *np_addcomp_t)(void *ent, void *comp);
typedef void *(__attribute__((thiscall)) *np_getcomp_t)(void *ent, void *key);
typedef void *(__attribute__((thiscall)) *np_find_t)(void *repo, unsigned *key);
typedef void (__attribute__((thiscall)) *np_vf0_t)(void *self);
typedef void (__attribute__((thiscall)) *np_vfdel_t)(void *self, int flags);
typedef void *(__attribute__((thiscall)) *np_vfclone_t)(void *self);
typedef void (__attribute__((thiscall)) *np_vfbind_t)(void *self, void *pawn, void *bcomp);

/* quantized memento field {vtable, dirty byte +4, frac +8, ?, bits +0x10}: value = frac * scale / (2^bits - 1) */
static void np_q(BYTE *f, float v, float scale)
{
    unsigned bits = *(unsigned *)(f + 0x10);
    if (bits == 0 || bits > 31) return;
    *(int *)(f + 8) = (int)lrintf(v / scale * (float)((1u << bits) - 1));
    f[4] = 1;
}

/* position block (memento+4 or +0x1A4): per axis cell*4 + frac*4/(2^bits-1); frac fields at +0xC/+0x20/+0x34, cells
 * {vtable, dirty +4, int +8} at +0x48/+0x54/+0x60 */
static void np_pos(BYTE *b, const float *p)
{
    int k;
    for (k = 0; k < 3; k++) {
        int cell = (int)floorf(p[k] / 4.0f);
        BYTE *c = b + 0x48 + 0xC * k;
        *(int *)(c + 8) = cell; c[4] = 1;
        np_q(b + 0xC + 0x14 * k, p[k] - cell * 4.0f, 4.0f);
    }
}

static float np_dq(const BYTE *f, float scale)
{
    unsigned bits = *(const unsigned *)(f + 0x10);
    if (bits == 0 || bits > 31) return 0;
    return *(const int *)(f + 8) * scale / (float)((1u << bits) - 1);
}

/* sender: let the game's own ThirdParty encoder (FUN_100a6ec0, the NetPlayer writer) fill a private memento from our
 * player and copy its velocity, aim angles, stance bit, move mode and flag into the packet. The encoder only reads
 * this+0x10 (the pawn component, as the beautifier bind FUN_105545b0 stores it), so a small fake object will do. */
/* our player's bullets: in MP the pawn's NetPlayer gets every CWeaponEventFireBullet in its event slot (vf+0x54,
 * FUN_100a5830) and keeps point / target / mode for the ThirdParty fire block. Our player has the Player beautifier
 * instead, so its base beautifier gets a private copy of its vtable with slot 0x54 pointing here: record the bullet,
 * then call the original slot. */
typedef unsigned (__attribute__((thiscall)) *bt_event_t)(void *self, int *ev);
static int g_lx_inshot, g_lx_ntypes;
static unsigned g_lx_types[8];
static unsigned __attribute__((thiscall)) shot_hook(void *self, int *ev)
{
    if (g_lx_inshot && ev && !IsBadReadPtr(ev, 8) && g_lx_ntypes < 8) {
        /* research: every event type the player's beautifier gets while our weapon is shooting */
        typedef BYTE *(__attribute__((thiscall)) *type1_t)(void *o);
        BYTE *ty = ((type1_t)(*(void ***)ev)[1])(ev);
        if (ty && !IsBadReadPtr(ty, 0x20)) { unsigned d = *(unsigned *)(ty + 4); g_lx_types[g_lx_ntypes++] = d >= 1 && d < 6 ? *(unsigned *)(ty + 4 + 4 * d) : 0; }
    }
    if (ev && !IsBadReadPtr(ev, 0x68)) {
        typedef void *(__attribute__((thiscall)) *type_t)(void *o);
        BYTE *ty;
        if (*(int *)(g_base + 0xFE15E4) == 0) ((void (*)(void))(g_base + 0xA4E80))();
        ty = ((type_t)(*(void ***)ev)[1])(ev);
        if (ty && *(unsigned *)(ty + 4) > 3 && *(unsigned *)(ty + 0x14) == *(unsigned *)(g_base + 0xFE15F8)) {
            memcpy(g_shot_p, ev + 0x10, sizeof g_shot_p);
            /* ev +0x4C is the muzzle (shooter side) point; FUN_100a5830 stores it relative to the pawn (scale 3) */
            memcpy(g_shot_t, ev + 0x13, sizeof g_shot_t);
            {
                int i;
                void *hd = NULL;
                BYTE *me = g_bodymat ? NULL : entity_obj(g_net_id, &hd);
                if (hd) (*(int *)((BYTE *)hd + 8))--;
                for (i = 0; i < 3; i++) g_shot_t[i] -= g_bodymat ? *(float *)(g_bodymat + 0x30 + 4 * i) : me ? *(float *)(me + 0x60 + 4 * i) : 0;
            }
            g_shot_mode = ev[0x19];
            g_shot_seq++;
            if (g_shot_seq < 200)
                logf_("shot %u: point (%.2f %.2f %.2f) muzzle offset (%.2f %.2f %.2f) mode %d", g_shot_seq, g_shot_p[0], g_shot_p[1], g_shot_p[2],
                      g_shot_t[0], g_shot_t[1], g_shot_t[2], g_shot_mode);
        }
    }
    return ((bt_event_t)g_shot_orig)(self, ev);
}

static void shot_hook_install(BYTE *obj)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    BYTE *bc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4));
    void *bt = bc ? *(void **)(bc + 0x2C) : NULL;
    if (!bt || (bt == g_shot_bt && *(void ***)bt == g_shot_vt) || IsBadReadPtr(*(void **)bt, sizeof g_shot_vt)) return;
    memcpy(g_shot_vt, *(void **)bt, sizeof g_shot_vt);
    g_shot_orig = g_shot_vt[0x54 / 4];
    g_shot_vt[0x54 / 4] = (void *)shot_hook;
    *(void ***)bt = g_shot_vt;
    g_shot_bt = bt;
    logf_("shot hook: player base beautifier %p (vtable copied, event slot was %p)", bt, g_shot_orig);
}

/* research: who calls the weapon's shot method (X = [[weapon+0x24]+0x54], vf+0x20 = FUN_10114330)? `xhook` gives our
 * player's current weapon object X a private vtable copy whose slot 0x20 logs each distinct caller (RVA) and the
 * call stack's next two return addresses, then runs the original. */
static void *g_xh_vt[64], *g_xh_orig, *g_xh_obj;
static unsigned g_xh_seen[16];
static int g_xh_n;
static void __attribute__((thiscall)) xshot_hook(void *self, void *pawn)
{
    unsigned ra = (unsigned)__builtin_return_address(0) - (unsigned)g_base;
    g_xh_calls++;
    int i;
    for (i = 0; i < g_xh_n && g_xh_seen[i] != ra; i++) ;
    if (i == g_xh_n && g_xh_n < 16) {
        /* the game code has no frame pointers: list code addresses found on the stack instead (likely return addresses) */
        unsigned *sp = (unsigned *)__builtin_frame_address(0), lo = (unsigned)g_base + 0x1000, hi = (unsigned)g_base + 0xE00000, got[8];
        int k, n = 0;
        g_xh_seen[g_xh_n++] = ra;
        for (k = 0; k < 160 && n < 8 && !IsBadReadPtr(sp + k, 4); k++) if (sp[k] > lo && sp[k] < hi) got[n++] = sp[k] - (unsigned)g_base;
        logf_("xhook: shot method called from RVA %X, pawn %p, stack code addresses: %X %X %X %X %X %X %X %X", ra, pawn,
              n > 0 ? got[0] : 0, n > 1 ? got[1] : 0, n > 2 ? got[2] : 0, n > 3 ? got[3] : 0, n > 4 ? got[4] : 0, n > 5 ? got[5] : 0,
              n > 6 ? got[6] : 0, n > 7 ? got[7] : 0);
    }
    ((void (__attribute__((thiscall)) *)(void *, void *))g_xh_orig)(self, pawn);
}

/* sender shot counter: bullet events miss shots (e.g. aimed at the ground close by), so the shot method of our own
 * current weapon object X (vf+0x20, FUN_10114330) is hooked through a private vtable copy and counted */
static void *g_lx_vt[64], *g_lx_orig;
static BYTE *g_lx_obj;
static unsigned g_lx_shots, g_lx_noevent, g_lx_aimed;
static void __attribute__((thiscall)) lx_hook(void *self, void *pawn)
{
    unsigned before = g_shot_seq;
    g_lx_inshot = 1; g_lx_ntypes = 0;
    ((void (__attribute__((thiscall)) *)(void *, void *))g_lx_orig)(self, pawn);
    g_lx_inshot = 0;
    g_lx_shots++;
    if (g_shot_seq == before) g_lx_noevent++;
    if (g_lx_shots <= 300) {
        /* research: per shot - aim angles (our own ThirdParty memento, decoded), bullet events and other event types */
        BYTE *m = g_tx_mem;
        logf_("shotlog %u: aim (%.3f %.3f) bullets %u%s last point (%.2f %.2f %.2f) | events during shot: %d [%08x %08x %08x %08x]", g_lx_shots,
              m ? np_dq(m + 0xAC, 360) : 0.0f, m ? np_dq(m + 0xC0, 360) : 0.0f, g_shot_seq - before, g_shot_seq == before ? " (NONE)" : "",
              g_shot_p[0], g_shot_p[1], g_shot_p[2], g_lx_ntypes, g_lx_types[0], g_lx_types[1], g_lx_types[2], g_lx_types[3]);
    }
}
static void lx_hook_weapon(void *wc)
{
    BYTE *y = wc ? *(BYTE **)((BYTE *)wc + 0x24) : NULL, *x = y ? *(BYTE **)(y + 0x54) : NULL;
    static void *seen_wc;
    static DWORD seen_t;
    if (!x || *(void ***)x == g_lx_vt || IsBadReadPtr(*(void **)x, sizeof g_lx_vt)) return;
    /* only the weapon object class we know (vtable RVA E1EA18, shot method FUN_10114330), and only once the weapon
     * has been in our hands for 2 s (hooking during the draw crashed once in FUN_10110470) */
    if (*(unsigned *)x != (unsigned)(g_base + 0xE1EA18)) return;
    if (wc != seen_wc) { seen_wc = wc; seen_t = GetTickCount(); return; }
    if (GetTickCount() - seen_t < 2000) return;
    memcpy(g_lx_vt, *(void **)x, sizeof g_lx_vt);
    g_lx_orig = g_lx_vt[0x20 / 4]; g_lx_vt[0x20 / 4] = (void *)lx_hook;
    *(void ***)x = g_lx_vt; g_lx_obj = x;
    logf_("tx: counting shots of our weapon object %p", x);
}

typedef void (__attribute__((thiscall)) *np_encode_t)(void *self, void *memento);
static void tx_encode(BYTE *obj, NetPktX *p, DWORD now)
{
    BYTE *m;
    void *pawn = ((np_getcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
    int k;
    if (!pawn) return;
    if (!g_tx_mem) {
        g_tx_mem = ((np_factory_t)(g_base + 0x40110))();
        logf_("tx: own ThirdParty memento %p", g_tx_mem);
        if (!g_tx_mem) return;
    }
    m = g_tx_mem;
    shot_hook_install(obj);
    *(void **)(g_tx_this + 0x10) = pawn;
    ((np_encode_t)(g_base + 0xA6EC0))(g_tx_this, m);
    for (k = 0; k < 3; k++) p->vel[k] = *(int *)(m + 0x78 + 0x14 * k);
    p->aim[0] = *(int *)(m + 0xB4); p->aim[1] = *(int *)(m + 0xC8);
    p->aim[2] = *(int *)(m + 0xDC); p->aim[3] = *(int *)(m + 0xF0);
    g_tx_pawn = (BYTE *)pawn;
    p->s104 = m[0x104] | (BYTE)g_tx_latch; p->s11c = m[0x11C]; p->s110 = m[0x110]; p->valid = 1;
    if (g_tx_latch && !m[0x104] && ++g_tx_latched <= 30) logf_("tx: fire bit latched between packets (%u)", g_tx_latched);
    g_tx_latch = 0;
    g_tx_ok++;
    {
        /* the weapon in our hands: inventory FUN_1007e140(pawn), mode FUN_10125f40 (1 = weapons), current FUN_10127da0;
         * its archetype name is looked up (Lua GetEntityName) only when the current weapon changes */
        typedef void *(__fastcall *inv_t)(void *pawn);
        typedef int (__attribute__((thiscall)) *iget_t)(void *inv);
        typedef void *(__attribute__((thiscall)) *cur_t)(void *inv);
        void *inv = ((inv_t)(g_base + 0x7E140))(pawn), *cur = NULL;
        if (inv && ((iget_t)(g_base + 0x125F40))(inv) == 1) cur = ((cur_t)(g_base + 0x127DA0))(inv);
        if (cur) lx_hook_weapon(cur);
        if (cur != g_tx_wcur) {
            char code[96];
            void *wh = cur ? *(void **)((BYTE *)cur + 8) : NULL;
            g_tx_wcur = cur; g_tx_weap[0] = 0;
            if (wh && !IsBadReadPtr(wh, 8)) {
                snprintf(code, sizeof code, "__out = tostring(GetEntityName('%llu'))", *(unsigned long long *)wh);
                lua_eval(code, g_tx_weap, sizeof g_tx_weap);
                if (!strcmp(g_tx_weap, "nil")) g_tx_weap[0] = 0;
            }
            logf_("tx: weapon in hands now '%s' (%p)", g_tx_weap, cur);
        }
    }
    if (now - g_tx_lastlog >= 1000) {
        g_tx_lastlog = now;
        logf_("tx: vel (%.2f %.2f %.2f) aim (%.3f %.3f | %.3f %.3f) stance %u mode %u flag %u",
              np_dq(m + 0x70, 15), np_dq(m + 0x84, 15), np_dq(m + 0x98, 15),
              np_dq(m + 0xAC, 360), np_dq(m + 0xC0, 360), np_dq(m + 0xD4, 360), np_dq(m + 0xE8, 360), m[0x104], m[0x11C], m[0x110]);
    }
}

/* put a clone of the repository prototype for key {k0, profile, pose} into a beautifier slot of the entity
 * (+0x2C base, +0x28 main); 0xFFFFFFFF in the key means "none" (the game's value at E2C55C). Returns the new one. */
static void *np_slot(BYTE *obj, int slot, unsigned k0, unsigned k1, unsigned k2)
{
    void *bc, *pawn, *repo, *proto, *old, *nb;
    unsigned key[3], none = *(unsigned *)(g_base + 0xE2C55C);
    bc = ((np_getcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4));
    pawn = ((np_getcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
    repo = ((np_factory_t)(g_base + 0xD4710))();
    if (!bc || !pawn || !repo) { logf_("avatar np: beautifier comp %p pawn %p repository %p", bc, pawn, repo); return NULL; }
    key[0] = k0 == 0xFFFFFFFFu ? none : k0; key[1] = k1 == 0xFFFFFFFFu ? none : k1; key[2] = k2 == 0xFFFFFFFFu ? none : k2;
    proto = ((np_find_t)(g_base + 0xD3DB0))(repo, key);
    if (!proto) { logf_("avatar np: no beautifier prototype for %08x %08x %08x", key[0], key[1], key[2]); return NULL; }
    old = *(void **)((BYTE *)bc + slot);
    if (old) { ((np_vf0_t)(*(void ***)old)[0x88 / 4])(old); ((np_vfdel_t)(*(void ***)old)[0])(old, 1); }
    nb = ((np_vfclone_t)(*(void ***)proto)[0x78 / 4])(proto);
    *(void **)((BYTE *)bc + slot) = nb;
    if (nb) { ((np_vfbind_t)(*(void ***)nb)[0x8C / 4])(nb, pawn, bc); ((np_vf0_t)(*(void ***)nb)[0x84 / 4])(nb); }
    logf_("avatar np: slot +%02x <- prototype %p (vt %08x) for %08x %08x %08x, new %p (old %p)", slot, proto, *(unsigned *)proto,
          key[0], key[1], key[2], nb, old);
    return nb;
}

/* swap the avatar's base beautifier (slot +0x2C) for a clone of the {network} prototype; returns the new one */
static void *np_beaut(BYTE *obj)
{
    return np_slot(obj, 0x2C, 0x608487bc, 0xFFFFFFFFu, 0xFFFFFFFFu);
}

/* attach the net component, give it the ThirdParty pieces and swap the base beautifier; returns the memento */
static BYTE *np_setup(unsigned long long id)
{
    void *holder = NULL, *nb;
    BYTE *obj = entity_obj(id, &holder), *comp, *mem;
    if (holder) (*(int *)((BYTE *)holder + 8))--;
    if (!obj) return NULL;
    /* network archetypes (PawnPlayerNetwork) already carry a CPawnNetworkComponent (vtable RVA E1AE00): reuse it */
    comp = NULL;
    {
        void **cs = *(void ***)(obj + 0x9C);
        int k, n = *(int *)(obj + 0xA0);
        for (k = 0; cs && k < n && k < 64; k++)
            if (cs[k] && !IsBadReadPtr(cs[k], 4) && *(DWORD *)cs[k] == (DWORD)(g_base + 0xE1AE00)) { comp = cs[k]; break; }
    }
    if (comp) logf_("avatar np: reusing the archetype's net component %p (memento %p)", comp, *(void **)(comp + 0x170));
    else {
        comp = ((np_factory_t)(g_base + 0x40840))();
        if (!comp) return NULL;
        ((np_addcomp_t)(g_base + 0x4E0D80))(obj, comp);
    }
    mem = *(BYTE **)(comp + 0x170);
    if (!mem) mem = ((np_factory_t)(g_base + 0x40110))();
    if (!mem) return NULL;
    *(unsigned *)(comp + 0x40) = 1; comp[0x44] = 1; *(unsigned *)(comp + 0x164) = 1; *(BYTE **)(comp + 0x170) = mem;
    /* NetPlayer sets the pawn's first counter (health, at CCountersComponentGO +0x44: value +0x10, max +0x14) from
     * memento +0x13C / +0x14C every frame; the defaults (1 of 1) kill it, so start from the pawn's own values */
    {
        BYTE *cc = ((np_getcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDF9A8)), *hc;
        g_av_hp = 100.0f; g_av_hpmax = 100;
        if (cc && !IsBadReadPtr(cc + 0x44, 4) && (hc = *(BYTE **)(cc + 0x44)) && !IsBadReadPtr(hc, 0x18)) {
            g_av_hp = *(float *)(hc + 0x10); g_av_hpmax = (unsigned)*(float *)(hc + 0x14);
            if (g_av_hp < 1.0f || g_av_hpmax < 1) { g_av_hp = 100.0f; g_av_hpmax = 100; }
        }
        *(float *)(mem + 0x13C) = g_av_hp; mem[0x134] = 1;
        *(unsigned *)(mem + 0x14C) = g_av_hpmax; mem[0x148] = 1;
        logf_("avatar np: health %.0f of %u", g_av_hp, g_av_hpmax);
    }
    {
        /* start at the peer's position (the avatar was spawned there); the stand-in peer has no real height, so then
         * keep the pawn's own */
        float sp[3];
        sp[0] = g_remote.pos[0] + g_av_off[0]; sp[1] = g_remote.pos[1] + g_av_off[1];
        sp[2] = g_av_fake ? *(float *)(obj + 0x68) : g_remote.pos[2];
        np_pos(mem + 4, sp);
        np_pos(mem + 0x1A4, sp);
    }
    g_av_comp = comp;
    nb = np_beaut(obj);
    logf_("avatar np: comp %p memento %p, base beautifier %p", comp, mem, nb);
    return mem;
}

/* MP-flag window for the avatar's main beautifier. FUN_100abb40 (third-person update, vf+0x7C) copies the desired
 * state into the actual one; with the global MP flag ([DAT_11645a74]+4) the actual velocity becomes the desired one,
 * without it (single player) it is limited by the physics' current velocity, so a remote-driven pawn can never speed
 * up past a walk. The avatar's main beautifier gets a private vtable copy whose update slots (vf+0x7C, vf+0x80) run
 * with that flag set for the duration of the call only. */
static void *g_mf_vt[64], *g_mf_orig7c, *g_mf_orig80, *g_mf_obj;
static int g_mf_on = 1;
static void __attribute__((thiscall)) mf_call(void *orig, void *self, float dt)
{
    BYTE *mp = *(BYTE **)(g_base + 0x1645A74);
    BYTE old = 0;
    if (mp && g_mf_on) { old = mp[4]; mp[4] = 1; }
    ((void (__attribute__((thiscall)) *)(void *, float))orig)(self, dt);
    if (mp && g_mf_on) mp[4] = old;
    npc_anim_apply(self);
}
static void __attribute__((thiscall)) mf_hook7c(void *self, float dt) { mf_call(g_mf_orig7c, self, dt); }
static void __attribute__((thiscall)) mf_hook80(void *self, float dt) { mf_call(g_mf_orig80, self, dt); }
static void mf_install(BYTE *bc)
{
    void *mb = bc ? *(void **)(bc + 0x28) : NULL;
    if (!mb || *(void ***)mb == g_mf_vt || IsBadReadPtr(*(void **)mb, sizeof g_mf_vt)) return;
    if (*(unsigned *)mb != (unsigned)(g_base + 0xE172E8)) return; /* only CPawnBeautifierThird */
    if (!g_mf_orig7c) {
        /* one vtable copy for the class, shared by every remote-driven pawn (avatar, NPC puppets) */
        memcpy(g_mf_vt, *(void **)mb, sizeof g_mf_vt);
        g_mf_orig7c = g_mf_vt[0x7C / 4]; g_mf_orig80 = g_mf_vt[0x80 / 4];
        g_mf_vt[0x7C / 4] = (void *)mf_hook7c; g_mf_vt[0x80 / 4] = (void *)mf_hook80;
    }
    *(void ***)mb = g_mf_vt; g_mf_obj = mb;
    logf_("remote pawn: main beautifier %p updates now run with the MP flag (velocity follows the packet)", mb);
}

/* every 500 ms: check that the avatar still runs NetPlayer in the base slot (+0x2C) with the memento in the applier
 * role; log the beautifier slots and role bytes when they change, and put NetPlayer back if something replaced it */
static void np_watch(void)
{
    static unsigned last[6];
    static DWORD lastfix;
    void *holder = NULL;
    BYTE *obj = entity_obj(g_av_id, &holder), *bc, *c = g_av_comp;
    unsigned cur[6], npvt = (unsigned)(g_base + 0xE16E98);
    if (holder) (*(int *)((BYTE *)holder + 8))--;
    if (!obj || !c) return;
    bc = ((np_getcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4));
    if (!bc) return;
    mf_install(bc);
    cur[0] = *(void **)(bc + 0x28) ? **(unsigned **)(bc + 0x28) : 0;
    cur[1] = *(void **)(bc + 0x2C) ? **(unsigned **)(bc + 0x2C) : 0;
    cur[2] = bc[0x14];
    cur[3] = *(unsigned *)(c + 0x15C) | *(unsigned *)(c + 0x160) << 8 | *(unsigned *)(c + 0x164) << 16;
    cur[4] = *(unsigned *)(c + 0x170);
    cur[5] = *(unsigned *)(obj + 0x70);
    if (memcmp(cur, last, sizeof cur)) {
        logf_("npwatch: main slot vt %08x, base slot vt %08x%s, enabled %u, roles %06x, memento %08x (ours %p), entity flags %08x",
              cur[0], cur[1], cur[1] == npvt ? " (NetPlayer)" : "", cur[2], cur[3], cur[4], g_av_mem, cur[5]);
        memcpy(last, cur, sizeof cur);
    }
    if ((cur[1] != npvt || cur[4] != (unsigned)g_av_mem || *(unsigned *)(c + 0x164) != 1) && GetTickCount() - lastfix > 3000) {
        lastfix = GetTickCount();
        *(unsigned *)(c + 0x164) = 1; *(BYTE **)(c + 0x170) = g_av_mem;
        if (cur[1] != npvt) logf_("npwatch: NetPlayer was replaced, reinstalled %p", np_beaut(obj));
        else logf_("npwatch: restored the applier role and memento");
    }
}

/* fire one shot of the avatar's current weapon the way the MP fire-message handler FUN_100ef8c0 does for a remote
 * pawn: DesiredData (pawn comp +0x140) +6 |= 0x20 (remote fire), the fire request {part -1, -1, ids -1, point,
 * muzzle offset} + mode into the weapon (FUN_1012f130), the weapon's fire method vf+0x80(pawn comp), then the pawn
 * event 0x121ADE93 (vf+0x78 -> FUN_1029da10) */
static void av_fire(const float *point, const float *off, int mode)
{
    typedef void *(__fastcall *inv_t)(void *pawn);
    typedef void *(__attribute__((thiscall)) *cur_t)(void *inv);
    typedef void (__attribute__((thiscall)) *req_t)(void *weapon, unsigned *req, int mode);
    typedef void (__attribute__((thiscall)) *fire_t)(void *weapon, void *pawn);
    typedef void *(__attribute__((thiscall)) *tags_t)(void *pawn);
    typedef void (__attribute__((thiscall)) *ev_t)(void *tags, unsigned ev);
    static unsigned fired;
    void *holder = NULL, *pawn, *inv, *wc, *tags;
    BYTE *obj = entity_obj(g_av_id, &holder);
    unsigned req[10];
    if (holder) (*(int *)((BYTE *)holder + 8))--;
    pawn = obj ? ((np_getcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)) : NULL;
    inv = pawn ? ((inv_t)(g_base + 0x7E140))(pawn) : NULL;
    wc = inv ? ((cur_t)(g_base + 0x127DA0))(inv) : NULL;
    if (!wc) return;
    {
        /* research: keep the shot-method hook on the avatar's current weapon object X, and log its state fields */
        BYTE *y = *(BYTE **)((BYTE *)wc + 0x24), *x = y ? *(BYTE **)(y + 0x54) : NULL;
        if (x && *(void ***)x != g_xh_vt && !IsBadReadPtr(*(void **)x, sizeof g_xh_vt)) {
            memcpy(g_xh_vt, *(void **)x, sizeof g_xh_vt);
            g_xh_orig = g_xh_vt[0x20 / 4]; g_xh_vt[0x20 / 4] = (void *)xshot_hook;
            *(void ***)x = g_xh_vt; g_xh_obj = x;
        }
        if (y && fired < 200) logf_("avfire state: y %p +18 %d +1c %d +20 %d +24 %d +28 %d +2c %d +5a %u, [y+4]+bc %d", y, *(int *)(y + 0x18),
                                    *(int *)(y + 0x1C), *(int *)(y + 0x20), *(int *)(y + 0x24), *(int *)(y + 0x28), *(int *)(y + 0x2C), y[0x5A],
                                    *(void **)(y + 4) ? *(int *)(*(BYTE **)(y + 4) + 0xBC) : -1);
    }
    ((BYTE *)pawn)[0x140 + 6] |= 0x20;
    req[0] = req[1] = req[2] = req[3] = 0xFFFFFFFFu;
    memcpy(&req[4], point, 12); memcpy(&req[7], off, 12);
    ((req_t)(g_base + 0x12F130))(wc, req, mode);
    {
        unsigned before = g_xh_calls;
        if (g_av_directfire == 1) ((fire_t)(*(void ***)wc)[0x80 / 4])(wc, pawn);
        if (fired < 200 && g_av_directfire == 1) logf_("avfire: vf+0x80 made %u shot call(s)", g_xh_calls - before);
    }
    tags = ((tags_t)(*(void ***)pawn)[0x78 / 4])(pawn);
    if (tags) ((ev_t)(g_base + 0x29DA10))(tags, 0x121ADE93u);
    if (++fired <= 200) logf_("avfire %u: weapon %p, avatar shot-method calls so far %u", fired, wc, g_xh_calls);
}

/* per tick: position (with the test offset), velocity from consecutive packets, yaw for aim/body, fire origin/dir */
static void np_tick(DWORD now)
{
    float p[3], yaw, dx = g_remote.dir[0], dy = g_remote.dir[1], n = sqrtf(dx * dx + dy * dy);
    BYTE *m = g_av_mem;
    int k, logged = 0;
    p[0] = g_remote.pos[0] + g_av_off[0]; p[1] = g_remote.pos[1] + g_av_off[1]; p[2] = g_remote.pos[2];
    if (g_av_fake) {
        /* the stand-in peer has no real height: keep the avatar's own (terrain) height */
        void *holder = NULL;
        BYTE *obj = entity_obj(g_av_id, &holder);
        if (obj) p[2] = *(float *)(obj + 0x68);
        if (holder) (*(int *)((BYTE *)holder + 8))--;
    }
    /* packets come in bunches through the relay, so the velocity is timed by the sender's sequence numbers
     * (20 per second) and low-passed. Every frame the memento gets the last packet's position extrapolated along
     * that velocity (at most 0.25 s ahead), so NetPlayer sees a target moving continuously at the speed it is told;
     * after 300 ms without news the velocity decays. */
    if (g_remote.seq != g_av_lastseq) {
        unsigned ds = g_remote.seq - g_av_lastseq;
        if (g_rx_ext.valid && !g_av_fake) {
            /* the peer's game reports its own physics velocity: use it as is (position-derived velocity overshoots
             * when the relay delivers packets in bunches) */
            for (k = 0; k < 3; k++) {
                unsigned bits = *(unsigned *)(m + 0x80 + 0x14 * k);
                g_av_vel[k] = (bits && bits < 32) ? g_rx_ext.vel[k] * 15.0f / (float)((1u << bits) - 1) : 0;
            }
        } else if (g_av_lastseq && ds > 0 && ds < 40) {
            float dt = ds * 0.05f;
            for (k = 0; k < 3; k++) {
                float v = (p[k] - g_av_lastpos[k]) / dt;
                v = v > 10.0f ? 10.0f : v < -10.0f ? -10.0f : v;
                g_av_vel[k] += (v - g_av_vel[k]) * 0.5f;
            }
        } else g_av_vel[0] = g_av_vel[1] = g_av_vel[2] = 0;
        memcpy(g_av_lastpos, p, sizeof p); g_av_lastseq = g_remote.seq; g_av_lastt = now;
    } else if (now - g_av_lastt > 300)
        for (k = 0; k < 3; k++) g_av_vel[k] *= 0.8f;
    {
        /* lead: 0.25 s for the position-derived velocity, 0.1 s with the game's own velocity */
        float ahead = (now - g_av_lastt) / 1000.0f, maxa = g_rx_ext.valid && !g_av_fake ? 0.1f : 0.25f;
        if (ahead > maxa) ahead = maxa;
        for (k = 0; k < 3; k++) p[k] = g_av_lastpos[k] + g_av_vel[k] * ahead;
    }
    if (now - g_av_lastlog >= 500) {
        /* measurements: how far the pawn is from the written target, and both speeds */
        void *holder = NULL;
        logged = 1;
        np_watch();
        BYTE *obj = entity_obj(g_av_id, &holder);
        if (obj) {
            float *ep = (float *)(obj + 0x60), d = sqrtf((ep[0] - p[0]) * (ep[0] - p[0]) + (ep[1] - p[1]) * (ep[1] - p[1]) + (ep[2] - p[2]) * (ep[2] - p[2]));
            float sp = (g_av_lastt && now > g_av_lastlog) ? sqrtf((ep[0] - g_av_logpos[0]) * (ep[0] - g_av_logpos[0]) + (ep[1] - g_av_logpos[1]) * (ep[1] - g_av_logpos[1])) / ((now - g_av_lastlog) / 1000.0f) : 0;
            logf_("avnp: dist %.2f m, packet speed %.2f, pawn speed %.2f, seq %u, age %lu ms", d,
                  sqrtf(g_av_vel[0] * g_av_vel[0] + g_av_vel[1] * g_av_vel[1]), sp, g_remote.seq, (unsigned long)(now - g_av_lastt));
            memcpy(g_av_logpos, ep, sizeof g_av_logpos);
        }
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        g_av_lastlog = now;
    }
    np_pos(m + 4, p);
    if (g_rx_ext.valid && !g_av_fake) {
        /* the peer sent its game-encoded fields: copy them as the net layer would (same quantization on both sides) */
        static const int aimf[4] = { 0xAC, 0xC0, 0xD4, 0xE8 };
        if (g_av_kp > 0) {
            /* velocity = the peer's game velocity + kp * (target - avatar) in the ground plane, every frame: NetPlayer only
             * adds the position error once it exceeds 1.5 m, so the pawn lags behind and then jumps; clamp 9 m/s */
            void *holder = NULL;
            BYTE *obj = entity_obj(g_av_id, &holder);
            float v[3], hv;
            for (k = 0; k < 3; k++) v[k] = g_av_vel[k];
            if (obj) { v[0] += g_av_kp * (p[0] - *(float *)(obj + 0x60)); v[1] += g_av_kp * (p[1] - *(float *)(obj + 0x64)); }
            if (holder) (*(int *)((BYTE *)holder + 8))--;
            hv = sqrtf(v[0] * v[0] + v[1] * v[1]);
            if (hv > 9.0f) { v[0] *= 9.0f / hv; v[1] *= 9.0f / hv; }
            for (k = 0; k < 3; k++) np_q(m + 0x70 + 0x14 * k, v[k] > 14.9f ? 14.9f : v[k] < -14.9f ? -14.9f : v[k], 15.0f);
        } else
            for (k = 0; k < 3; k++) { *(int *)(m + 0x78 + 0x14 * k) = g_rx_ext.vel[k]; m[0x74 + 0x14 * k] = 1; }
        for (k = 0; k < 4; k++) { *(int *)(m + aimf[k] + 8) = g_rx_ext.aim[k]; m[aimf[k] + 4] = 1; }
        m[0x104] = g_rx_ext.s104; m[0x100] = 1;
        m[0x11C] = g_rx_ext.s11c; m[0x118] = 1;
        m[0x110] = g_rx_ext.s110; m[0x10C] = 1;
        {
            /* fire block, as the NetPlayer writer fills it from CWeaponEventFireBullet: part +0x1A0 (-1), point
             * (impact) +0x1A4, target id +0x218/+0x21C (-1: ids are not shared between PCs), muzzle offset +0x220
             * (muzzle - pawn, scale 3), mode +0x264. The applier hands it to the current weapon every frame; on a new
             * bullet we write it and keep it for 120 ms, then put back what the memento had before the first one. */
            static int idle_saved, idle_part, idle_mode;
            static DWORD shot_t;
            if (g_rx_shot_seq != g_av_shot_seq) {
                float d[3];
                if (!idle_saved) { idle_saved = 1; idle_part = *(int *)(m + 0x1A0); idle_mode = *(int *)(m + 0x264);
                    logf_("avshot: memento fire block before the first bullet: part %d mode %d ids %08x %08x", idle_part, idle_mode,
                          *(unsigned *)(m + 0x218), *(unsigned *)(m + 0x21C)); }
                g_av_shot_seq = g_rx_shot_seq; shot_t = now;
                for (k = 0; k < 3; k++) d[k] = g_rx_shot_t[k] > 2.99f ? 2.99f : g_rx_shot_t[k] < -2.99f ? -2.99f : g_rx_shot_t[k];
                *(int *)(m + 0x1A0) = -1; m[0x19C] = 1;
                *(unsigned *)(m + 0x218) = 0xFFFFFFFFu; *(unsigned *)(m + 0x21C) = 0xFFFFFFFFu; m[0x214] = 1;
                np_pos(m + 0x1A4, g_rx_shot_p);
                for (k = 0; k < 3; k++) np_q(m + 0x220 + 0x14 * k, d[k], 3.0f);
                *(int *)(m + 0x264) = g_rx_shot_mode; m[0x260] = 1;
                if (g_av_directfire) av_fire(g_rx_shot_p, d, g_rx_shot_mode);
                if (g_av_shot_seq < 200)
                    logf_("avshot %u: point (%.2f %.2f %.2f) muzzle offset (%.2f %.2f %.2f) mode %d", g_av_shot_seq, g_rx_shot_p[0], g_rx_shot_p[1],
                          g_rx_shot_p[2], d[0], d[1], d[2], g_rx_shot_mode);
            } else if (shot_t && now - shot_t > 120) {
                shot_t = 0;
                *(int *)(m + 0x1A0) = idle_part; m[0x19C] = 1;
                *(int *)(m + 0x264) = idle_mode; m[0x260] = 1;
            }
        }
        if (logged) /* once per 500 ms metrics line */
            logf_("avnp ext: vel (%.2f %.2f %.2f) aim (%.1f %.1f) stance %u mode %u flag %u", np_dq(m + 0x70, 15), np_dq(m + 0x84, 15),
                  np_dq(m + 0x98, 15), np_dq(m + 0xAC, 360), np_dq(m + 0xC0, 360), m[0x104], m[0x11C], m[0x110]);
    } else {
    for (k = 0; k < 3; k++) np_q(m + 0x70 + 0x14 * k, g_av_vel[k], 15.0f);
    if (n > 0.5f) {
        dx /= n; dy /= n;
        yaw = atan2f(dy, dx) * 57.29578f + g_av_yawoff;
        while (yaw < 0) yaw += 360.0f;
        while (yaw >= 360.0f) yaw -= 360.0f;
        np_q(m + 0xAC, 0, 360.0f); np_q(m + 0xC0, yaw, 360.0f);
        np_q(m + 0xD4, 0, 360.0f); np_q(m + 0xE8, yaw, 360.0f);
        np_pos(m + 0x1A4, p);
        np_q(m + 0x220, dx, 3.0f); np_q(m + 0x234, dy, 3.0f); np_q(m + 0x248, 0, 3.0f);
    }
    }
    *(float *)(m + 0x13C) = g_av_hp; *(unsigned *)(m + 0x14C) = g_av_hpmax;
}

static int av_valid(void)
{
    return g_av_mat && g_av_body != g_body && !IsBadWritePtr(g_av_mat, 0x40) && !IsBadReadPtr(g_av_body, 4) && *(unsigned *)g_av_body == (unsigned)(g_base + RVA_BODY_VTABLE);
}

static void av_remove(void)
{
    char code[128], out[64];
    if (g_av_id) {
        snprintf(code, sizeof code, "RemoveEntity('%llu') __out = 'removed'", g_av_id);
        lua_eval(code, out, sizeof out);
        logf_("avatar %llu removed: %s", g_av_id, out);
    }
    g_av_id = 0; g_av_body = g_av_mat = NULL; g_av_have = 0;
    g_av_mem = NULL; g_av_comp = NULL; g_av_npstate = 0; g_av_weap[0] = 0; g_av_lastseq = 0; g_av_smhave = 0;
}

/* ---- stims (damage events) ----
 * Damage reaches an entity as a "Stim" event (class vtable RVA E11ECC, ctor FUN_1050f580, 0x94 bytes): type +0x48,
 * amount +0x58, flags +0x5C, two entity handles +0x3C / +0x40 (handle: id +0, refcount +8, object +0xC), two vectors
 * +0x7C / +0x88. KillPawnAgent sends one {type 3, 100000, 0x40} through the entity's event method vf+0x20.
 * stimlog <avatar|me|id>: the entity gets a private vtable copy (with the RTTI slot in front) whose vf+0x20 logs every
 * event; stims are dumped field by field. Slot 0 = avatar, 1 = local player. */
/* hit sync (on by default, "hitsync 0|1"): hits between players are decided by the shooter's window. A damage stim on
 * the avatar from our own player goes to the peer as a HIT packet; there it becomes a base Stim (built like
 * KillPawnAgent does) on the local player with the avatar as source. The avatar's replayed shots no longer hurt the
 * local player: stims on it whose source is the avatar are dropped. */
#define HIT_MAGIC 0x31544948u
#pragma pack(push, 1)
typedef struct { unsigned magic, seq; int type, amount; unsigned flags, part, w60; float pos[3]; unsigned subvt, tail[8]; } HitPkt;
#pragma pack(pop)
/* NPC hits (npcsync): slot 2 is one vtable copy shared by the synced NPCs. On the joiner a stim on a puppet whose
 * source is our player goes to the host as NHIT (with the NPC id) and still lands locally (hit reaction); the host
 * applies it to its NPC with the avatar as source and drops the avatar's replayed shots at NPCs. Health and death then
 * come back with the NPC packets. */
#define NHIT_MAGIC 0x3154484Eu
#pragma pack(push, 1)
typedef struct { HitPkt h; unsigned long long npc; } NpcHitPkt;
#pragma pack(pop)
static unsigned g_hit_tx, g_hit_rx, g_hit_blocked, g_nhit_tx, g_nhit_rx, g_nhit_blocked, g_nsht_tx, g_nsht_rx, g_nsht_blocked;
static void *g_st_vt[3][257], *g_st_orig[3];
static BYTE *g_st_obj[2];
static unsigned long long g_st_id[2];
static unsigned g_st_n[3], g_st_other[3];
static unsigned long long npc_id_of(BYTE *obj);
static int npc_is_synced(unsigned long long id);
static int npc_shot_ok(BYTE *obj, int pull);
/* NPC shots at players are decided on the host as well: a stim on the avatar whose source is a synced NPC goes to the
 * joiner as NSHT (hit + the host's NPC id) and lands on the joiner's player with the puppet as source; the puppets'
 * own replayed shots at the joiner's player are dropped there. */
#define NSHT_MAGIC 0x5448534Eu
static unsigned long long st_hid(BYTE *h) { return h && !IsBadReadPtr(h, 8) ? *(unsigned long long *)h : 0; }
/* an event's name: MSVC std::string at +0xC (inline buffer up to 15 chars, size +0x1C, capacity +0x20) */
static const char *st_name(BYTE *ev)
{
    unsigned cap = *(unsigned *)(ev + 0x20), len = *(unsigned *)(ev + 0x1C);
    const char *s = cap > 15 ? *(const char **)(ev + 0xC) : (const char *)(ev + 0xC);
    if (len > 64 || !s || IsBadReadPtr(s, len + 1) || s[len]) return "?";
    return s;
}
static void st_pack(HitPkt *hp, BYTE *ev, unsigned evt)
{
    hp->type = *(int *)(ev + 0x48); hp->amount = *(int *)(ev + 0x58);
    hp->flags = *(unsigned *)(ev + 0x5C); hp->part = *(unsigned *)(ev + 0x44); hp->w60 = *(unsigned *)(ev + 0x60);
    memcpy(hp->pos, ev + 0x64, sizeof hp->pos); hp->subvt = evt - (unsigned)g_base;
    /* bullet stims (vtable RVA E119A4, 0xB4 bytes) carry 0x20 more bytes after the base */
    if (hp->subvt == 0xE119A4 && !IsBadReadPtr(ev, 0xB4)) memcpy(hp->tail, ev + 0x94, sizeof hp->tail); else memset(hp->tail, 0, sizeof hp->tail);
}
static int __attribute__((thiscall)) st_hook(BYTE *self, BYTE *ev)
{
    int s = *(void ***)self == &g_st_vt[1][1] ? 1 : *(void ***)self == &g_st_vt[2][1] ? 2 : 0;
    unsigned evt = ev && !IsBadReadPtr(ev, 0x24) ? *(unsigned *)ev : 0;
    const char *nm = evt ? st_name(ev) : "";
    if (!strcmp(nm, "IsUsable")) evt = 0;
    if (s == 2 && evt && g_npcev_left > 0) {
        /* npcev: what the NPCs get, to find what starts their idle actions (flask, smoke) on the host */
        g_npcev_left--;
        logf_("npcev %llu: %s (vt rva %x)", npc_id_of(self), nm, evt - (unsigned)g_base);
    }
    if (s == 2 && (!strcmp(nm, "PullTrigger") || !strcmp(nm, "start_shoot") || !strcmp(nm, "WeaponFireBullet")) && !npc_shot_ok(self, nm[0] == 'P')) return 0;
    if (!strcmp(nm, "Stims") && !IsBadReadPtr(ev, 0x94)) {
        unsigned long long src = st_hid(*(BYTE **)(ev + 0x3C));
        if (g_hitsync && s == 0 && src == g_net_id && *(int *)(ev + 0x58) && g_ns != INVALID_SOCKET) {
            HitPkt hp;
            st_pack(&hp, ev, evt);
            hp.magic = HIT_MAGIC; hp.seq = ++g_hit_tx;
            sendto(g_ns, (char *)&hp, sizeof hp, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
            if (g_hit_tx <= 50) logf_("hit %u: we hit the avatar (type %d, amount %d, flags %x, part %08x, sub rva %x, tail %08x %08x %08x %08x %08x %08x %08x %08x) -> sent",
                                      g_hit_tx, hp.type, hp.amount, hp.flags, hp.part, hp.subvt, hp.tail[0], hp.tail[1], hp.tail[2], hp.tail[3], hp.tail[4], hp.tail[5], hp.tail[6], hp.tail[7]);
        }
        if (g_hitsync && s == 2 && g_npc_role == 2 && src == g_net_id && *(int *)(ev + 0x58) && g_ns != INVALID_SOCKET) {
            NpcHitPkt nk;
            st_pack(&nk.h, ev, evt);
            nk.h.magic = NHIT_MAGIC; nk.h.seq = ++g_nhit_tx; nk.npc = npc_id_of(self);
            if (nk.npc) sendto(g_ns, (char *)&nk, sizeof nk, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
            if (g_nhit_tx <= 50) logf_("npc hit %u: we hit NPC %llu (type %d, amount %d, part %08x) -> sent to the host", g_nhit_tx, nk.npc, nk.h.type, nk.h.amount, nk.h.part);
        }
        if (g_hitsync && s == 2 && g_npc_role == 1 && src && src == g_av_id) {
            if (++g_nhit_blocked <= 50) logf_("npc hit: dropped the avatar's replayed stim on NPC %llu (amount %d) - the joiner's window decides", npc_id_of(self), *(int *)(ev + 0x58));
            return 0;
        }
        /* type 4 stims are perception ("seen/heard", amount 0-1): they stay local; the rest is damage */
        int dmg = *(int *)(ev + 0x48) != 4 && *(int *)(ev + 0x58);
        if (g_hitsync && s == 0 && g_npc_role == 1 && dmg && src && src != g_net_id && npc_is_synced(src) && g_ns != INVALID_SOCKET) {
            NpcHitPkt nk;
            st_pack(&nk.h, ev, evt);
            nk.h.magic = NSHT_MAGIC; nk.h.seq = ++g_nsht_tx; nk.npc = src;
            sendto(g_ns, (char *)&nk, sizeof nk, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
            if (g_nsht_tx <= 50) logf_("npc shot %u: NPC %llu hit the avatar (type %d, amount %d, part %08x) -> sent to the joiner", g_nsht_tx, src, nk.h.type, nk.h.amount, nk.h.part);
        }
        if (g_hitsync && s == 1 && g_npc_role == 2 && dmg && src && npc_is_synced(src)) {
            if (++g_nsht_blocked <= 50) logf_("npc shot: dropped puppet %llu's own stim on us (amount %d) - the host decides", src, *(int *)(ev + 0x58));
            return 0;
        }
        if (g_hitsync && s == 1 && src && src == g_av_id) {
            if (++g_hit_blocked <= 50) logf_("hit: dropped the avatar's own stim on us (type %d, amount %d) - the shooter's window decides", *(int *)(ev + 0x48), *(int *)(ev + 0x58));
            return 0;
        }
        if (g_st_verbose && ++g_st_n[s] <= 200)
            logf_("stim %u (vt rva %x) -> %s %llu: type %d %d %d %d amount %d / %.2f flags %x src %llu inst %llu bytes %02x%02x%02x%02x%02x i78 %d "
                  "v1 (%.2f %.2f %.2f) v2 (%.2f %.2f %.2f) w %08x %08x %08x %08x %08x", g_st_n[s], evt - (unsigned)g_base, s == 2 ? "npc" : s ? "me" : "avatar", s == 2 ? npc_id_of(self) : g_st_id[s],
                  *(int *)(ev + 0x48), *(int *)(ev + 0x4C), *(int *)(ev + 0x50), *(int *)(ev + 0x54), *(int *)(ev + 0x58), *(float *)(ev + 0x58),
                  *(unsigned *)(ev + 0x5C), st_hid(*(BYTE **)(ev + 0x3C)), st_hid(*(BYTE **)(ev + 0x40)), ev[0x70], ev[0x71], ev[0x72], ev[0x73], ev[0x74],
                  *(int *)(ev + 0x78), *(float *)(ev + 0x7C), *(float *)(ev + 0x80), *(float *)(ev + 0x84), *(float *)(ev + 0x88), *(float *)(ev + 0x8C),
                  *(float *)(ev + 0x90), *(unsigned *)(ev + 0x60), *(unsigned *)(ev + 0x64), *(unsigned *)(ev + 0x68), *(unsigned *)(ev + 0x6C), *(unsigned *)(ev + 0x44));
    } else if (evt && g_st_verbose && ++g_st_other[s] <= 40)
        logf_("event -> %s: %s (vt rva %x)", s == 2 ? "npc" : s ? "me" : "avatar", nm, evt - (unsigned)g_base);
    if (evt == (unsigned)(g_base + 0xE9376C)) {
        /* AI area query (FUN_107ac420): an entity that does not mark the reply (+0x31) must have component FE4090, the
         * game reads its +0x14 unchecked. NPCs spawned here from enemy_archetypes.* can lack it: mark them as skipped. */
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        static unsigned logged;
        int r = ((int (__attribute__((thiscall)) *)(void *, void *))g_st_orig[s])(self, ev);
        if (!ev[0x31] && !((gcomp_t)(g_base + 0x4E2CC0))(self, (void *)(g_base + 0xFE4090))) {
            ev[0x31] = 1;
            if (logged++ < 10) logf_("area query '%s' on %s %llu without component FE4090: marked as skipped (the game would crash)", nm,
                                     s == 2 ? "npc" : s ? "me" : "avatar", s == 2 ? npc_id_of(self) : g_st_id[s]);
        }
        return r;
    }
    return ((int (__attribute__((thiscall)) *)(void *, void *))g_st_orig[s])(self, ev);
}
static void stim_install(unsigned long long id, int slot)
{
    void *hd = NULL;
    BYTE *obj = entity_obj(id, &hd);
    void **vt;
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!obj) { logf_("stimlog: no entity %llu", id); return; }
    vt = *(void ***)obj;
    if (vt == &g_st_vt[slot][1]) return;
    if (g_st_obj[slot] == obj && g_st_orig[slot] && vt[0x20 / 4] != g_st_orig[slot]) { logf_("stimlog: %llu has another event method now, left alone", id); return; }
    if (IsBadReadPtr(vt - 1, sizeof g_st_vt[slot])) { logf_("stimlog: vtable %p not readable", vt); return; }
    memcpy(g_st_vt[slot], vt - 1, sizeof g_st_vt[slot]);
    g_st_orig[slot] = vt[0x20 / 4];
    g_st_vt[slot][1 + 0x20 / 4] = (void *)st_hook;
    *(void ***)obj = &g_st_vt[slot][1];
    g_st_obj[slot] = obj; g_st_id[slot] = id;
    logf_("stimlog: %s %llu object %p vtable %p (rva %x), events now logged", slot ? "me" : "avatar", id, obj, vt, (unsigned)vt - (unsigned)g_base);
}

/* put a synced NPC on the shared NPC vtable copy (slot 2); NPCs of another class are left alone */
static void st_hook_npc(BYTE *obj)
{
    static int warned;
    void **vt = *(void ***)obj;
    if (vt == &g_st_vt[2][1]) return;
    if (!g_st_orig[2]) {
        if (IsBadReadPtr(vt - 1, sizeof g_st_vt[2])) return;
        memcpy(g_st_vt[2], vt - 1, sizeof g_st_vt[2]);
        g_st_orig[2] = vt[0x20 / 4];
        g_st_vt[2][1 + 0x20 / 4] = (void *)st_hook;
        logf_("npc hits: NPC class vtable %p (rva %x) copied", vt, (unsigned)vt - (unsigned)g_base);
    } else if (memcmp(vt, &g_st_vt[2][1], 0x20) || vt[0x20 / 4] != g_st_orig[2]) {
        if (!warned++) logf_("npc hits: NPC %p has another class (vtable rva %x), not hooked", obj, (unsigned)vt - (unsigned)g_base);
        return;
    }
    *(void ***)obj = &g_st_vt[2][1];
}

/* build a stim from a hit packet and hand it to the target's original event method, with srcid (the avatar, or a
 * puppet for NPC shots) as source and instigator */
static void st_deliver(const HitPkt *hp, BYTE *target, void *orig, unsigned long long srcid)
{
    typedef void *(__fastcall *ctor_t)(void *ev);
    BYTE ev[0xC0], *nh;
    void *ah = NULL;
    memset(ev, 0, sizeof ev);
    if (hp->subvt == 0xE119A4) {
        ((ctor_t)(g_base + 0x50FFB0))(ev);
        *(unsigned *)ev = (unsigned)(g_base + 0xE119A4);
        memcpy(ev + 0x94, hp->tail, sizeof hp->tail);
        *(unsigned *)(ev + 0xB0) = *(unsigned *)(g_base + 0xE2C55C);
    } else ((ctor_t)(g_base + 0x50F580))(ev);
    *(int *)(ev + 0x48) = hp->type; *(int *)(ev + 0x58) = hp->amount; *(unsigned *)(ev + 0x5C) = hp->flags;
    *(unsigned *)(ev + 0x44) = hp->part; *(unsigned *)(ev + 0x60) = hp->w60; memcpy(ev + 0x64, hp->pos, sizeof hp->pos);
    /* source and instigator = the avatar (one reference each, released by the destructor like the null handles) */
    if (srcid && entity_obj(srcid, &ah) && ah) {
        nh = *(BYTE **)(ev + 0x3C); (*(int *)(nh + 8))--;
        nh = *(BYTE **)(ev + 0x40); (*(int *)(nh + 8))--;
        (*(int *)((BYTE *)ah + 8))++;
        *(void **)(ev + 0x3C) = ah; *(void **)(ev + 0x40) = ah;
    } else if (ah) (*(int *)((BYTE *)ah + 8))--;
    ((int (__attribute__((thiscall)) *)(void *, void *))orig)(target, ev);
    ((ctor_t)(g_base + 0x50E9F0))(ev);
}

/* NHIT on the host: the joiner's player hit this NPC there */
static void npc_hit_apply(const NpcHitPkt *nk)
{
    void *hd = NULL;
    BYTE *obj;
    if (!g_hitsync || g_npc_role != 1) return;
    obj = entity_obj(nk->npc, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!obj) return;
    st_deliver(&nk->h, obj, *(void ***)obj == &g_st_vt[2][1] ? g_st_orig[2] : (*(void ***)obj)[0x20 / 4], g_av_id);
    if (++g_nhit_rx <= 50) logf_("npc hit %u: the joiner hit NPC %llu (type %d, amount %d, part %08x) -> applied", nk->h.seq, nk->npc, nk->h.type, nk->h.amount, nk->h.part);
}

/* a HIT from the peer: the peer's player hit our avatar there, so our player takes it here. Bullet hits are rebuilt as
 * the bullet stim class (ctor FUN_1050ffb0, vtable RVA E119A4, "none" at +0xB0, the sender's 0x20-byte tail); a base
 * Stim with type 3 read past its end left the player's health at -inf. */
static void hit_apply(const HitPkt *hp)
{
    void *hd = NULL;
    BYTE *me;
    if (!g_hitsync || !g_st_orig[1]) return;
    me = entity_obj(g_net_id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!me || *(void ***)me != &g_st_vt[1][1]) return;
    st_deliver(hp, me, g_st_orig[1], g_av_id);
    if (++g_hit_rx <= 50) logf_("hit %u: the peer hit us (type %d, amount %d, flags %x, part %08x, sub rva %x) -> applied", hp->seq, hp->type, hp->amount, hp->flags, hp->part, hp->subvt);
}

/* keep the event hooks on the avatar and on our player (both get new objects after a respawn) */
static void hit_tick(DWORD now)
{
    static DWORD last;
    void *hd = NULL;
    BYTE *o;
    if (!g_hitsync || now - last < 1000) return;
    last = now;
    if (g_av_id && (o = entity_obj(g_av_id, &hd)) && *(void ***)o != &g_st_vt[0][1]) stim_install(g_av_id, 0);
    if (hd) { (*(int *)((BYTE *)hd + 8))--; hd = NULL; }
    if (g_net_id && (o = entity_obj(g_net_id, &hd)) && *(void ***)o != &g_st_vt[1][1]) stim_install(g_net_id, 1);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
}

/* ---- NPC sync (npcsync host <radius> | join | off) ----
 * host: every 100 ms the AI pawns within the radius (CPawnAgent scan, no players) are encoded by the game's own
 * ThirdParty encoder (FUN_100a6ec0) into a private memento each and sent as one NPC packet.
 * join: each NPC in the packet becomes a puppet once: its agent's AI is paused (agent vf+0x164(1), what the scripted AI
 * mode does for all agents), and it gets the avatar treatment (pawn net component, ThirdParty memento in the applier
 * role, NetPlayer base beautifier, MP-flag window on the third-person main beautifier); afterwards the host's
 * fields are written into its memento every frame. Health travels too, so a kill on the host kills the puppet. */
#define NPC_MAGIC 0x3143504Eu
#define NPC_MAX 24
#pragma pack(push, 1)
typedef struct { unsigned long long id; float pos[3]; int vel[3], aim[4]; unsigned char s104, s11c, s110, pad; float hp, hpmax; unsigned pulls; } NpcEnt;
typedef struct { unsigned magic, seq, count; NpcEnt e[NPC_MAX]; } NpcPkt;
#pragma pack(pop)
static struct { unsigned long long id; BYTE *mem, *obj; unsigned shots, fires; BYTE lastfire; void *wcur; int wmode; char wname[64]; unsigned wcat; DWORD wsent; unsigned lastact; } g_nh[NPC_MAX];
static int g_nh_n;
static BYTE g_npc_this[0x40];
/* lid: the local entity id when the NPC had to be spawned here (the host's id is unknown to this world) */
static struct { unsigned long long id, lid; BYTE *agent, *comp, *mem, *obj; int state, nospawn, gone; NpcEnt e; DWORD last, req; unsigned shots, fires, supp, av[0x70]; int avok; BYTE *mb; void *wcur; int wmode; char wname[64], hw[64]; unsigned wcat, hcat, lastact; int hset, wtries, ownact, respawn; DWORD wfix; } g_np[NPC_MAX];
static int g_np_n;

/* scan for CPawnAgents (vtable RVA EC5078, agent+4 = pawn holder), calling back with id, entity, agent; spread over many
 * calls: each reads at most `budget` bytes of committed read-write memory and continues where the last one stopped (a
 * full pass at once took ~280 ms, a visible hitch); returns 1 when a pass has just been completed. The AI manager's
 * array (*(DAT_11607408 + 0xC) +0x68/+0x6C, what EnableScriptedAIMode walks) holds other objects (vtable EC40D0, no
 * agent pointers in their first 0x300 bytes), so this stays a memory scan. */
typedef struct { BYTE *p, *c; int busy; } IncScan;
static int npc_scan_step(IncScan *s, size_t budget, void (*cb)(unsigned long long id, BYTE *obj, BYTE *agent, void *ctx), void *ctx)
{
    static BYTE chunk[0x10000];
    MEMORY_BASIC_INFORMATION mbi;
    unsigned vt = (unsigned)(g_base + 0xEC5078);
    size_t done = 0;
    if (!s->busy) { s->busy = 1; s->p = NULL; s->c = NULL; }
    while (done < budget) {
        BYTE *rb, *rend;
        if (VirtualQuery(s->p, &mbi, sizeof mbi) != sizeof mbi) { s->busy = 0; return 1; }
        rb = (BYTE *)mbi.BaseAddress; rend = rb + mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && (mbi.Protect & PAGE_READWRITE) && mbi.RegionSize < 0x20000000) {
            if (!s->c || s->c < rb || s->c >= rend) s->c = rb;
            while (s->c < rend && done < budget) {
                size_t n = (size_t)(rend - s->c), k;
                if (n > sizeof chunk) n = sizeof chunk;
                if (safe_read(s->c, chunk, n))
                    for (k = 0; k + 8 <= n; k += 4) {
                        BYTE *holder, *obj;
                        if (*(unsigned *)(chunk + k) != vt) continue;
                        holder = *(BYTE **)(chunk + k + 4);
                        if (!holder || IsBadReadPtr(holder, 16) || !(obj = *(BYTE **)(holder + 0xC)) || IsBadReadPtr(obj, 0xA4)) continue;
                        cb(*(unsigned long long *)holder, obj, s->c + k, ctx);
                    }
                s->c += n; done += n;
            }
            if (s->c < rend) return 0;
        }
        s->p = rend; s->c = NULL;
        if ((ULONG_PTR)rend <= (ULONG_PTR)rb) { s->busy = 0; return 1; }
    }
    return 0;
}
static int npc_has_netcomp(BYTE *obj)
{
    void **cs = *(void ***)(obj + 0x9C);
    int k, n = *(int *)(obj + 0xA0);
    for (k = 0; cs && k < n && k < 64; k++) if (cs[k] && !IsBadReadPtr(cs[k], 4) && *(DWORD *)cs[k] == (DWORD)(g_base + 0xE1AE00)) return 1;
    return 0;
}
static struct { unsigned long long id; BYTE *mem, *obj; unsigned shots, fires; BYTE lastfire; void *wcur; int wmode; char wname[64]; unsigned wcat; DWORD wsent; unsigned lastact; } g_nb[NPC_MAX];  /* list being built */
static int g_nb_n;
static unsigned long long g_nx[64];  /* ids never synced (buddies) */
static int g_nx_n;
static void npc_host_cb(unsigned long long id, BYTE *obj, BYTE *agent, void *ctx)
{
    /* ctx: our player's and the avatar's ground positions; an NPC near either of them is synced */
    float *me = (float *)ctx, r2 = g_npc_rad * g_npc_rad;
    float ax = *(float *)(obj + 0x60) - me[0], ay = *(float *)(obj + 0x64) - me[1];
    float bx = *(float *)(obj + 0x60) - me[2], by = *(float *)(obj + 0x64) - me[3];
    int i;
    (void)agent;
    if (g_nb_n >= NPC_MAX || id == g_net_id || id == g_av_id || (ax * ax + ay * ay > r2 && bx * bx + by * by > r2) || npc_has_netcomp(obj)) return;
    for (i = 0; i < g_nb_n; i++) if (g_nb[i].id == id) return;
    for (i = 0; i < g_nx_n; i++) if (g_nx[i] == id) return;
    {
        /* each player keeps their own buddies (rescue): buddies are not synced */
        char code[96], name[96];
        snprintf(code, sizeof code, "__out = tostring(GetEntityName('%llu'))", id);
        lua_eval(code, name, sizeof name);
        if (!strncmp(name, "buddies.", 8)) { if (g_nx_n < 64) g_nx[g_nx_n++] = id; logf_("npcsync host: %llu is a buddy (%s), not synced", id, name); return; }
    }
    memset(&g_nb[g_nb_n], 0, sizeof g_nb[0]);
    g_nb[g_nb_n].id = id; g_nb[g_nb_n].obj = obj; g_nb_n++;
}
static float npc_hp(BYTE *obj, float *hpmax)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    BYTE *cc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDF9A8)), *hc;
    if (cc && !IsBadReadPtr(cc + 0x44, 4) && (hc = *(BYTE **)(cc + 0x44)) && !IsBadReadPtr(hc, 0x18)) { *hpmax = *(float *)(hc + 0x14); return *(float *)(hc + 0x10); }
    *hpmax = 0; return -1;
}
/* animation graph inputs. Idle actions (flask, food, smoke, holstered weapon) are chosen by the AI and reach the
 * animation graph as variables, not through the beautifiers: *(anim component (key FDF190) + 0x1C) + 0x10 + index * 4
 * (setters FUN_1051f460/480/4a0, FUN_10520a20). v58 is the current action (-1 none, 6, 10 seen on the host), v42 is
 * set while it runs, v43/v44/v46 move with it; a puppet sat at v58 = 9 instead. The host sends v00..v6F of each NPC
 * (NANM, 5 times a second); the joiner writes them into its puppet's graph right after the puppet's third-person
 * beautifier update, except the 23 variables that update sets itself from the synced movement (g_anim_own). */
#define NANM_MAGIC 0x4D4E414Eu
#define NANM_VARS 0x70
#pragma pack(push, 1)
typedef struct { unsigned magic; unsigned long long id; unsigned v[NANM_VARS]; } NpcAnimPkt;
#pragma pack(pop)
/* the 23 variables FUN_100ac190 sets from the synced movement stay the puppet's own. Tried: keeping only the 8 that
 * change every frame (v00 v01 v02 v0b v1d v34 v38 v5f) and taking the rest from the host - idle actions still did not
 * play (a host NPC drank, its puppet stood): the variables mirror the action, they do not start it */
static const unsigned char g_anim_own[] = { 0x00, 0x01, 0x02, 0x07, 0x08, 0x0b, 0x14, 0x1d, 0x1f, 0x20, 0x25, 0x26, 0x33, 0x34, 0x38, 0x40,
                                            0x5c, 0x5d, 0x5e, 0x5f, 0x62, 0x65, 0x66 };
static unsigned *npc_animvars(BYTE *obj)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    BYTE *ac = obj ? ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDF190)) : NULL, *vb;
    if (!ac || IsBadReadPtr(ac + 0x1C, 4) || !(vb = *(BYTE **)(ac + 0x1C)) || IsBadWritePtr(vb + 0x10, NANM_VARS * 4)) return NULL;
    return (unsigned *)(vb + 0x10);
}
/* npcweap: log what an NPC holds whenever it changes (inventory FUN_1007e140(pawn), mode FUN_10125f40, current
 * FUN_10127da0, name by GetEntityName): do idle actions (flask, food) switch to inventory items? */
#define NWPN_MAGIC 0x4E50574Eu
#pragma pack(push, 1)
typedef struct { unsigned magic; unsigned long long id; unsigned cat; char name[64]; } NpcWeapPkt;
#pragma pack(pop)
static int npc_weap_watch(const char *who, unsigned long long id, BYTE *obj, void **wcur, int *wmode, char *wname, unsigned *wcat)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void *(__fastcall *inv_t)(void *pawn);
    typedef int (__attribute__((thiscall)) *iget_t)(void *inv);
    typedef void *(__attribute__((thiscall)) *cur_t)(void *inv);
    void *pawn = obj ? ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)) : NULL, *inv, *cur = NULL;
    int mode = -1;
    char code[96], name[96] = "";
    if (!pawn || !(inv = ((inv_t)(g_base + 0x7E140))(pawn))) return 0;
    mode = ((iget_t)(g_base + 0x125F40))(inv);
    cur = mode == 1 ? ((cur_t)(g_base + 0x127DA0))(inv) : NULL;
    if (cur == *wcur && mode == *wmode) return 0;
    *wcur = cur; *wmode = mode; *wcat = 0;
    if (cur) {
        typedef unsigned (__attribute__((thiscall)) *slot_t)(void *weapon);
        void *wh = *(void **)((BYTE *)cur + 8);
        unsigned slot = ((slot_t)(*(void ***)cur)[0x8C / 4])(cur);
        if (slot && !IsBadReadPtr((void *)slot, 4)) *wcat = *(unsigned *)slot;
        if (wh && !IsBadReadPtr(wh, 8)) { snprintf(code, sizeof code, "__out = tostring(GetEntityName('%llu'))", *(unsigned long long *)wh); lua_eval(code, name, sizeof name); }
        if (!strcmp(name, "nil")) name[0] = 0;
    }
    memcpy(wname, name, 64); wname[63] = 0;
    logf_("npcweap %s %llu: mode %d, current %p '%s' category %08x", who, id, mode, cur, wname, *wcat);
    return 1;
}
static void npc_host_tick(DWORD now)
{
    static DWORD last_scan, last_send;
    static unsigned seq;
    NpcPkt pk;
    int i, n = 0;
    static IncScan hs;
    static float mp[4];
    if (g_npc_role != 1 || g_ns == INVALID_SOCKET) return;
    /* re-pick the NPCs near us or the avatar: a pass every 15 s, 16 MB of memory per frame (a full pass at once was a
     * ~280 ms hitch); the finished list keeps the mementos and counters of the NPCs that stay */
    if (!hs.busy && (!last_scan || now - last_scan > 15000)) {
        void *hd = NULL;
        BYTE *me = entity_obj(g_net_id, &hd), *av;
        if (hd) { (*(int *)((BYTE *)hd + 8))--; hd = NULL; }
        memset(mp, 0, sizeof mp);
        if (me) memcpy(mp, me + 0x60, 2 * sizeof(float));
        av = g_av_id ? entity_obj(g_av_id, &hd) : NULL;
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (av) memcpy(mp + 2, av + 0x60, 2 * sizeof(float)); else { mp[2] = mp[0]; mp[3] = mp[1]; }
        g_nb_n = 0; last_scan = now; hs.busy = 0;
        npc_scan_step(&hs, 0, npc_host_cb, mp);
    }
    if (hs.busy && npc_scan_step(&hs, 16u << 20, npc_host_cb, mp)) {
        int j, changed = g_nb_n != g_nh_n;
        for (i = 0; i < g_nb_n; i++) {
            for (j = 0; j < g_nh_n && g_nh[j].id != g_nb[i].id; j++) ;
            if (j < g_nh_n) { g_nb[i].mem = g_nh[j].mem; g_nb[i].shots = g_nh[j].shots; g_nb[i].fires = g_nh[j].fires; g_nb[i].lastfire = g_nh[j].lastfire; g_nb[i].wcur = g_nh[j].wcur; g_nb[i].wmode = g_nh[j].wmode; memcpy(g_nb[i].wname, g_nh[j].wname, 64); g_nb[i].wcat = g_nh[j].wcat; g_nb[i].lastact = g_nh[j].lastact; }
            else changed = 1;
        }
        memcpy(g_nh, g_nb, sizeof g_nh); g_nh_n = g_nb_n;
        if (changed) logf_("npcsync host: %d NPCs within %.0f m of us or the avatar (pass %lu ms)", g_nh_n, g_npc_rad, GetTickCount() - last_scan);
    }
    if (now - last_send < 100) return;
    last_send = now;
    memset(&pk, 0, sizeof pk);
    for (i = 0; i < g_nh_n; i++) {
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        void *hd = NULL, *pawn;
        BYTE *obj = entity_obj(g_nh[i].id, &hd), *m;
        NpcEnt *e = &pk.e[n];
        int k;
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!obj) continue;
        pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
        if (!pawn) continue;
        if (!g_nh[i].mem) g_nh[i].mem = ((np_factory_t)(g_base + 0x40110))();
        g_nh[i].obj = obj;
        if (g_hitsync) st_hook_npc(obj);
        /* the NPC's weapon (or none, holstered) goes to the joiner on every change and every 4 s */
        if (npc_weap_watch("host", g_nh[i].id, obj, &g_nh[i].wcur, &g_nh[i].wmode, g_nh[i].wname, &g_nh[i].wcat) || now - g_nh[i].wsent > 4000) {
            NpcWeapPkt w;
            memset(&w, 0, sizeof w);
            w.magic = NWPN_MAGIC; w.id = g_nh[i].id; w.cat = g_nh[i].wcat; memcpy(w.name, g_nh[i].wname, sizeof w.name);
            sendto(g_ns, (char *)&w, sizeof w, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
            g_nh[i].wsent = now;
        }
        if (!(m = g_nh[i].mem)) continue;
        *(void **)(g_npc_this + 0x10) = pawn;
        ((np_encode_t)(g_base + 0xA6EC0))(g_npc_this, m);
        e->id = g_nh[i].id;
        memcpy(e->pos, obj + 0x60, sizeof e->pos);
        for (k = 0; k < 3; k++) e->vel[k] = *(int *)(m + 0x78 + 0x14 * k);
        e->aim[0] = *(int *)(m + 0xB4); e->aim[1] = *(int *)(m + 0xC8); e->aim[2] = *(int *)(m + 0xDC); e->aim[3] = *(int *)(m + 0xF0);
        /* the encoder leaves the first (look) pair at 0/0 for AI pawns while the second pair holds the body yaw (a doorman
         * facing 1.67 rad stood at 0 on the joiner, the third-person beautifier turns the body to the look pair): the body
         * yaw goes into both; head turns come with the animation graph inputs */
        e->aim[0] = 0; e->aim[1] = e->aim[3];
        e->s104 = m[0x104]; e->s11c = m[0x11C]; e->s110 = m[0x110];
        if (e->s104 && !g_nh[i].lastfire) g_nh[i].fires++;
        g_nh[i].lastfire = e->s104;
        e->hp = npc_hp(obj, &e->hpmax);
        e->pulls = g_nh[i].shots;
        n++;
    }
    if (g_npcanim && seq % 2 == 0)
        for (i = 0; i < g_nh_n; i++) {
            NpcAnimPkt a;
            unsigned *v = g_nh[i].obj ? npc_animvars(g_nh[i].obj) : NULL;
            if (!v || !safe_read(v, a.v, sizeof a.v)) continue;
            if (a.v[0x58] != g_nh[i].lastact) {
                logf_("npcact host %llu: action v58 %d -> %d (v42 %u v48 %u v11 %u v12 %u)", g_nh[i].id, (int)g_nh[i].lastact, (int)a.v[0x58], a.v[0x42],
                      a.v[0x48], a.v[0x11], a.v[0x12]);
                g_nh[i].lastact = a.v[0x58];
            }
            a.magic = NANM_MAGIC; a.id = g_nh[i].id;
            sendto(g_ns, (char *)&a, sizeof a, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
        }
    pk.magic = NPC_MAGIC; pk.seq = ++seq; pk.count = n;
    if (n) sendto(g_ns, (char *)&pk, 12 + n * sizeof(NpcEnt), 0, (struct sockaddr *)&g_peer, sizeof g_peer);
}
static void npc_rx(const NpcPkt *pk, int len)
{
    unsigned i;
    int j;
    if (g_npc_role != 2 || len < 12 || pk->count > NPC_MAX || len < (int)(12 + pk->count * sizeof(NpcEnt))) return;
    for (i = 0; i < pk->count; i++) {
        for (j = 0; j < g_np_n && g_np[j].id != pk->e[i].id; j++) ;
        if (j == g_np_n) { if (g_np_n >= NPC_MAX) continue; memset(&g_np[j], 0, sizeof g_np[j]); g_np[j].id = pk->e[i].id; g_np_n++; }
        g_np[j].e = pk->e[i]; g_np[j].last = GetTickCount();
    }
}
static unsigned long long npc_id_of(BYTE *obj)
{
    int i;
    for (i = 0; i < g_np_n; i++) if (g_np[i].obj == obj) return g_np[i].id;
    for (i = 0; i < g_nh_n; i++) if (g_nh[i].obj == obj) return g_nh[i].id;
    return 0;
}
static int npc_is_synced(unsigned long long id)
{
    int i;
    for (i = 0; i < g_np_n; i++) if (g_np[i].id == id || (g_np[i].lid && g_np[i].lid == id)) return 1;
    for (i = 0; i < g_nh_n; i++) if (g_nh[i].id == id) return 1;
    return 0;
}
/* NPC trigger pulls: the host counts them per NPC and sends the count; a puppet may only pull its trigger as often as
 * its host NPC did (its own paused AI still fired back at the joiner's gunfire); the rest of a refused shot (start_shoot,
 * WeaponFireBullet) is refused too */
static int npc_shot_ok(BYTE *obj, int pull)
{
    int i;
    for (i = 0; i < g_nh_n; i++) if (g_nh[i].obj == obj) { if (pull) g_nh[i].shots++; return 1; }
    for (i = 0; i < g_np_n; i++) if (g_np[i].obj == obj) {
        if (pull) {
            if (g_np[i].shots < g_np[i].e.pulls) { g_np[i].shots++; g_np[i].fires = 1; return 1; }
            g_np[i].supp++; g_np[i].fires = 0; return 0;
        }
        return g_np[i].fires != 0;
    }
    return 1;
}

/* spawn requests: the joiner asks for the archetype of an NPC id its world lacks (NREQ), the host answers with
 * GetEntityName (NARC), the joiner spawns it there and drives it like any other puppet */
#define NREQ_MAGIC 0x5145524Eu
#define NARC_MAGIC 0x4352414Eu
#pragma pack(push, 1)
typedef struct { unsigned magic; unsigned long long id; char name[96]; } NpcArcPkt;
#pragma pack(pop)
static void npc_req_rx(const NpcArcPkt *q)
{
    NpcArcPkt a;
    char code[96];
    if (g_npc_role != 1 || g_ns == INVALID_SOCKET) return;
    memset(&a, 0, sizeof a);
    a.magic = NARC_MAGIC; a.id = q->id;
    snprintf(code, sizeof code, "__out = tostring(GetEntityName('%llu'))", q->id);
    lua_eval(code, a.name, sizeof a.name);
    sendto(g_ns, (char *)&a, sizeof a, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    logf_("npcsync host: the joiner lacks NPC %llu -> sent its name '%s'", q->id, a.name);
}
/* spawn an NPC from a host name: the name itself (reinforcements are named enemy_archetypes.<faction>.<class>), else
 * for a save NPC's instance name (Red_Faction.Assault_Caucasian_38) "enemy_archetypes." + the name without its number */
static unsigned long long npc_spawn_named(const char *name, const float *pos, char *used, size_t un)
{
    char code[240], out[40], alt[120];
    unsigned long long lid;
    int k;
    for (k = 0; k < 2; k++) {
        const char *nm = name;
        if (k == 1) {
            char *u;
            snprintf(alt, sizeof alt, "enemy_archetypes.%s", name);
            u = strrchr(alt, '_');
            if (!u || !u[1] || strspn(u + 1, "0123456789") != strlen(u + 1)) return 0;
            *u = 0; nm = alt;
        }
        snprintf(code, sizeof code, "__out = tostring(SpawnEntityFromArchetype('%s', %.3f, %.3f, %.3f, 0, 0, 0))", nm, pos[0], pos[1], pos[2]);
        lua_eval(code, out, sizeof out);
        lid = strtoull(out, NULL, 10);
        if (lid && out[0] != '-' && lid != ~0ULL) { snprintf(used, un, "%s", nm); return lid; }
    }
    return 0;
}
static void npc_arc_rx(const NpcArcPkt *a)
{
    char name[96], used[120];
    int j;
    unsigned long long lid;
    if (g_npc_role != 2) return;
    for (j = 0; j < g_np_n && g_np[j].id != a->id; j++) ;
    if (j == g_np_n || g_np[j].lid || g_np[j].nospawn) return;
    memcpy(name, a->name, sizeof name); name[sizeof name - 1] = 0;
    if (!name[0] || strchr(name, '\'') || !strcmp(name, "nil") || !strncmp(name, "buddies.", 8)) { g_np[j].nospawn = 1; logf_("npcsync join: no name for NPC %llu ('%s')", a->id, name); return; }
    lid = npc_spawn_named(name, g_np[j].e.pos, used, sizeof used);
    if (!lid) { g_np[j].nospawn = 1; logf_("npcsync join: spawning '%s' for host NPC %llu failed%s", name, a->id, g_np[j].respawn ? ", the puppet stays as it is" : ""); return; }
    if (g_np[j].respawn == 1) {
        /* the fresh NPC exists: now the old one goes, and the puppet is rebuilt on the new entity */
        char rm[96], o2[16];
        snprintf(rm, sizeof rm, "RemoveEntity('%llu') __out = 'ok'", g_np[j].id);
        lua_eval(rm, o2, sizeof o2);
        g_np[j].respawn = 2; g_np[j].state = 0; g_np[j].agent = NULL; g_np[j].obj = NULL; g_np[j].mb = NULL; g_np[j].comp = NULL; g_np[j].mem = NULL;
        g_np[j].wcur = NULL; g_np[j].wmode = 0; g_np[j].wname[0] = 0; g_np[j].wtries = 0;
    }
    g_np[j].lid = lid;
    logf_("npcsync join: spawned '%s' as %llu for host NPC %llu at (%.1f %.1f %.1f)%s", used, lid, a->id, g_np[j].e.pos[0], g_np[j].e.pos[1],
          g_np[j].e.pos[2], g_np[j].respawn == 2 ? ", replacing our own copy" : "");
}
/* NSHT on the joiner: a host NPC hit our avatar there, so our player takes it here from that NPC's puppet */
static void npc_shot_apply(const NpcHitPkt *nk)
{
    void *hd = NULL;
    BYTE *me;
    int j;
    unsigned long long src = nk->npc;
    if (!g_hitsync || g_npc_role != 2 || !g_st_orig[1]) return;
    for (j = 0; j < g_np_n; j++) if (g_np[j].id == nk->npc) { if (g_np[j].lid) src = g_np[j].lid; break; }
    me = entity_obj(g_net_id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!me || *(void ***)me != &g_st_vt[1][1]) return;
    st_deliver(&nk->h, me, g_st_orig[1], src);
    if (++g_nsht_rx <= 50) logf_("npc shot %u: host NPC %llu hit us (type %d, amount %d, part %08x) -> applied", nk->h.seq, nk->npc, nk->h.type, nk->h.amount, nk->h.part);
}
static void npc_anim_rx(const NpcAnimPkt *a)
{
    int j;
    if (g_npc_role != 2) return;
    for (j = 0; j < g_np_n; j++) if (g_np[j].id == a->id) { memcpy(g_np[j].av, a->v, sizeof g_np[j].av); g_np[j].avok = 1; return; }
}
/* called after a remote-driven main beautifier's update (mf_call) */
static void npc_anim_apply(BYTE *mb)
{
    static unsigned char own[NANM_VARS];
    static int init;
    unsigned *v;
    int j, k;
    if (g_npc_role != 2 || !g_npcanim) return;
    if (!init) { for (k = 0; k < (int)sizeof g_anim_own; k++) own[g_anim_own[k]] = 1; init = 1; }
    for (j = 0; j < g_np_n; j++)
        if (g_np[j].mb == mb) {
            if (g_np[j].avok && (v = npc_animvars(g_np[j].obj))) {
                if (!g_np[j].lastact && !g_np[j].lid && (v[0x58] != g_np[j].av[0x58] || v[0x42] != g_np[j].av[0x42])) g_np[j].ownact = 1;
                if (g_np[j].av[0x58] != g_np[j].lastact) {
                    logf_("npcact puppet %llu: host action %d -> %d, puppet graph had %d (v42 %u -> %u)", g_np[j].id, (int)g_np[j].lastact,
                          (int)g_np[j].av[0x58], (int)v[0x58], v[0x42], g_np[j].av[0x42]);
                    g_np[j].lastact = g_np[j].av[0x58];
                }
                for (k = 0; k < NANM_VARS; k++) if (!own[k]) v[k] = g_np[j].av[k];
            }
            return;
        }
}
/* NWPN on the joiner: what the host NPC holds; the puppet is made to hold the same (see npc_weap_fix) */
static void npc_weap_rx(const NpcWeapPkt *w)
{
    int j;
    if (g_npc_role != 2) return;
    for (j = 0; j < g_np_n; j++)
        if (g_np[j].id == w->id) {
            if (strncmp(g_np[j].hw, w->name, 64) || !g_np[j].hset) g_np[j].wtries = 0;
            memcpy(g_np[j].hw, w->name, 64); g_np[j].hw[63] = 0; g_np[j].hcat = w->cat; g_np[j].hset = 1;
            /* a host NPC at a stationary gun reports it as its weapon; given to a puppet it hung at its side: holster */
            if (!strncmp(g_np[j].hw, "weapons.MountedWeapons.", 23)) { g_np[j].hw[0] = 0; g_np[j].hcat = 0; }
            return;
        }
}
/* a puppet that holds something else than its host NPC (its paused AI still switches weapons; idle actions holster
 * them): holster (FUN_1012b340, what HolsterWeapon does), select by category (FUN_1012ce80), and when the puppet does
 * not have that weapon after a select, give it one (pawn_give_weapon); at most every 1.5 s, 4 tries per change */
static void npc_weap_fix(int j, BYTE *obj, DWORD now)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void *(__fastcall *inv_t)(void *pawn);
    typedef void (__attribute__((thiscall)) *inv0_t)(void *inv);
    typedef void (__attribute__((thiscall)) *sel_t)(void *inv, unsigned *cat);
    void *pawn, *inv;
    if (!g_np[j].hset || !strcmp(g_np[j].wname, g_np[j].hw) || now - g_np[j].wfix < 1500 || g_np[j].wtries >= 4) return;
    g_np[j].wfix = now; g_np[j].wtries++;
    if (!(pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C))) || !(inv = ((inv_t)(g_base + 0x7E140))(pawn))) return;
    if (!g_np[j].hw[0]) ((inv0_t)(g_base + 0x12B340))(inv);
    else if (g_np[j].wtries <= 2 && g_np[j].hcat) { unsigned cat = g_np[j].hcat; ((sel_t)(g_base + 0x12CE80))(inv, &cat); }
    else pawn_give_weapon(obj, g_np[j].hw, "npcweap give");
    logf_("npcweap fix %llu: holds '%s', host holds '%s' -> %s (try %d)", g_np[j].id, g_np[j].wname, g_np[j].hw,
          !g_np[j].hw[0] ? "holster" : g_np[j].wtries <= 2 ? "select" : "give", g_np[j].wtries);
}
static void npc_join_find_cb(unsigned long long id, BYTE *obj, BYTE *agent, void *ctx)
{
    int j;
    (void)obj; (void)ctx;
    for (j = 0; j < g_np_n; j++) if ((g_np[j].id == id || (g_np[j].lid && g_np[j].lid == id)) && !g_np[j].agent) g_np[j].agent = agent;
}
/* per synced NPC: shots seen (start_shoot events), health; host and joiner lines compare by id */
static void npc_stat(void)
{
    int i;
    for (i = 0; i < g_nh_n; i++) {
        float mx; void *hd = NULL; BYTE *o = entity_obj(g_nh[i].id, &hd);
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        logf_("npcstat %llu: trigger pulls %u (fire-bit bursts %u) hp %.0f", g_nh[i].id, g_nh[i].shots, g_nh[i].fires, o ? npc_hp(o, &mx) : -2.0f);
    }
    for (i = 0; i < g_np_n; i++)
        logf_("npcstat %llu: host pulls %u, puppet pulls %u, refused %u, hp %.0f state %d%s%s", g_np[i].id, g_np[i].e.pulls, g_np[i].shots, g_np[i].supp, g_np[i].e.hp, g_np[i].state,
              g_np[i].lid ? " spawned here" : "", g_np[i].gone ? " GONE" : "");
    logf_("npcstat done: npc shots at players sent %u applied %u dropped %u, npc hits sent %u applied %u dropped %u", g_nsht_tx, g_nsht_rx, g_nsht_blocked,
          g_nhit_tx, g_nhit_rx, g_nhit_blocked);
}

/* the joiner's own world must not run NPCs of its own: NPCs it spawns at runtime (alarm reinforcements, patrols; their ids
 * have the high bit set, save NPCs do not) fought and killed the joiner's player. They are removed (RemoveEntity); the
 * host's versions come as puppets. Kept: our puppets, players, the avatar, buddies. */
static unsigned long long g_nr[32];
static int g_nr_n;
static unsigned long long g_nkeep[32];
static int g_nkeep_n;
static BYTE *g_npaused[160];
static int g_npaused_n;
static void npc_join_local_cb(unsigned long long id, BYTE *obj, BYTE *agent, void *ctx)
{
    int j;
    (void)obj; (void)agent; (void)ctx;
    npc_join_find_cb(id, obj, agent, ctx);
    /* every NPC of the save is paused as soon as it is found, before the host's packets make it a puppet */
    if (!(id >> 63) && id != g_net_id && id != g_av_id && agent) {
        for (j = 0; j < g_npaused_n && g_npaused[j] != agent; j++) ;
        if (j == g_npaused_n && g_npaused_n < 160) {
            ((void (__attribute__((thiscall)) *)(void *, char))(*(void ***)agent)[0x164 / 4])(agent, 1);
            g_npaused[g_npaused_n++] = agent;
            if (g_npaused_n <= 3 || g_npaused_n % 20 == 0) logf_("npcsync join: paused the AI of %d NPCs so far (last %llu)", g_npaused_n, id);
        }
    }
    if (!(id >> 63) || id == g_net_id || id == g_av_id || g_nr_n >= 32) return;
    for (j = 0; j < g_np_n; j++) if (g_np[j].lid == id || g_np[j].id == id) return;
    for (j = 0; j < g_nkeep_n; j++) if (g_nkeep[j] == id) return;
    g_nr[g_nr_n++] = id;
}
static void npc_join_tick(DWORD now)
{
    static DWORD last_find;
    int j, k;
    if (g_npc_role != 2) return;
    static IncScan js;
    if (!js.busy && now - last_find > 3000) { g_nr_n = 0; last_find = now; npc_scan_step(&js, 0, npc_join_local_cb, NULL); }
    if (js.busy && npc_scan_step(&js, 16u << 20, npc_join_local_cb, NULL)) {
        last_find = now;
        for (k = 0; k < g_nr_n; k++) {
            char code[120], name[96];
            snprintf(code, sizeof code, "__out = tostring(GetEntityName('%llu'))", g_nr[k]);
            lua_eval(code, name, sizeof name);
            if (!strncmp(name, "buddies.", 8) || !strncmp(name, "player.", 7)) { if (g_nkeep_n < 32) g_nkeep[g_nkeep_n++] = g_nr[k]; continue; }
            snprintf(code, sizeof code, "RemoveEntity('%llu')", g_nr[k]);
            lua_eval(code, name, sizeof name);
            logf_("npcsync join: removed our own NPC %llu (%s) - the host runs NPCs", g_nr[k], name);
        }
    }
    for (j = 0; j < g_np_n; j++) {
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        void *hd = NULL;
        BYTE *obj = entity_obj(g_np[j].lid ? g_np[j].lid : g_np[j].id, &hd), *m;
        NpcEnt *e = &g_np[j].e;
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!obj) {
            /* not in this world (spawned on the host after the save): ask for its archetype, at most every 3 s */
            if (g_np[j].state == 1 && !g_np[j].gone) { g_np[j].gone = 1; logf_("npcsync join: puppet %llu is gone from this world", g_np[j].id); }
            if (g_np[j].state == 0 && !g_np[j].lid && !g_np[j].nospawn && e->hp > 0 && now - g_np[j].req > 3000 && g_ns != INVALID_SOCKET) {
                NpcArcPkt q;
                memset(&q, 0, sizeof q); q.magic = NREQ_MAGIC; q.id = g_np[j].id; g_np[j].req = now;
                sendto(g_ns, (char *)&q, sizeof q, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
            }
            continue;
        }
        if (g_np[j].state == 0) {
            BYTE *comp = NULL, *bc;
            void **cs = *(void ***)(obj + 0x9C);
            int n = *(int *)(obj + 0xA0);
            if (!g_np[j].agent) continue;
            ((void (__attribute__((thiscall)) *)(void *, char))(*(void ***)g_np[j].agent)[0x164 / 4])(g_np[j].agent, 1);
            for (k = 0; cs && k < n && k < 64; k++) if (cs[k] && !IsBadReadPtr(cs[k], 4) && *(DWORD *)cs[k] == (DWORD)(g_base + 0xE1AE00)) { comp = cs[k]; break; }
            if (!comp) { comp = ((np_factory_t)(g_base + 0x40840))(); if (!comp) continue; ((np_addcomp_t)(g_base + 0x4E0D80))(obj, comp); }
            m = *(BYTE **)(comp + 0x170);
            if (!m) m = ((np_factory_t)(g_base + 0x40110))();
            if (!m) continue;
            *(unsigned *)(comp + 0x40) = 1; comp[0x44] = 1; *(unsigned *)(comp + 0x164) = 1; *(BYTE **)(comp + 0x170) = m;
            *(float *)(m + 0x13C) = e->hp > 0 ? e->hp : 0; m[0x134] = 1; *(unsigned *)(m + 0x14C) = (unsigned)e->hpmax; m[0x148] = 1;
            np_pos(m + 4, e->pos); np_pos(m + 0x1A4, e->pos);
            g_np[j].comp = comp; g_np[j].mem = m; g_np[j].state = 1; g_np[j].obj = obj;
            if (g_hitsync) st_hook_npc(obj);
            np_slot(obj, 0x2C, 0x608487bc, 0xFFFFFFFFu, 0xFFFFFFFFu);
            bc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4));
            if (bc) { mf_install(bc); g_np[j].mb = *(BYTE **)(bc + 0x28); }
            logf_("npcsync join: NPC %llu%s is a puppet now (FE4090 %s, agent %p paused, comp %p, memento %p, main vt %08x, hp %.0f/%.0f)", g_np[j].id, g_np[j].lid ? " (spawned here)" : "",
                  ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFE4090)) ? "yes" : "NO", g_np[j].agent,
                  comp, m, bc && *(void **)(bc + 0x28) ? **(unsigned **)(bc + 0x28) : 0, e->hp, e->hpmax);
            continue;
        }
        if (g_npcrespawn && g_np[j].ownact && !g_np[j].respawn && !g_np[j].lid && g_ns != INVALID_SOCKET) {
            /* its graph runs an action of its own (started before the session connected) that the host's inputs do not
             * stop: replace the NPC by a fresh one of the same archetype (NREQ/NARC as for the host's spawns) */
            NpcArcPkt q;
            memset(&q, 0, sizeof q); q.magic = NREQ_MAGIC; q.id = g_np[j].id;
            sendto(g_ns, (char *)&q, sizeof q, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
            g_np[j].respawn = 1; g_np[j].req = now;
            logf_("npcsync join: puppet %llu runs an action of its own, asking for its archetype to respawn it", g_np[j].id);
        }
        m = g_np[j].mem;
        if (!m) continue;
        npc_weap_watch("puppet", g_np[j].id, obj, &g_np[j].wcur, &g_np[j].wmode, g_np[j].wname, &g_np[j].wcat);
        npc_weap_fix(j, obj, now);
        np_pos(m + 4, e->pos);
        for (k = 0; k < 3; k++) { *(int *)(m + 0x78 + 0x14 * k) = e->vel[k]; m[0x74 + 0x14 * k] = 1; }
        { static const int aimf[4] = { 0xAC, 0xC0, 0xD4, 0xE8 }; for (k = 0; k < 4; k++) { *(int *)(m + aimf[k] + 8) = e->aim[k]; m[aimf[k] + 4] = 1; } }
        m[0x104] = e->s104; m[0x100] = 1; m[0x11C] = e->s11c; m[0x118] = 1; m[0x110] = e->s110; m[0x10C] = 1;
        if (e->hp >= 0) { *(float *)(m + 0x13C) = e->hp; m[0x134] = 1; }
    }
}

static void av_tick(DWORD now)
{
    av_init_ptr();
    if (g_net_rx == 0 || now - g_net_lastrx > 3000) return;
    if (!g_av_id) {
        char code[256], out[64];
        unsigned long long id;
        if (now - g_av_lastspawn < 3000) return;
        g_av_lastspawn = now;
        if (g_av_np)
            snprintf(code, sizeof code, "__out = tostring(SpawnEntityFromArchetype('%s', %.3f, %.3f, %.3f, 0, 0, 0))",
                     g_av_arch, g_remote.pos[0] + g_av_off[0], g_remote.pos[1] + g_av_off[1], g_remote.pos[2] + 1.0f);
        else
            snprintf(code, sizeof code, "__out = tostring(SpawnEntityFromArchetype(GetEntityName(GetLocalPlayerId()), %.3f, %.3f, %.3f, 0, 0, 0))",
                     g_remote.pos[0], g_remote.pos[1], g_remote.pos[2]);
        lua_eval(code, out, sizeof out);
        id = strtoull(out, NULL, 10);
        if (id == 0 || id == 0xFFFFFFFFFFFFFFFFull) { logf_("avatar spawn failed: %s", out); return; }
        g_av_id = id;
        logf_("avatar spawned: %llu", id);
        snprintf(code, sizeof code, "CDominoManager_GetInstance():SendRegisteredEventToEntity('%llu', 'CFCXCountersComponent_SetInvincible') __out = 'ok'", id);
        lua_eval(code, out, sizeof out);
        logf_("avatar set invincible: status %s", out);
        return;
    }
    if (g_av_np) {
        /* give the new entity a moment to finish spawning, then set it up once */
        if (!g_av_mem) {
            if (now - g_av_lastspawn < 4000 || g_av_npstate) return;
            g_av_npstate = 1;
            g_av_mem = np_setup(g_av_id);
            if (!g_av_mem) logf_("avatar np: setup failed");
            return;
        }
        np_tick(now);
        /* the peer changed the weapon in its hands: give the avatar the same one (retry at most every 2 s) */
        if (strcmp(g_rx_weap, g_av_weap) && now - g_av_weap_try > 2000) {
            g_av_weap_try = now;
            if (!g_rx_weap[0]) { logf_("avweapon: peer holds no weapon (keeping '%s')", g_av_weap); strcpy(g_av_weap, g_rx_weap); }
            else if (av_give_weapon(g_rx_weap)) strcpy(g_av_weap, g_rx_weap);
        }
        return;
    }
    if (!av_valid()) {
        if (!g_body) return;  /* need our own body first, so it can be excluded */
        if (now - g_av_lastfind < 1000) return;
        g_av_lastfind = now;
        if (find_body(g_av_id, &g_av_body, &g_av_mat, g_body)) { g_av_have = 0; logf_("avatar body bound: %p (local body %p)", g_av_body, g_body); }
        return;
    }
    {
        float *cur = g_av_cur, *tg = g_remote.pos;
        float d = fabsf(tg[0] - cur[0]) + fabsf(tg[1] - cur[1]) + fabsf(tg[2] - cur[2]);
        if (!g_av_have || d > 6.0f) { memcpy(cur, tg, sizeof g_av_cur); g_av_have = 1; }
        else { cur[0] += (tg[0] - cur[0]) * 0.25f; cur[1] += (tg[1] - cur[1]) * 0.25f; cur[2] += (tg[2] - cur[2]) * 0.25f; }
        *(float *)(g_av_mat + 0x30) = cur[0]; *(float *)(g_av_mat + 0x34) = cur[1]; *(float *)(g_av_mat + 0x38) = cur[2];
    }
    /* heading: the body capsule never rotates and the avatar has no controller, so the entity matrix
     * keeps whatever rotation is written into it (yaw only, rows (d0,d1,0) (-d1,d0,0) (0,0,1),
     * the same layout as the player's) */
    {
        float dx = g_remote.dir[0], dy = g_remote.dir[1], n = sqrtf(dx * dx + dy * dy);
        void *holder = NULL;
        BYTE *obj;
        if (n < 0.5f) return;
        dx /= n; dy /= n;
        if (!g_av_have || g_av_dir[0] * dx + g_av_dir[1] * dy < -0.9f) { g_av_dir[0] = dx; g_av_dir[1] = dy; }
        else {
            g_av_dir[0] += (dx - g_av_dir[0]) * 0.25f; g_av_dir[1] += (dy - g_av_dir[1]) * 0.25f;
            n = sqrtf(g_av_dir[0] * g_av_dir[0] + g_av_dir[1] * g_av_dir[1]);
            if (n < 1e-3f) { g_av_dir[0] = dx; g_av_dir[1] = dy; } else { g_av_dir[0] /= n; g_av_dir[1] /= n; }
        }
        obj = entity_obj(g_av_id, &holder);
        if (obj && !IsBadWritePtr(obj + 0x30, 0x30)) {
            float *r = (float *)(obj + 0x30);
            r[0] = g_av_dir[0]; r[1] = g_av_dir[1]; r[2] = 0;
            r[4] = -g_av_dir[1]; r[5] = g_av_dir[0]; r[6] = 0;
            r[8] = 0; r[9] = 0; r[10] = 1;
        }
        if (holder) (*(int *)((BYTE *)holder + 8))--;
    }
}

/* dumpd: an NPC's animation graph variables, to see which of them carry the idle actions (flask, food, holstered
 * weapon). The setters (FUN_1051f460 bool, FUN_1051f480 / FUN_1051f4a0 float / int, FUN_10520a20 wrapped angle) all
 * write *(anim component (key FDF190) + 0x1C) + 0x10 + index * 4; FUN_100ac190 sets indices up to 0x66. The block is
 * logged once (with its 16-byte header), then the variables that changed, twice a second. The pawn's desired-state
 * block (pawn +0x140) of an AI NPC did not change at all in 90 s, and its base beautifier (vtable E0F010) has empty
 * update methods: idle actions do not come through the beautifiers. */
#define DD_N 160
static void dumpd_tick(DWORD now)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    static DWORD last;
    static unsigned prev[DD_N + 4];
    static unsigned long long previd;
    void *hd = NULL;
    BYTE *obj, *ac, *vb;
    unsigned cur[DD_N + 4];
    int k, n = 0;
    char line[900];
    if (!g_dd_id || (int)(now - g_dd_until) > 0 || now - last < 500) return;
    last = now;
    obj = entity_obj(g_dd_id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (obj) {
        /* facing: the entity's matrix rows before the position (+0x60) against the yaw/pitch pairs the host encodes */
        float *mx = (float *)(obj + 0x30);
        int i;
        for (i = 0; i < g_nh_n && g_nh[i].id != g_dd_id; i++) ;
        logf_("dumpd facing: rows (%.2f %.2f %.2f %.2f) (%.2f %.2f %.2f %.2f) (%.2f %.2f %.2f %.2f) pos (%.1f %.1f %.1f)%s", mx[0], mx[1], mx[2], mx[3],
              mx[4], mx[5], mx[6], mx[7], mx[8], mx[9], mx[10], mx[11], mx[12], mx[13], mx[14], i < g_nh_n ? "" : " (not a host NPC)");
        if (i < g_nh_n && g_nh[i].mem)
            logf_("dumpd facing: encoded aim (%.3f %.3f | %.3f %.3f)", np_dq(g_nh[i].mem + 0xAC, 360), np_dq(g_nh[i].mem + 0xC0, 360),
                  np_dq(g_nh[i].mem + 0xD4, 360), np_dq(g_nh[i].mem + 0xE8, 360));
    }
    if (!obj || !(ac = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDF190))) || IsBadReadPtr(ac + 0x1C, 4)) return;
    vb = *(BYTE **)(ac + 0x1C);
    if (!vb || !safe_read(vb, cur, sizeof cur)) return;
    if (previd != g_dd_id) {
        logf_("dumpd %llu: anim component %p, variables at %p, header %08x %08x %08x %08x", g_dd_id, ac, vb, cur[0], cur[1], cur[2], cur[3]);
        for (k = 0; k < DD_N; k += 10) {
            int o = snprintf(line, sizeof line, "dumpd v%02x:", k), j;
            for (j = 0; j < 10 && k + j < DD_N; j++) o += snprintf(line + o, sizeof line - o, " %08x", cur[4 + k + j]);
            logf_("%s", line);
        }
        previd = g_dd_id;
    } else {
        int o = snprintf(line, sizeof line, "dumpd %lu:", now);
        for (k = 0; k < DD_N && o < (int)sizeof line - 24; k++)
            if (cur[4 + k] != prev[4 + k]) { o += snprintf(line + o, sizeof line - o, " v%02x=%08x", k, cur[4 + k]); n++; }
        if (n) logf_("%s", line);
    }
    memcpy(prev, cur, sizeof prev);
}

static void net_tick(void)
{
    DWORD now;
    if (g_net_cfg == 0) {
        if (g_av_id) av_remove();
        if (g_ns != INVALID_SOCKET) { closesocket(g_ns); g_ns = INVALID_SOCKET; logf_("net socket closed (tx=%u rx=%u)", g_net_tx, g_net_rx); }
        /* a joiner (coop_flags npcjoin) pauses its NPCs from the moment the world exists, before the session runs */
        if (g_npc_role == 2 && g_nstates && GetCurrentThreadId() == g_states[0].thread) npc_join_tick(GetTickCount());
        return;
    }
    if (g_nstates == 0 || GetCurrentThreadId() != g_states[0].thread) return;
    now = GetTickCount();
    if (g_net_cfg == 1) {
        WSADATA wd;
        struct sockaddr_in a;
        u_long nb = 1;
        WSAStartup(MAKEWORD(2, 2), &wd);
        memset(&g_peer, 0, sizeof g_peer);
        g_peer.sin_family = AF_INET; g_peer.sin_addr.s_addr = inet_addr(g_net_pip); g_peer.sin_port = htons((unsigned short)g_net_pport);
        if (g_peer.sin_addr.s_addr == INADDR_NONE) { logf_("net: bad peer address %s", g_net_pip); g_net_cfg = 0; return; }
        memset(&a, 0, sizeof a);
        /* a peer on this PC (127.x) keeps the port on loopback; any other peer needs the port on the network */
        a.sin_family = AF_INET; a.sin_port = htons((unsigned short)g_net_lport);
        a.sin_addr.s_addr = (ntohl(g_peer.sin_addr.s_addr) >> 24) == 127 ? htonl(INADDR_LOOPBACK) : htonl(INADDR_ANY);
        g_ns = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (bind(g_ns, (struct sockaddr *)&a, sizeof a) != 0) { logf_("net: bind %u failed (%d)", g_net_lport, WSAGetLastError()); closesocket(g_ns); g_ns = INVALID_SOCKET; g_net_cfg = 0; return; }
        ioctlsocket(g_ns, FIONBIO, &nb);
        g_net_seq = g_net_tx = g_net_rx = g_net_drop = 0; g_net_lastsend = g_net_lastlog = now; g_net_lastrx = 0;
        memset(&g_remote, 0, sizeof g_remote); g_rx_ext.valid = 0;
        g_net_cfg = 2;
        logf_("net: socket up, local %s:%u -> peer %s:%u", a.sin_addr.s_addr == htonl(INADDR_LOOPBACK) ? "127.0.0.1" : "0.0.0.0", g_net_lport, g_net_pip, g_net_pport);
    }
    if (g_walk && g_bodymat && !IsBadWritePtr(g_bodymat, 0x40)) {
        float t = (GetTickCount() - g_walk_t0) / 1000.0f;
        if (t > g_walk_secs) { g_walk = 0; logf_("walk finished"); }
        else {
            float ang = g_walk_speed * t / g_walk_r;
            *(float *)(g_bodymat + 0x30) = g_walk_c[0] + g_walk_r * (cosf(ang) - 1.0f);
            *(float *)(g_bodymat + 0x34) = g_walk_c[1] + g_walk_r * sinf(ang);
            *(float *)(g_bodymat + 0x38) = g_walk_c[2];
        }
    }
    /* make sure we know our own body */
    if (!g_bodymat || IsBadReadPtr(g_body, 4) || *(unsigned *)g_body != (unsigned)(g_base + RVA_BODY_VTABLE)) {
        /* the body search scans all memory (a visible hitch): retry every 3 s at first, then back off to 60 s */
        static unsigned tries;
        if (now - g_net_lastfind > (tries < 5 ? 3000u : 60000u)) {
            char c[64];
            g_net_lastfind = now; tries++;
            snprintf(c, sizeof c, "findbody %llu", g_net_id);
            native_cmd(c);
        }
    }
    /* receive everything pending; only packets from the peer's address count (the port may differ behind NAT) */
    for (;;) {
        NetPktX4 q4;
        NetPktX3 q;
        NetPktX2 p;
        struct sockaddr_in from;
        int fl = sizeof from;
        static NpcPkt rb;
        int r = recvfrom(g_ns, (char *)&rb, sizeof rb, 0, (struct sockaddr *)&from, &fl);
        if (r == SOCKET_ERROR) { if (WSAGetLastError() == WSAEMSGSIZE) { g_net_drop++; continue; } break; }
        if (r == (int)sizeof(NpcArcPkt) && (rb.magic == NREQ_MAGIC || rb.magic == NARC_MAGIC)) {
            if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) { if (rb.magic == NREQ_MAGIC) npc_req_rx((const NpcArcPkt *)&rb); else npc_arc_rx((const NpcArcPkt *)&rb); }
            continue;
        }
        if (r == (int)sizeof(NpcWeapPkt) && rb.magic == NWPN_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) npc_weap_rx((const NpcWeapPkt *)&rb); continue; }
        if (r == (int)sizeof(NpcAnimPkt) && rb.magic == NANM_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) npc_anim_rx((const NpcAnimPkt *)&rb); continue; }
        if (r == (int)sizeof(NpcHitPkt) && rb.magic == NSHT_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) npc_shot_apply((const NpcHitPkt *)&rb); continue; }
        if (r == (int)sizeof(NpcHitPkt) && rb.magic == NHIT_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) npc_hit_apply((const NpcHitPkt *)&rb); continue; }
        if (r == (int)sizeof(HitPkt) && rb.magic == HIT_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) hit_apply((const HitPkt *)&rb); continue; }
        if (r >= 12 && rb.magic == NPC_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) npc_rx(&rb, r); continue; }
        if (r > (int)sizeof q4) { g_net_drop++; continue; }
        memcpy(&q4, &rb, r);
        q = q4.s;
        if (r == (int)sizeof q4) {
            if (q4.world_valid && from.sin_addr.s_addr == g_peer.sin_addr.s_addr) { g_rx_tod = q4.tod; g_rx_day = q4.day; g_rx_world = 1; }
            r = sizeof q;
        }
        p = q.w;
        if (r == (int)sizeof q) {
            g_rx_shot_seq = q.shot_seq; g_rx_shot_mode = q.shot_mode;
            memcpy(g_rx_shot_p, q.shot_p, sizeof g_rx_shot_p); memcpy(g_rx_shot_t, q.shot_t, sizeof g_rx_shot_t);
            r = sizeof p;
        }
        if ((r != (int)sizeof p.x.b && r != (int)sizeof p.x && r != (int)sizeof p) || p.x.b.magic != NET_MAGIC ||
            from.sin_addr.s_addr != g_peer.sin_addr.s_addr) { g_net_drop++; continue; }
        if (g_av_fake) continue;
        g_remote = p.x.b; g_net_rx++; g_net_lastrx = now;
        if (r >= (int)sizeof p.x) g_rx_ext = p.x; else g_rx_ext.valid = 0;
        if (r == (int)sizeof p) { p.weap[sizeof p.weap - 1] = 0; strcpy(g_rx_weap, p.weap); }
    }
    /* test stand-in for a peer: a point walking a circle (avfake), 20 updates per second like the real sender */
    if (g_av_fake && now - g_av_fake_last >= 50) {
        float t = (now - g_av_fake_t0) / 1000.0f, ang;
        g_av_fake_last = now;
        if (t > g_av_fake_secs) { g_av_fake = 0; logf_("avfake finished"); }
        else {
            ang = g_av_fake_speed * t / g_av_fake_r;
            g_remote.magic = NET_MAGIC; g_remote.seq++;
            g_remote.pos[0] = g_av_fake_c[0] + g_av_fake_r * cosf(ang);
            g_remote.pos[1] = g_av_fake_c[1] + g_av_fake_r * sinf(ang);
            g_remote.pos[2] = g_av_fake_c[2];
            g_remote.dir[0] = -sinf(ang); g_remote.dir[1] = cosf(ang);
            g_net_rx++; g_net_lastrx = now;
        }
    }
    av_tick(now);
    world_tick(now);
    npc_host_tick(now);
    hit_tick(now);
    dumpd_tick(now);
    npc_join_tick(now);
    /* send at 20 Hz */
    if ((g_bodymat || g_net_id) && now - g_net_lastsend >= 50) {
        NetPktX4 q4;
        NetPktX3 q;
        NetPktX2 p;
        void *holder = NULL;
        BYTE *obj = entity_obj(g_net_id, &holder);
        g_net_lastsend = now;
        memset(&p, 0, sizeof p);
        p.x.b.magic = NET_MAGIC; p.x.b.seq = ++g_net_seq;
        if (g_bodymat) memcpy(p.x.b.pos, g_bodymat + 0x30, sizeof p.x.b.pos);
        else if (obj) memcpy(p.x.b.pos, obj + 0x60, sizeof p.x.b.pos);
        p.x.b.dir[0] = obj ? *(float *)(obj + 0x30) : 0; p.x.b.dir[1] = obj ? *(float *)(obj + 0x34) : 0;
        if (obj) tx_encode(obj, &p.x, now);
        strcpy(p.weap, g_tx_weap);
        {
            /* a shot with no bullet event since the last packet (e.g. into the ground close by - the game sends none):
             * aim the point along our view instead, 25 m from the muzzle; aim angles (radians) are pitch and yaw from our
             * own ThirdParty memento, forward = (-sin yaw, cos yaw) */
            static unsigned last_shots, last_bullets;
            if (g_lx_obj && g_lx_shots != last_shots && g_shot_seq == last_bullets && g_tx_mem) {
                float pitch = np_dq(g_tx_mem + 0xAC, 360), yaw = np_dq(g_tx_mem + 0xC0, 360), mz[3], d[3];
                int i;
                if (g_shot_t[0] == 0 && g_shot_t[1] == 0 && g_shot_t[2] == 0) g_shot_t[2] = 1.67f;
                for (i = 0; i < 3; i++) mz[i] = p.x.b.pos[i] + g_shot_t[i];
                d[0] = -sinf(yaw) * cosf(pitch); d[1] = cosf(yaw) * cosf(pitch); d[2] = sinf(pitch);
                for (i = 0; i < 3; i++) g_shot_p[i] = mz[i] + 25.0f * d[i];
                if (++g_lx_aimed <= 30) logf_("tx: shot %u without a bullet: point from aim (pitch %.2f yaw %.2f) -> (%.2f %.2f %.2f)", g_lx_shots,
                                              pitch, yaw, g_shot_p[0], g_shot_p[1], g_shot_p[2]);
            }
            last_shots = g_lx_shots; last_bullets = g_shot_seq;
        }
        q.w = p; q.shot_seq = g_lx_obj ? g_lx_shots : g_shot_seq; q.shot_mode = g_shot_mode;
        memcpy(q.shot_p, g_shot_p, sizeof q.shot_p); memcpy(q.shot_t, g_shot_t, sizeof q.shot_t);
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        memset(&q4, 0, sizeof q4); q4.s = q;
        if (g_ws_role == 1) { BYTE *env = env_obj(); if (env) { q4.tod = *(float *)(env + 0x260); q4.day = *(int *)(env + 0x4EC); q4.world_valid = 1; } }
        sendto(g_ns, (char *)&q4, sizeof q4, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
        g_net_tx++;
    }
    if (now - g_net_lastlog >= 1000) {
        g_net_lastlog = now;
        logf_("net: tx=%u rx=%u local=(%.2f %.2f %.2f) remote=(%.2f %.2f %.2f) seq=%u age=%lums drop=%u", g_net_tx, g_net_rx,
              g_bodymat ? *(float *)(g_bodymat + 0x30) : 0, g_bodymat ? *(float *)(g_bodymat + 0x34) : 0, g_bodymat ? *(float *)(g_bodymat + 0x38) : 0,
              g_remote.pos[0], g_remote.pos[1], g_remote.pos[2], g_remote.seq, g_net_lastrx ? (unsigned long)(now - g_net_lastrx) : 0UL, g_net_drop);
    }
}

/* coop_auto.txt next to the probe: native commands (separated by ';' or lines) run once, 3 s after the game opened a
 * save and as soon as GetLocalPlayerId gives an id; "$ME" is replaced by that id. A session then starts as soon as
 * each copy is in its world (worldsync, avatar, netstart), with nobody typing commands. */
static void auto_start(void)
{
    static int done;
    char path[MAX_PATH], buf[1024], out[32], line[1100], *s, *e;
    FILE *f;
    size_t n;
    unsigned long long me;
    if (done || !g_sav_tick || GetTickCount() - g_sav_tick < 3000) return;
    strcpy(path, g_natpath); strcpy(strrchr(path, '\\') + 1, "coop_auto.txt");
    if (!(f = fopen(path, "rb"))) { done = 1; return; }
    n = fread(buf, 1, sizeof buf - 1, f); buf[n] = 0; fclose(f);
    lua_eval("__out = tostring(GetLocalPlayerId())", out, sizeof out);
    me = strtoull(out, NULL, 10);
    if (!me || me == ~0ULL) return;   /* not in the world yet: try again next poll */
    {
        /* the id exists early in the load; wait until the player's entity and pawn exist, then 12 s more */
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        static DWORD ready;
        void *hd = NULL;
        BYTE *obj = entity_obj(me, &hd);
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        /* the entity and pawn exist while the load screen is still up, at position (0, 0, 0); netstart then crashed
         * in the encoder: wait for a real position */
        if (!obj || !((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)) ||
            (*(float *)(obj + 0x60) == 0.0f && *(float *)(obj + 0x64) == 0.0f)) { ready = 0; return; }
        if (!ready) { ready = GetTickCount() | 1; return; }
        if (GetTickCount() - ready < 12000) return;   /* 3 s still crashed in the encoder (Dunia+0x493bb0) */
    }
    done = 1;
    logf_("autostart: player %llu, running %s", me, path);
    for (s = buf; *s; s = e) {
        char *d = line, *q;
        for (e = s; *e && *e != ';' && *e != '\n' && *e != '\r'; e++) ;
        for (q = s; q < e && d < line + sizeof line - 24; q++) {
            if (q + 3 <= e && !strncmp(q, "$ME", 3)) { d += snprintf(d, line + sizeof line - d, "%llu", me); q += 2; }
            else *d++ = *q;
        }
        *d = 0;
        while (*e == ';' || *e == '\n' || *e == '\r') e++;
        if (line[0]) { logf_("autostart: %s", line); native_cmd(line); }
    }
}
static void pump_main(void)
{
    FILE *f;
    if (g_nstates == 0 || g_busy || GetCurrentThreadId() != g_states[0].thread) return;
    if (GetTickCount() - g_lastpoll < 250) return;
    g_lastpoll = GetTickCount();
    g_busy = 1; auto_start(); g_busy = 0;
    f = fopen(g_natpath, "rb");
    if (f) { fclose(f); g_busy = 1; run_native(); g_busy = 0; return; }
    f = fopen(g_cmdpath, "rb");
    if (!f) return;
    fclose(f);
    g_busy = 1;
    run_cmd(g_states[0].L);
    g_busy = 0;
}
static BOOL WINAPI h_PeekMessageA(LPMSG m, HWND h, UINT a, UINT b, UINT c) { hold_tick(); net_tick(); watchd_tick(); fire_latch_tick(); pump_main(); return o_PeekMessageA(m, h, a, b, c); }
static BOOL WINAPI h_PeekMessageW(LPMSG m, HWND h, UINT a, UINT b, UINT c) { hold_tick(); net_tick(); watchd_tick(); fire_latch_tick(); pump_main(); return o_PeekMessageW(m, h, a, b, c); }

static int __cdecl h_gettop(void *L)
{
    unsigned long tid = GetCurrentThreadId();
    int i, best = -1;
    for (i = 0; i < g_nstates; i++) if (g_states[i].L == L) break;
    if (i == g_nstates && g_nstates < MAXL) {
        g_states[i].L = L; g_states[i].thread = tid; g_states[i].hits = 0; g_nstates++;
        logf_("new lua_State %p first seen on thread %lu", L, tid);
    }
    if (i < MAXL) g_states[i].hits++;
    return o_gettop(L);
}

static void install_lua(HMODULE m)
{
    char *s;
    g_base = (BYTE *)m;
    lua_settop_ = (void *)(g_base + RVA_SETTOP);
    lua_dobuffer_ = (void *)(g_base + RVA_DOBUFFER);
    lua_checklstr_ = (void *)(g_base + RVA_CHECKLSTR);
    lua_getglobal_ = (void *)(g_base + RVA_GETGLOBAL);
    GetModuleFileNameA(g_self, g_cmdpath, MAX_PATH);
    s = strrchr(g_cmdpath, '\\');
    strcpy(s + 1, "coop_cmd.lua");
    strcpy(g_natpath, g_cmdpath);
    strcpy(strrchr(g_natpath, '\\') + 1, "coop_native.txt");
    o_gettop = (void *)make_detour(g_base + RVA_GETTOP, 7, h_gettop, 1);
    make_detour(g_base + RVA_ALERT, 6, h_alert, 0);
    logf_("lua hooks installed (gettop, _ALERT); command file %s", g_cmdpath);
}

static DWORD WINAPI watcher(LPVOID p)
{
    int tries;
    (void)p;
    for (tries = 0; tries < 1200; tries++) {
        HMODULE m = GetModuleHandleA("Dunia.dll");
        if (m) {
            logf_("Dunia.dll at %p, patching IAT", (void *)m);
            logf_("patched %d IAT entries", patch_iat(m));
            install_lua(m);
            return 0;
        }
        Sleep(50);
    }
    logf_("Dunia.dll never appeared");
    return 0;
}

/* real dinput8 */
static FARPROC g_real;
__declspec(naked) HRESULT WINAPI DirectInput8Create(HINSTANCE a, DWORD b, REFIID c, LPVOID *d, LPUNKNOWN e)
{
    __asm__ __volatile__("jmp *%0" : : "m"(g_real));
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID res)
{
    (void)res;
    if (reason == DLL_PROCESS_ATTACH) {
        char path[MAX_PATH], sys[MAX_PATH];
        HMODULE r;
        g_self = inst;
        SetUnhandledExceptionFilter(crash_filter);
        AddVectoredExceptionHandler(1, veh_filter);
        DisableThreadLibraryCalls(inst);
        InitializeCriticalSection(&g_cs);
        GetModuleFileNameA(inst, path, MAX_PATH);
        strcpy(strrchr(path, '\\') + 1, "coop_probe.log");
        g_log = fopen(path, "a");
        logf_("probe loaded, cmdline: %s", GetCommandLineA());
        GetSystemDirectoryA(sys, MAX_PATH);
        strcat(sys, "\\dinput8.dll");
        r = LoadLibraryA(sys);
        g_real = r ? GetProcAddress(r, "DirectInput8Create") : NULL;
        CreateThread(NULL, 0, watcher, NULL, 0, NULL);
    }
    return TRUE;
}
