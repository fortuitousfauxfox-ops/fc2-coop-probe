/*
 * fc2-coop-probe: a dinput8.dll proxy for TEST COPIES of Far Cry 2 (Steam 1.03, Dunia engine).
 * Logs network, file and exit calls of Dunia.dll, runs Lua 4.0 and native commands inside the
 * game, finds the player's Havok body and exchanges its position between two copies over its own
 * UDP socket (research prototype; see README.md). MIT licence, see LICENSE.
 * Addresses (RVAs) below are for Dunia.dll SHA-256 6353936a...2765 only.
 */
#include <stddef.h>
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <math.h>
#include <tlhelp32.h>

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
/* set once the game asks to quit: the per-frame work (sync, avatar, NPC puppets) stops, as the world is torn down
 * while message pumping goes on (a read of freed memory through D+23ba22 on PC2 right after the quit) */
static volatile int g_quitting;
static void bye_send(void);
#define AV_SILENT_MS 15000         /* the avatar leaves after this long without packets (see BYE1); 5 s re-spawned it on
                                    * two PCs, where the host's packets paused for ~5 s every ~10 s */
static volatile int g_peer_bye;    /* the peer said it is leaving, at g_bye_at */
static DWORD g_bye_at;
static char g_peer_nick[64];      /* the other player's Steam name (NAM1) */
static int g_peer_named;
static VOID WINAPI h_PostQuitMessage(int c)
{
    g_quitting = 1;
    bye_send();
    logf_("PostQuitMessage(%d) caller=%p: per-frame work stopped", c, __builtin_return_address(0));
    o_PostQuitMessage(c);
}
/* ---- on-screen notices ("Игрок <Steam name> подключается") ----
 * Shown the way the game shows "QUICK_SAVING" in the top left (FUN_1071b590 area): the message widget is
 * FUN_104ce530(manager [0x11644d74], 1); its vf+0x4C(text, duration [0x10F48190]) shows a UTF-16 text, which the game
 * gets from its string table (FUN_104d1e40(&category, &key, [0x10F9B554]), RET 0xC, -> FUN_104d1d90 returns the wide
 * string). Our own text goes in instead. Works in the DX9 and DX10 renderers alike (a Direct3D 9 overlay never saw a frame: the game ran DX10).
 * Called on the main thread (net tick); the text buffer stays alive until the next notice. */
static BYTE *g_base;
static wchar_t g_ov_text[2][160];
static volatile LONG g_ov_pending;
static int g_ov_slot;
static void notice_w(const wchar_t *text)
{
    lstrcpynW(g_ov_text[g_ov_slot ^ 1], text, 160);
    g_ov_slot ^= 1;
    InterlockedExchange(&g_ov_pending, 1);
}
/* "Игрок <name> <what>" with a UTF-8 name */
static void notice_player(const char *name_utf8, const wchar_t *what)
{
    wchar_t n[64], t[160];
    if (!MultiByteToWideChar(CP_UTF8, 0, name_utf8, -1, n, 64)) lstrcpyW(n, L"?");
    n[63] = 0;
    _snwprintf(t, 159, L"Игрок %ls %ls", n, what);
    t[159] = 0;
    notice_w(t);
}
/* Back to the main menu: the console command quitToMainMenu (registered in FUN_1065a9c0, handler FUN_10658a20) is
 * just vf+0x20 of the game object at [0x10FDE158]. Main thread only. */
static void quit_to_menu(const char *why)
{
    void *g = g_base ? *(void **)(g_base + 0xFDE158) : NULL;
    logf_("menu: leaving for the main menu (%s)%s", why, g ? "" : " - no game object");
    if (g) ((void (__attribute__((thiscall)) *)(void *))(*(void ***)g)[0x20 / 4])(g);
}
static void notice_tick(void)
{
    typedef void *(__attribute__((thiscall)) *getw_t)(void *mgr, int which);
    typedef void (__attribute__((thiscall)) *show_t)(void *w, const wchar_t *text, float seconds);
    void *mgr, *w;
    if (!g_ov_pending || !g_base) return;
    mgr = *(void **)(g_base + 0x1644D74);
    if (!mgr) return;   /* not in the world yet: keep it pending */
    InterlockedExchange(&g_ov_pending, 0);
    w = ((getw_t)(g_base + 0x4CE530))(mgr, 1);
    if (!w) { logf_("notice: no message widget"); return; }
    ((show_t)(*(void ***)w)[0x4C / 4])(w, g_ov_text[g_ov_slot], *(float *)(g_base + 0xF48190));
    {
        char u8[480];
        WideCharToMultiByte(CP_UTF8, 0, g_ov_text[g_ov_slot], -1, u8, sizeof u8, NULL, NULL);
        logf_("notice shown: %s", u8);
    }
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
static wchar_t g_sav_last[MAX_PATH];   /* the save the game read last, and how many it has read: a load */
static volatile LONG g_sav_loads;
static BYTE *g_base;
static int safe_read(const void *addr, void *buf, size_t n);
static HANDLE WINAPI h_CreateFileW(LPCWSTR n, DWORD a, DWORD sh, LPSECURITY_ATTRIBUTES sa, DWORD cd, DWORD fl, HANDLE t)
{
    HANDLE h = o_CreateFileW(n, a, sh, sa, cd, fl, t); DWORD le = GetLastError(); /* our logging must not change the caller's error code (WSAEWOULDBLOCK) */
    if (n && (wcsstr(n, L"av") || wcsstr(n, L"Saved") || wcsstr(n, L"Documents") || wcsstr(n, L"Profile"))) logf_("CreateFileW %ls acc=%lx disp=%lu -> %s", n, a, cd, h == INVALID_HANDLE_VALUE ? "FAIL" : "ok");
    if (n && !g_sav_tick && wcsstr(n, L".sav") && h != INVALID_HANDLE_VALUE) g_sav_tick = GetTickCount() | 1;
    if (n && wcsstr(n, L".sav") && h != INVALID_HANDLE_VALUE && !(a & (GENERIC_WRITE | FILE_WRITE_DATA)) && wcslen(n) < MAX_PATH) {
        wcscpy(g_sav_last, n);
        InterlockedIncrement(&g_sav_loads);
    }
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
static int g_noautodraw;          /* coop_flags.txt "noautodraw": leave our player's inventory bAutoDraw as loaded */
static int g_vehsync;              /* vehsync 0|1 (defined with the vehicle sync) */
static int g_doorsync;              /* doorsync 0|1 (defined with the doors) */
static int g_nresync;               /* nresync 0|1 (defined with the NPC reactions) */
static int g_mslog;                 /* mslog 0|1 (defined with the anim vars) */
static int g_nmssync;               /* nmssync 0|1 (defined with the NPC move states) */
static unsigned g_nms_tx, g_nms_rx, g_nms_set;
static volatile LONG g_ms_skips;
static int g_nmslayers;
static int g_npcface;
static void wbp_start(int n);
static int g_npcflag;
static void wbp_tick(void);
static int g_npcsigdrop = 1;         /* npcsigdrop 0|1 */
static unsigned g_npcsigdropped;
static void *g_np_drv[64];
static int g_npcz = 1;              /* npcz 0|1: puppet height pulled to the host's */
static DWORD g_npcz_log;
static unsigned g_npcz_snaps;
static DWORD g_npcz_t[64];
static int g_mountprof;
static unsigned g_ndp_tx, g_ndp_rx, g_ndp_add, g_ndp_del;
static int g_nsgsync;               /* nsgsync 0|1 (defined with the NPC behaviour signals) */
static int g_plyfind;                /* plyfind 1: the player lookup answers a fake player for the avatar */
static int g_plylog;                 /* plylog 1: plycallers every 2 s */
static void ply_add(void);
static void ply_del(const char *why);
static void ply_install(void);
static void ply_callers(void);
static void ply_show(void);
static int g_siglog, g_sigsync = 1; /* siglog 0|1|2|3, sigsync 0 off | 1 allow list | 2 all but denied (RE) */
static unsigned g_sig_deny[32], g_sig_allow[32] = {
    0x328D8D10u, 0x9D3BCA58u,      /* throw_grenade, throw_player: the avatar throws (its weapon sync gives empty hands) */
    0x33111508u, 0xC4A5E460u, 0x9F347422u,  /* open_door, open_door_to / out_of_weaponsafe: the door moves only with its
                                             * user's animation, so the avatar plays it (DOR1 gives it the door first) */
};
static int g_sig_ndeny, g_sig_nallow = 5;
static void door_target_send(void);
static int sig_listed(const unsigned *l, int n, unsigned h);
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
        if (strstr(flags, "noautodraw")) g_noautodraw = 1;
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
static unsigned g_findtries;   /* findbody tries since the body was last lost (3 s apart for 5 tries, then 60 s) */
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
static int player_ready(unsigned long long me);
static void npc_join_tick(DWORD now);
static int g_hitsync = 1, g_st_verbose, g_npcev_left;
static int g_npcanim = 2;           /* npcanim 0|1|2: puppets take the host NPCs' animation graph inputs (2: the pose too) */
static int g_join_tp;              /* the joiner was put next to the host once */
static int g_npcrespawn;            /* npcrespawn 1: replace puppets that run an action of their own (off: replacements are
                                     * spawned from the generic archetype and look different, and actions still differed) */
static void npc_anim_apply(BYTE *mb);
static int g_reinfblock = 1;         /* reinfblock 0|1: the joiner's world spawns no reinforcements of its own */
static int g_npcdiff;                /* npcdiff 0|1: log each live puppet's error against the host once a second */
static DWORD g_np_react[64];     /* joiner: the puppet plays its own reaction until then (NRE1): host anim vars wait */
static unsigned long long g_dd_id;   /* dumpd: NPC whose desired-state block is logged */
static DWORD g_dd_until;  /* hit sync on by default; stimlog turns on event logging */
static void av_remove(void);
static void av_forget(void);
static DWORD g_av_gone_at;   /* when the avatar entity vanished (the world was rebuilt: a load) */
static int g_rld_force;
static int g_mk_sign = 1;     /* mapsign -1 flips the turn of the avatar arrow on the map if it turns the wrong way */
static float g_mk_dbg[2];     /* mapdbg <dx> <dy>: extra offset of the avatar arrow in map units (test) */
/* maparch <archetype>: overrides the other player's arrow (empty: by role). coop.PeerPosition is the player arrow in
 * yellow, added to the test copies' patch archive (tools/make_peer_arrow.py); without it all arrows stay green */
static char g_mk_arch[96];
static float g_mk_yaw;        /* mapyaw <degrees>: turn added for a model whose arrow points elsewhere at yaw 0 */
static int g_mk_respawn;
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

/* ---- resources an entity has streamed in for itself: CDynamicDeploadComponent (component key FDFC14) +0x10 is a
 * CResourceContainer (vtable E38B20): children at +0x28, count +0x2C, loaded children +0x34; a resource has its
 * refcount at +4, its id (CRC32 of the lowercase path) at +0x1C, vf+4 its type {name, ...}, vf+0x18 "loaded",
 * vf+0x48 find(&id), vf+0x60 add, vf+0x64 remove. The AI adds what an action needs (FUN_10543f40) and removes it
 * after (FUN_10543f70): the smart terrain executor (9AB190) adds the STP's CAIWorkspaceResource. ---- */
static const char *res_type(BYTE *r)
{
    typedef const char ***(__attribute__((thiscall)) *tf_t)(void *);
    const char ***t;
    if (!r || IsBadReadPtr(r, 0x30) || IsBadReadPtr(*(void **)r, 0x1C)) return "?";
    t = ((tf_t)(*(void ***)r)[1])(r);
    if (!t || IsBadReadPtr(t, 8) || IsBadReadPtr(*t, 4)) return "?";
    return (const char *)*t;
}
static BYTE *dep_container(BYTE *obj)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    BYTE *c = obj ? ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDFC14)) : NULL, *k;
    if (!c || IsBadReadPtr(c + 0x10, 4) || !(k = *(BYTE **)(c + 0x10)) || IsBadReadPtr(k, 0x38)) return NULL;
    return k;
}
static void dep_log(unsigned long long id, BYTE *obj)
{
    typedef char (__attribute__((thiscall)) *lf_t)(void *);
    BYTE *k = dep_container(obj), **ch, **cc;
    unsigned i, j, n, m;
    if (!k) { logf_("deplist %llu: no depload component", id); return; }
    n = *(unsigned *)(k + 0x2C); ch = *(BYTE ***)(k + 0x28);
    logf_("deplist %llu: container %p (%s) %u children, %u loaded", id, k, res_type(k), n, *(unsigned *)(k + 0x34));
    if (n > 64 || IsBadReadPtr(ch, n * 4)) return;
    for (i = 0; i < n; i++) {
        BYTE *r = ch[i];
        if (!r || IsBadReadPtr(r, 0x38)) { logf_("  [%u] %p unreadable", i, r); continue; }
        logf_("  [%u] %p %s id %08x refs %d state %d loaded %d, %u children", i, r, res_type(r), *(unsigned *)(r + 0x1C),
              *(int *)(r + 4), *(short *)(r + 8), (int)((lf_t)(*(void ***)r)[6])(r), *(unsigned *)(r + 0x2C));
        m = *(unsigned *)(r + 0x2C); cc = *(BYTE ***)(r + 0x28);
        if (m > 64 || IsBadReadPtr(cc, m * 4)) continue;
        for (j = 0; j < m; j++)
            if (cc[j] && !IsBadReadPtr(cc[j], 0x20))
                logf_("      %s id %08x", res_type(cc[j]), *(unsigned *)(cc[j] + 0x1C));
    }
}
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
/* guarded calls into the game's ThirdParty encoder (enc_safe): the encoder dereferences pawn state that is null while
 * a pawn dies, is rescued or loads (Dunia+0x493bb0, read of +0x2C); an access violation inside it jumps back to the
 * guarded call, which skips that packet. The SEH chain (fs:[0]) is put back to its value at the call. */
static void *g_enc_jb[5];
static volatile int g_enc_guard;
static DWORD g_enc_seh, g_enc_tid;
static LONG WINAPI veh_filter(EXCEPTION_POINTERS *ep)
{
    static int n;
    if (g_enc_guard && ep->ExceptionRecord->ExceptionCode == 0xC0000005 && GetCurrentThreadId() == g_enc_tid) {
        DWORD seh = g_enc_seh;
        g_enc_guard = 0;
        __asm__ volatile("movl %0, %%fs:0" : : "r"(seh) : "memory");
        __builtin_longjmp(g_enc_jb, 1);
    }
    if (ep->ExceptionRecord->ExceptionCode == 0xC0000005 && n < 30) {
        char mod[96];
        caller_str(ep->ExceptionRecord->ExceptionAddress, mod, sizeof mod);
        /* IsBadReadPtr's own caught faults (scans) would use up the 30 entries before a real crash */
        if (!_strnicmp(mod, "KERNEL32", 8) || !_strnicmp(mod, "KERNELBASE", 10)) return EXCEPTION_CONTINUE_SEARCH;
        n++;
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
static void *g_last_gadget;          /* gadget component pawn_give_weapon added last */
static unsigned long long g_last_wid;  /* weapon entity pawn_give_weapon added last (0 = a gadget or nothing) */
/* weapons the avatar already carries, by archetype: switching back to one only selects it (as the player's own
 * switch does: holster / draw animations). Spawning a new entity on every switch swapped the weapon in the hands
 * at once, sometimes leaving them empty. */
static struct { char arch[96]; unsigned long long wid; } g_av_wc[8];
static void *g_av_mapcomp;           /* the avatar's map gadget component while it holds the map */
static unsigned long long g_av_gps;  /* the avatar's own GPS entity while it holds the map (0 none) */
/* The GPS in the other hand while the map is out. The map's UseStrategy (gadget comp +0x10, vtable E99EC0) owns a
 * compass (gadgets.Equipped.CompassSingle, handle at +0x108) that its open method (vf slot 15, FUN_106edcc0) puts in
 * the hand - only for a player who uses the map. That compass stays invisible on the avatar even when taken into its
 * hand and shown, while a freshly spawned CompassSingle is drawn once the Lua SetVisibility shows it. So the avatar
 * gets its own: spawned, bound to the pawn's hand animation by its gadget comp FUN_10156b40(pawn comp) (what
 * FUN_106edcc0 does), shown; removed when the map goes away (in_hand 0, which also forgets the map). */
static void av_compass(int in_hand)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void (__attribute__((thiscall)) *take_t)(void *gadget, void *pawn);
    char code[200], out[64];
    void *hd = NULL, *gh = NULL, *pawn, *gc;
    BYTE *obj, *gobj;
    if (!in_hand) {
        g_av_mapcomp = NULL;
        if (g_av_gps && !g_quitting) { snprintf(code, sizeof code, "RemoveEntity('%llu') __out = 'ok'", g_av_gps); lua_eval(code, out, sizeof out); logf_("avgps: GPS %llu removed", g_av_gps); }
        g_av_gps = 0;
        return;
    }
    obj = g_av_id ? entity_obj(g_av_id, &hd) : NULL;
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    pawn = obj ? ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)) : NULL;
    if (!pawn) return;
    if (!g_av_gps) {
        snprintf(code, sizeof code, "__out = tostring(SpawnEntityFromArchetype('gadgets.Equipped.CompassSingle', %.3f, %.3f, %.3f, 0, 0, 0))",
                 *(float *)(obj + 0x60), *(float *)(obj + 0x64), *(float *)(obj + 0x68) + 1.2f);
        lua_eval(code, out, sizeof out);
        g_av_gps = strtoull(out, NULL, 10);
        if (g_av_gps == 0xFFFFFFFFFFFFFFFFull) g_av_gps = 0;
    }
    gobj = g_av_gps ? entity_obj(g_av_gps, &gh) : NULL;
    if (gh) (*(int *)((BYTE *)gh + 8))--;
    gc = gobj ? ((gcomp_t)(g_base + 0x4E2CC0))(gobj, (void *)(g_base + 0xFDFFB4)) : NULL;
    if (!gc) { logf_("avgps: GPS spawn failed (%s, entity %p)", out, gobj); return; }
    ((take_t)(g_base + 0x156B40))(gc, pawn);
    snprintf(code, sizeof code, "SetVisibility('%llu', true) __out = 'ok'", g_av_gps);
    lua_eval(code, out, sizeof out);
    logf_("avgps: GPS %llu in the avatar's hand, shown", g_av_gps);
}
/* holster what a pawn holds (FUN_1012b340 on its inventory, what the Lua HolsterWeapon does for the player); a gadget
 * in the hands (map / GPS: inventory impl +0x74 = 2) is put away with FUN_1012b350 */
static void pawn_holster(BYTE *obj)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void *(__fastcall *inv_t)(void *pawn);
    typedef int (__attribute__((thiscall)) *iget_t)(void *inv);
    typedef void (__attribute__((thiscall)) *inv0_t)(void *inv);
    void *pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)), *inv;
    BYTE *impl;
    if (!pawn || !(inv = ((inv_t)(g_base + 0x7E140))(pawn))) return;
    impl = *(BYTE **)((BYTE *)inv + 4);
    if (impl && *(int *)(impl + 0x74) == 2) ((inv0_t)(g_base + 0x12B350))(inv);
    if (((iget_t)(g_base + 0x125F40))(inv) == 1) ((inv0_t)(g_base + 0x12B340))(inv);
}
/* select a weapon the avatar already carries: 0 when it has none of that archetype in its slot any more */
static int av_select_cached(const char *arch)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void *(__fastcall *inv_t)(void *pawn);
    typedef unsigned (__attribute__((thiscall)) *slot_t)(void *weapon);
    typedef void *(__attribute__((thiscall)) *inslot_t)(void *inv, unsigned slot);
    typedef void (__attribute__((thiscall)) *sel_t)(void *inv, unsigned *cat);
    void *hd = NULL, *wh = NULL, *pawn, *wc, *inv;
    BYTE *obj, *wobj;
    unsigned slot, cat;
    int i;
    for (i = 0; i < 8; i++) if (g_av_wc[i].wid && !strcmp(g_av_wc[i].arch, arch)) break;
    if (i == 8 || !g_av_id) return 0;
    obj = entity_obj(g_av_id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    wobj = entity_obj(g_av_wc[i].wid, &wh);
    if (wh) (*(int *)((BYTE *)wh + 8))--;
    if (!obj || !wobj || !(pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C))) ||
        !(wc = ((gcomp_t)(g_base + 0x4E2CC0))(wobj, (void *)(g_base + 0xFE01F8))) || !(inv = ((inv_t)(g_base + 0x7E140))(pawn))) {
        g_av_wc[i].wid = 0; return 0;
    }
    slot = ((slot_t)(*(void ***)wc)[0x8C / 4])(wc);
    if (((inslot_t)(g_base + 0x129DE0))(inv, slot) != wc || IsBadReadPtr((void *)slot, 4)) { g_av_wc[i].wid = 0; return 0; }
    cat = *(unsigned *)slot;
    ((sel_t)(g_base + 0x12CE80))(inv, &cat);
    logf_("avweapon: %s already carried (entity %llu), selected", arch, g_av_wc[i].wid);
    return 1;
}
static void av_cache_weapon(const char *arch, unsigned long long wid)
{
    int i, j = -1;
    for (i = 0; i < 8; i++) {
        if (g_av_wc[i].wid && !strcmp(g_av_wc[i].arch, arch)) { j = i; break; }
        if (!g_av_wc[i].wid && j < 0) j = i;
    }
    if (j < 0) j = 0;
    snprintf(g_av_wc[j].arch, sizeof g_av_wc[j].arch, "%s", arch); g_av_wc[j].wid = wid;
}
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
    g_last_wid = wc ? wid : 0;
    if (pawn && !wc && (wc = ((gcomp_t)(g_base + 0x4E2CC0))(wobj, (void *)(g_base + 0xFDFFB4)))) {
        /* a gadget (map / GPS), added like the Lua AddGadget handler (LAB_109f9460) does: slot = vf+0x8C, the old
         * gadget of that slot FUN_10129df0 -> FUN_1012e3f0, FUN_10149ec0(3), FUN_10128a00; then taken into the hands
         * by category (FUN_1012e410 -> FUN_1012d730: holsters the weapon, impl +0x24 / +0x78 = 2, draws the gadget) */
        typedef void *(__attribute__((thiscall)) *gslot_t)(void *inv, void *slot);
        typedef void (__attribute__((thiscall)) *inv1_t)(void *inv, void *p);
        typedef int (__attribute__((thiscall)) *cnt_t)(void *gadget, int n);
        typedef void (__attribute__((thiscall)) *sel_t)(void *inv, unsigned *cat);
        unsigned cat;
        slot = ((slot_t)(*(void ***)wc)[0x8C / 4])(wc);
        inv = ((inv_t)(g_base + 0x7E140))(pawn);
        if (!inv) { logf_("%s: pawn has no inventory", who); return 0; }
        old = ((gslot_t)(g_base + 0x129DF0))(inv, (void *)slot);
        if (old) { void *oh = *(void **)((BYTE *)old + 8); ((inv1_t)(g_base + 0x12E3F0))(inv, old); if (oh) { snprintf(code, sizeof code, "RemoveEntity('%llu') __out = 'ok'", *(unsigned long long *)oh); lua_eval(code, out, sizeof out); } }
        ((cnt_t)(g_base + 0x149EC0))(wc, 3);
        ((inv1_t)(g_base + 0x128A00))(inv, wc);
        cat = IsBadReadPtr((void *)slot, 4) ? 0 : *(unsigned *)slot;
        if (cat) ((sel_t)(g_base + 0x12E410))(inv, &cat);
        g_last_gadget = wc;
        logf_("%s: gadget %s entity %llu comp %p category %08x -> inventory %p (old %p), hands %d", who, arch, wid, wc, cat, inv, old,
              *(int *)(*(BYTE **)((BYTE *)inv + 4) + 0x74));
        return 1;
    }
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

/* A u64 entry of a pawn's blackboard (pawn component vf+0x7C, read with FUN_1008e610): CurrentVehicleID 0xFD1BA782 =
 * the vehicle the pawn sits in, 0x1BAA9B71 = the vehicle it asked for. ~0 when unset or no pawn. */
static unsigned long long pawn_bb_u64(unsigned long long id, unsigned key)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void *(__attribute__((thiscall)) *bb_t)(void *pawn);
    typedef void (__attribute__((thiscall)) *bbget_t)(void *bb, const unsigned *key, unsigned long long *out);
    unsigned long long v = ~0ULL;
    void *hd = NULL, *pawn, *bb;
    BYTE *obj = entity_obj(id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!obj || !(pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C))) || IsBadReadPtr(*(void **)pawn, 0x80)) return v;
    if (!(bb = ((bb_t)(*(void ***)pawn)[0x7C / 4])(pawn))) return v;
    ((bbget_t)(g_base + 0x8E610))(bb, &key, &v);
    return v;
}
/* set an existing u64 blackboard entry (FUN_1008e310); 0 when there is no pawn or blackboard */
static int pawn_bb_set_u64(unsigned long long id, unsigned key, unsigned long long v)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void *(__attribute__((thiscall)) *bb_t)(void *pawn);
    typedef void (__attribute__((thiscall)) *bbset_t)(void *bb, const unsigned *key, const unsigned long long *val);
    void *hd = NULL, *pawn, *bb;
    BYTE *obj = entity_obj(id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!obj || !(pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C))) || IsBadReadPtr(*(void **)pawn, 0x80)) return 0;
    if (!(bb = ((bb_t)(*(void ***)pawn)[0x7C / 4])(pawn))) return 0;
    ((bbset_t)(g_base + 0x8E310))(bb, &key, &v);
    return 1;
}

/* ---- vehicles: CVehicle component FDF990, its impl at +0x10 holds the seats (impl +0xC, stride 0x50, count +0x10;
 * seat +0x10 type 1 driver / 2 gunner / 3 passenger, +0x28 user id, +0x30 state 2 = taken). Engine calls, all
 * thiscall on the impl: E1810(pawn comp) = accept a user (picks a free seat, driver first), D8050(seat, pawn comp, 0,
 * -1) = put the pawn in that seat (pawn side 151D50: vehicle pose), E4E70(pawn comp, 0) = get out. ---- */
#define VEH_SEAT_STRIDE 0x50
/* send a state event (hash) to a pawn's state machines: pawn comp vf+0x78 returns its StateDriver, FUN_1029da10 passes
 * the hash to each machine. Seat events: 0x0350C66F in vehicle [10F932AC], 0xF1ACDD97 "exitvehicle" [10F932B0]. */
static void pawn_state_event(BYTE *pawn, unsigned hash)
{
    void *drv = ((void *(__attribute__((thiscall)) *)(void *))(*(void ***)pawn)[0x78 / 4])(pawn);
    if (drv) ((void (__attribute__((thiscall)) *)(void *, unsigned))(g_base + 0x29DA10))(drv, hash);
}
static BYTE *veh_impl(unsigned long long id)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    void *hd = NULL;
    BYTE *obj = entity_obj(id, &hd), *vc, *im;
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!obj || !(vc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDF990))) || IsBadReadPtr(vc, 0x14)) return NULL;
    im = *(BYTE **)(vc + 0x10);
    return im && !IsBadReadPtr(im, 0x14) && *(unsigned *)(im + 0x10) <= 16 ? im : NULL;
}
static BYTE *pawn_comp_of(unsigned long long id)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    void *hd = NULL;
    BYTE *obj = entity_obj(id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    return obj ? ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)) : NULL;
}
static unsigned g_veh_faults;
/* how: 0 = accept (engine picks the seat), 1 = the given seat, 2 = get out, 3 = the pawn's own "enter vehicle" (AI
 * path CDFC60: approach data into its blackboard + the named event; needs the target vehicle 0x1BAA9B71 set first).
 * Fault-safe like enc_safe. */
static int __attribute__((noinline)) veh_seat_call(int how, BYTE *im, int seat, BYTE *pawn)
{
    DWORD seh;
    __asm__ volatile("movl %%fs:0, %0" : "=r"(seh));
    g_enc_seh = seh; g_enc_tid = GetCurrentThreadId();
    if (__builtin_setjmp(g_enc_jb)) {
        g_enc_guard = 0;
        if (++g_veh_faults <= 20) logf_("veh: fault in the seat call %d (%u so far)", how, g_veh_faults);
        return 0;
    }
    g_enc_guard = 1;
    if (how == 3) ((void (__cdecl *)(void *))(g_base + 0xCDFC60))(pawn);
    else if (how == 4) ((int (__attribute__((thiscall)) *)(void *, void *))(g_base + 0xE5740))(im, pawn);
    else if (how == 5) ((int (__attribute__((thiscall)) *)(void *, void *))(g_base + 0xE5B40))(im, pawn);
    else if (how == 0) ((void (__attribute__((thiscall)) *)(void *, void *))(g_base + 0xE1810))(im, pawn);
    else if (how == 1) {
        /* as E1810 does after picking the seat: seat the pawn, then send the in-vehicle event [10F932AC] to its state
         * machines (pawn vf+0x78 = its StateDriver, pawn data +0x4F8; FUN_1029da10(driver, hash) passes it on) */
        ((void (__attribute__((thiscall)) *)(void *, void *, void *, int, int))(g_base + 0xD8050))(im, *(BYTE **)(im + 0xC) + seat * VEH_SEAT_STRIDE, pawn, 0, -1);
        pawn_state_event(pawn, *(unsigned *)(g_base + 0xF932AC));
    }
    else ((void (__attribute__((thiscall)) *)(void *, void *, int))(g_base + 0xE4E70))(im, pawn, 0);
    g_enc_guard = 0;
    return 1;
}
/* seat index of a pawn in a vehicle, or -1 */
static int veh_seat_of(BYTE *im, unsigned long long pawn_id)
{
    unsigned i, n = *(unsigned *)(im + 0x10);
    BYTE *s = *(BYTE **)(im + 0xC);
    if (!s || IsBadReadPtr(s, n * VEH_SEAT_STRIDE)) return -1;
    for (i = 0; i < n; i++) if (*(unsigned long long *)(s + i * VEH_SEAT_STRIDE + 0x28) == pawn_id) return (int)i;
    return -1;
}

#define NANM_VARS 0x70
static unsigned *npc_animvars(BYTE *obj);
static void native_cmd(const char *ln)
{
    unsigned long long id, k0x;
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
    } else if (sscanf(ln, "mapyaw %f", &fx) == 1) {
        g_mk_yaw = fx * 3.14159265f / 180.0f;
        logf_("mapyaw: %.1f degrees", fx);
    } else if (strncmp(ln, "maparch ", 8) == 0) {
        if (sscanf(ln + 8, "%95s", g_mk_arch) == 1 && !strchr(g_mk_arch, '\'')) g_mk_respawn = 1;
        logf_("maparch: %s", g_mk_arch);
    } else if (sscanf(ln, "mapdbg %f %f", &fx, &fy) == 2) {
        g_mk_dbg[0] = fx; g_mk_dbg[1] = fy;
        logf_("mapdbg: %.3f %.3f", fx, fy);
    } else if (strncmp(ln, "mapsign ", 8) == 0) {
        g_mk_sign = atoi(ln + 8) < 0 ? -1 : atoi(ln + 8) > 0 ? 1 : 0;   /* 0: same heading as ours (test) */
        logf_("mapsign: %d", g_mk_sign);
    } else if (strncmp(ln, "notice ", 7) == 0) {
        /* notice <UTF-8 text>: show it on screen (test) */
        wchar_t w[160];
        if (MultiByteToWideChar(CP_UTF8, 0, ln + 7, -1, w, 160)) { w[159] = 0; notice_w(w); }
        logf_("notice: %s", ln + 7);
    } else if (strcmp(ln, "menuquit") == 0) {
        /* menuquit: leave for the main menu like the console's quitToMainMenu (test) */
        quit_to_menu("menuquit command");
    } else if (strcmp(ln, "rldsend") == 0) {
        /* rldsend (host): send the reload message for the save we read last, as after a load (test) */
        g_rld_force = 1;
        logf_("rldsend: reload message for %ls requested", g_sav_last);
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
        g_npcanim = atoi(ln + 8);
        logf_("npcanim %d: NPC animation graph inputs %s", g_npcanim, g_npcanim == 2 ? "all follow the host" : g_npcanim ? "follow the host" : "are the puppets' own");
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
    } else if (sscanf(ln, "beautprof %llu %lx", &id, &a) == 2) {
        /* beautprof <id> <profile hash>: set the pawn's beautifier profile (FUN_100e97c0: the repository then picks the
         * main beautifier for {k0, profile, pose}); e.g. 1b80e486 vehicle, c83da229 vehiclepassenger, standard */
        void *holder = NULL, *bc;
        BYTE *obj = entity_obj(id, &holder);
        unsigned h = (unsigned)a;
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        bc = obj ? ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4)) : NULL;
        if (!bc) { logf_("beautprof: no beautifier component"); return; }
        ((void (__attribute__((thiscall)) *)(void *, unsigned *))(g_base + 0xE97C0))(bc, &h);
        logf_("beautprof %llu %08x: main %p (vt %08x) base %p (vt %08x)", id, h, *(void **)((BYTE *)bc + 0x28),
              *(void **)((BYTE *)bc + 0x28) ? **(unsigned **)((BYTE *)bc + 0x28) : 0, *(void **)((BYTE *)bc + 0x2C),
              *(void **)((BYTE *)bc + 0x2C) ? **(unsigned **)((BYTE *)bc + 0x2C) : 0);
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
    } else if (sscanf(ln, "deplist %llu", &id) == 1) {
        /* deplist <entity id>: the resources the entity's CDynamicDeploadComponent (key FDFC14) holds ([[ai]]) */
        void *holder = NULL;
        BYTE *obj = entity_obj(id, &holder);
        if (holder) (*(int *)((BYTE *)holder + 8))--;
        if (!obj) { logf_("deplist %llu: no entity", id); return; }
        dep_log(id, obj);
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
    } else if (sscanf(ln, "vehme %llu", &id) == 1) {
        /* vehme <pawn id>: the vehicle the pawn sits in (blackboard CurrentVehicleID) and the one it asked for */
        logf_("vehme %llu: current %llx, target %llx", id, pawn_bb_u64(id, 0xFD1BA782u), pawn_bb_u64(id, 0x1BAA9B71u));
    } else if (sscanf(ln, "vehseat %llu %llu %d", &id, &k0x, &n) == 3 || sscanf(ln, "vehexit %llu %llu", &id, &k0x) == 2) {
        /* vehseat <pawn> <vehicle> <seat index | -1 = engine picks>; vehexit <pawn> <vehicle> */
        BYTE *im = veh_impl(k0x), *pw = pawn_comp_of(id);
        int ex = ln[3] == 'e';
        if (!im || !pw) { logf_("%s: vehicle impl %p pawn %p", ex ? "vehexit" : "vehseat", im, pw); return; }
        if (!ex && n >= (int)*(unsigned *)(im + 0x10)) { logf_("vehseat: seat %d of %u", n, *(unsigned *)(im + 0x10)); return; }
        logf_("%s %llu %llu %d: call ok %d, seat now %d, pawn current vehicle %llx", ex ? "vehexit" : "vehseat", id, k0x, n,
              veh_seat_call(ex ? 2 : n < 0 ? 0 : 1, im, n, pw), veh_seat_of(im, id), pawn_bb_u64(id, 0xFD1BA782u));
    } else if (sscanf(ln, "siglog %d", &n) == 1) {
        /* siglog 0|1|2|3: log state signals of our player and the avatar (2 also other pawns, first 400; 3 all) */
        g_siglog = n; logf_("siglog %d", n);
    } else if (strcmp(ln, "plyadd") == 0) {
        ply_add();
    } else if (strcmp(ln, "plydel") == 0) {
        ply_del("command");
    } else if (strcmp(ln, "plyshow") == 0) {
        ply_show();
    } else if (sscanf(ln, "plyfind %d", &n) == 1) {
        /* plyfind 1: FUN_104f3430 (player of an entity id) answers our fake player for the avatar */
        ply_install(); g_plyfind = n; logf_("plyfind %d", n);
    } else if (sscanf(ln, "plylog %d", &n) == 1) {
        ply_install(); g_plylog = n; logf_("plylog %d", n);
    } else if (strcmp(ln, "plycallers") == 0) {
        ply_install(); ply_callers();
    } else if (sscanf(ln, "nsgsync %d", &n) == 1) {
        g_nsgsync = n; logf_("nsgsync %d", n);
    } else if (sscanf(ln, "nmssync %d", &n) == 1) {
        g_nmssync = n; logf_("nmssync %d (sent %u, got %u, set %u, guard skips %ld; ndp sent %u, got %u, added %u, removed %u)", n, g_nms_tx, g_nms_rx,
              g_nms_set, g_ms_skips, g_ndp_tx, g_ndp_rx, g_ndp_add, g_ndp_del);
    } else if (sscanf(ln, "mountprof %d", &n) == 1) {
        g_mountprof = n; logf_("mountprof %d", n);
    } else if (sscanf(ln, "npcsigdrop %d", &n) == 1) {
        g_npcsigdrop = n; logf_("npcsigdrop %d (%u dropped)", n, g_npcsigdropped);
    } else if (sscanf(ln, "npcflag %d", &n) == 1) {
        g_npcflag = n; logf_("npcflag %d", n);
    } else if (sscanf(ln, "wbp %d", &n) == 1) {
        wbp_start(n);
    } else if (sscanf(ln, "reinfblock %d", &n) == 1) {
        g_reinfblock = n; logf_("reinfblock %d", n);
    } else if (sscanf(ln, "npcdiff %d", &n) == 1) {
        g_npcdiff = n; logf_("npcdiff %d", n);
    } else if (sscanf(ln, "npcz %d", &n) == 1) {
        g_npcz = n; logf_("npcz %d", n);
    } else if (sscanf(ln, "npcface %d", &n) == 1) {
        g_npcface = n; logf_("npcface %d", n);
    } else if (sscanf(ln, "nmslayers %d", &n) == 1) {
        g_nmslayers = n < 0 ? 0 : n > 3 ? 3 : n; logf_("nmslayers %d", g_nmslayers);
    } else if (sscanf(ln, "mslog %d", &n) == 1) {
        g_mslog = n; logf_("mslog %d", n);
    } else if (sscanf(ln, "nresync %d", &n) == 1) {
        g_nresync = n; logf_("nresync %d", n);
    } else if (sscanf(ln, "doorsync %d", &n) == 1) {
        g_doorsync = n; logf_("doorsync %d", n);
    } else if (sscanf(ln, "sigsync %d", &n) == 1) {
        g_sigsync = n; logf_("sigsync %d (%d allowed, %d denied)", n, g_sig_nallow, g_sig_ndeny);
    } else if (sscanf(ln, "sigallow %lx", &a) == 1 || sscanf(ln, "sigdeny %lx", &a) == 1) {
        /* sigallow <crc32>: send this signal too (sigsync 1); sigdeny <crc32>: never send it (sigsync 2) */
        int al = ln[3] == 'a';
        unsigned *l = al ? g_sig_allow : g_sig_deny;
        int *nl = al ? &g_sig_nallow : &g_sig_ndeny;
        if (!sig_listed(l, *nl, (unsigned)a) && *nl < 32) l[(*nl)++] = (unsigned)a;
        logf_("%s %08lx (%d listed)", al ? "sigallow" : "sigdeny", a, *nl);
    } else if (sscanf(ln, "pawnsig %llu %lx", &id, &a) == 2) {
        /* pawnsig <id> <signal crc32>: a signal for the pawn's GO state machine (e.g. b2b02045 entervehicle_new) */
        BYTE *pw = pawn_comp_of(id);
        if (pw) pawn_state_event(pw, (unsigned)a);
        logf_("pawnsig %llu %08lx: %s", id, a, pw ? "sent" : "no pawn");
    } else if (sscanf(ln, "bbset %llu %lx %llx", &id, &a, &k0x) == 3) {
        logf_("bbset %llu %08lx = %llx: %d, reads %llx", id, a, k0x, pawn_bb_set_u64(id, (unsigned)a, k0x), pawn_bb_u64(id, (unsigned)a));
    } else if (sscanf(ln, "vehgetin %llu %llu", &id, &k0x) == 2 || sscanf(ln, "vehgetout %llu %llu", &id, &k0x) == 2) {
        /* vehgetin / vehgetout <pawn> <vehicle>: the vehicle's own get-in E5740 (seat, CurrentVehicleID, "get in
         * vehicle" event, anim var v13 = vehicle anim type impl+4) / get-out E5B40 */
        BYTE *im = veh_impl(k0x), *pw = pawn_comp_of(id);
        int in = ln[6] == 'i';
        if (!im || !pw) { logf_("vehget: vehicle impl %p pawn %p", im, pw); return; }
        logf_("vehget%s %llu %llu: call ok %d, seat now %d, pawn current vehicle %llx", in ? "in" : "out", id, k0x,
              veh_seat_call(in ? 4 : 5, im, 0, pw), veh_seat_of(im, id), pawn_bb_u64(id, 0xFD1BA782u));
    } else if (sscanf(ln, "vehenter %llu %llu", &id, &k0x) == 2) {
        /* vehenter <pawn> <vehicle>: target vehicle into the pawn's blackboard, then its own enter-vehicle request */
        BYTE *pw = pawn_comp_of(id);
        int ok = pw && pawn_bb_set_u64(id, 0x1BAA9B71u, k0x);
        logf_("vehenter %llu %llu: target set %d (reads %llx), call ok %d", id, k0x, ok, pawn_bb_u64(id, 0x1BAA9B71u),
              ok ? veh_seat_call(3, NULL, 0, pw) : 0);
    } else if (sscanf(ln, "animvars %llu", &id) == 1) {
        /* animvars <id>: the anim graph variables v00-v6F (anim comp FDF190 +0x1C -> +0x10), 16 per line */
        void *hd = NULL;
        BYTE *obj = entity_obj(id, &hd);
        unsigned *v;
        int i;
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!(v = npc_animvars(obj))) { logf_("animvars %llu: none", id); return; }
        for (i = 0; i < NANM_VARS; i += 16)
            logf_("animvars %llu v%02X: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x", id, i, v[i], v[i + 1], v[i + 2],
                  v[i + 3], v[i + 4], v[i + 5], v[i + 6], v[i + 7], v[i + 8], v[i + 9], v[i + 10], v[i + 11], v[i + 12], v[i + 13], v[i + 14], v[i + 15]);
    } else if (sscanf(ln, "vehsync %d", &n) == 1) {
        g_vehsync = n;
        logf_("vehsync %s", n ? "on" : "off");
    } else if (sscanf(ln, "vehseats %llu", &id) == 1) {
        /* vehseats <vehicle id>: CVehicle component, its impl (+0x10) and the seats (impl +0xC, stride 0x50, count +0x10) */
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        void *hd = NULL;
        BYTE *obj = entity_obj(id, &hd), *vc, *im;
        unsigned i, n;
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!obj) { logf_("vehseats %llu: no entity", id); return; }
        vc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDF990));
        if (!vc || IsBadReadPtr(vc, 0x20) || IsBadReadPtr(im = *(BYTE **)(vc + 0x10), 0x20)) { logf_("vehseats %llu: no CVehicle", id); return; }
        n = *(unsigned *)(im + 0x10);
        logf_("vehseats %llu: comp %p impl %p seats %u at %p", id, vc, im, n, *(void **)(im + 0xC));
        hexdump_(im, 0x40);
        for (i = 0; i < n && i < 8; i++) if (!IsBadReadPtr(*(BYTE **)(im + 0xC) + i * 0x50, 0x50)) hexdump_(*(BYTE **)(im + 0xC) + i * 0x50, 0x50);
    } else if (sscanf(ln, "avtake %llu", &id) == 1) {
        /* avtake <gadget entity>: bind it to the avatar's hand animation with its gadget comp FUN_10156b40(pawn comp)
         * and show it (Lua SetVisibility), as av_compass does for the GPS. RE only. */
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        typedef void (__attribute__((thiscall)) *take_t)(void *gadget, void *pawn);
        void *h1 = NULL, *h2 = NULL, *pawn = NULL, *gc = NULL;
        BYTE *ao = g_av_id ? entity_obj(g_av_id, &h1) : NULL, *go = entity_obj(id, &h2);
        char code[96], out[32];
        if (h1) (*(int *)((BYTE *)h1 + 8))--;
        if (h2) (*(int *)((BYTE *)h2 + 8))--;
        if (ao) pawn = ((gcomp_t)(g_base + 0x4E2CC0))(ao, (void *)(g_base + 0xFDE39C));
        if (go) gc = ((gcomp_t)(g_base + 0x4E2CC0))(go, (void *)(g_base + 0xFDFFB4));
        if (!pawn || !gc) { logf_("avtake %llu: pawn %p gadget %p", id, pawn, gc); return; }
        ((take_t)(g_base + 0x156B40))(gc, pawn);
        snprintf(code, sizeof code, "SetVisibility('%llu', true) __out = 'ok'", id);
        lua_eval(code, out, sizeof out);
        logf_("avtake %llu: bound to the avatar's hands", id);
    } else if (strncmp(ln, "attach ", 7) == 0) {
        /* attach <child id> <parent id> <bone hash hex> qx qy qz qw x y z: FUN_104e11b0(parent, child handle, &bone, 0, 0),
         * then local rotation FUN_104df660 and position FUN_104e01b0 (see av_compass). RE only. */
        typedef void (__attribute__((thiscall)) *attach_t)(void *parent, void *child, const unsigned *bone, int a, int b);
        typedef void (__attribute__((thiscall)) *lrot_t)(void *ent, const float *q, int f);
        typedef void (__attribute__((thiscall)) *lpos_t)(void *ent, float x, float y, float z);
        static float q[4] __attribute__((aligned(16)));
        unsigned long long cid, pid;
        unsigned bone;
        float x, y, z;
        void *ch = NULL, *ph = NULL;
        BYTE *co, *po;
        if (sscanf(ln + 7, "%llu %llu %x %f %f %f %f %f %f %f", &cid, &pid, &bone, &q[0], &q[1], &q[2], &q[3], &x, &y, &z) != 10) { logf_("attach: bad arguments"); return; }
        co = entity_obj(cid, &ch); po = entity_obj(pid, &ph);
        if (ph) (*(int *)((BYTE *)ph + 8))--;
        if (!co || !po || !ch) { if (ch) (*(int *)((BYTE *)ch + 8))--; logf_("attach: no entity (%p %p)", co, po); return; }
        ((attach_t)(g_base + 0x4E11B0))(po, ch, &bone, 0, 0);   /* releases the reference entity_obj took on ch */
        ((lrot_t)(g_base + 0x4DF660))(co, q, 0);
        ((lpos_t)(g_base + 0x4E01B0))(co, x, y, z);
        logf_("attach: %llu to %llu bone %08x rot %.3f %.3f %.3f %.3f pos %.3f %.3f %.3f", cid, pid, bone, q[0], q[1], q[2], q[3], x, y, z);
    } else if (sscanf(ln, "vcall1 %lx %lx %d", &a, &pv, &n) == 3) {
        /* vcall1 <obj> <vtable byte offset> <int>: thiscall obj->vf(int) for one-argument methods (RET 4). RE only. */
        if (IsBadReadPtr((void *)a, 4) || IsBadReadPtr(*(void **)a, pv + 4)) { logf_("vcall1 %lx: bad object", a); return; }
        logf_("vcall1 %lx +%lx (%p) -> %08x", a, pv, (*(void ***)a)[pv / 4],
              ((unsigned (__attribute__((thiscall)) *)(void *, int))(*(void ***)a)[pv / 4])((void *)a, n));
    } else if (sscanf(ln, "vcall %lx %lx", &a, &pv) == 2 || sscanf(ln, "vcallp %lx %lx", &a, &pv) == 2) {
        /* vcall <obj> <vtable byte offset> [f1 f2 f3 f4]: thiscall obj->vf(f1..f4 by value); vcallp passes a pointer
         * to f1..f4 instead (vector setters) and logs what the callee left there. Logs eax. RE only. */
        typedef unsigned (__attribute__((thiscall)) *vc_t)(void *, float, float, float, float);
        typedef unsigned (__attribute__((thiscall)) *vcp_t)(void *, float *);
        static float f[4];
        int byptr = ln[5] == 'p';
        unsigned r;
        f[0] = f[1] = f[2] = f[3] = 0;
        sscanf(ln + 5 + byptr, " %*x %*x %f %f %f %f", &f[0], &f[1], &f[2], &f[3]);
        if (IsBadReadPtr((void *)a, 4) || IsBadReadPtr(*(void **)a, pv + 4)) { logf_("vcall %lx: bad object", a); return; }
        r = byptr ? ((vcp_t)(*(void ***)a)[pv / 4])((void *)a, f)
                  : ((vc_t)(*(void ***)a)[pv / 4])((void *)a, f[0], f[1], f[2], f[3]);
        logf_("vcall %lx +%lx (%p) -> %08x, vec %.3f %.3f %.3f %.3f", a, pv, (*(void ***)a)[pv / 4], r, f[0], f[1], f[2], f[3]);
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

/* sender shot counter: bullet events miss shots (e.g. aimed at the ground close by), so the shot method vf+0x20 of the
 * weapon object classes X (vtable RVA E1EA18 for guns, FUN_10114330; E21DE0 for the machete) is hooked in the class
 * vtables themselves and the shots of our own current weapon object are counted. It was a private vtable copy put on our weapon once it had been in our hands
 * for 2 s (hooking during the draw crashed once): a machete drawn and swung at once was never counted, so the avatar
 * did not swing. */
static const unsigned g_lx_cls[2] = { 0xE1EA18, 0xE21DE0 };
static void *g_lx_origs[2];
static BYTE *g_lx_obj, *g_lx_cur;
static unsigned g_lx_shots, g_lx_noevent, g_lx_aimed;
static void __attribute__((thiscall)) lx_hook(void *self, void *pawn)
{
    unsigned before = g_shot_seq;
    void *g_lx_orig = g_lx_origs[*(unsigned *)self == (unsigned)(g_base + g_lx_cls[1])];
    if (self != g_lx_cur) { ((void (__attribute__((thiscall)) *)(void *, void *))g_lx_orig)(self, pawn); return; }
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
    static unsigned other;
    int c;
    if (!x || IsBadReadPtr(x, 4)) { g_lx_cur = NULL; return; }
    c = *(unsigned *)x == (unsigned)(g_base + g_lx_cls[0]) ? 0 : *(unsigned *)x == (unsigned)(g_base + g_lx_cls[1]) ? 1 : -1;
    if (c < 0) {
        if (other != *(unsigned *)x) { other = *(unsigned *)x; logf_("tx: our weapon object %p has class vtable rva %x, shots not counted", x, other - (unsigned)g_base); }
        g_lx_cur = NULL;
        return;
    }
    if (!g_lx_origs[c]) {
        void **slot = (void **)(g_base + g_lx_cls[c] + 0x20);
        DWORD old;
        if (!VirtualProtect(slot, 4, PAGE_READWRITE, &old)) { logf_("tx: class vtable not writable (%lu)", GetLastError()); return; }
        g_lx_origs[c] = *slot;
        *slot = (void *)lx_hook;
        VirtualProtect(slot, 4, old, &old);
        logf_("tx: shot method of weapon class %X hooked (was %p)", g_lx_cls[c], g_lx_origs[c]);
    }
    if (g_lx_cur != x) logf_("tx: counting shots of our weapon object %p", x);
    g_lx_cur = g_lx_obj = x;
}

typedef void (__attribute__((thiscall)) *np_encode_t)(void *self, void *memento);
static unsigned g_enc_faults;
static int __attribute__((noinline)) enc_safe(void *self, void *mem, unsigned long long who)
{
    DWORD seh;
    __asm__ volatile("movl %%fs:0, %0" : "=r"(seh));
    g_enc_seh = seh; g_enc_tid = GetCurrentThreadId();
    if (__builtin_setjmp(g_enc_jb)) {
        g_enc_guard = 0;
        if (++g_enc_faults <= 20 || g_enc_faults % 500 == 0) logf_("encoder fault on %llu (pawn not ready: dying, rescued or loading), packet skipped (%u so far)", who, g_enc_faults);
        return 0;
    }
    g_enc_guard = 1;
    ((np_encode_t)(g_base + 0xA6EC0))(self, mem);
    g_enc_guard = 0;
    return 1;
}
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
    if (!enc_safe(g_tx_this, m, g_net_id)) return;
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
        typedef void *(__fastcall *gcur_t)(void *impl);
        void *inv = ((inv_t)(g_base + 0x7E140))(pawn), *cur = NULL;
        BYTE *impl = inv ? *(BYTE **)((BYTE *)inv + 4) : NULL;
        if (inv && ((iget_t)(g_base + 0x125F40))(inv) == 1) cur = ((cur_t)(g_base + 0x127DA0))(inv);
        lx_hook_weapon(cur);
        /* bAutoDraw (inventory impl +0x4E, archetype setting 1 for the player) comes back 0 from the saves: then the
         * weapon graph's "try auto-draw" (inventory request 18) never takes the weapon back after a grenade, a door
         * or a vehicle - the same without the probe. Set it back unless coop_flags.txt says noautodraw. */
        if (impl && !g_noautodraw && !impl[0x4E]) { impl[0x4E] = 1; logf_("tx: our inventory %p had bAutoDraw 0, set to 1", impl); }
        /* a gadget in the hands (impl +0x74 = 2: the map with the GPS) is sent like a weapon, by its archetype name;
         * FUN_10129090(impl) = the gadget component in the hands. Only gadgets.Equipped.*: grenades and molotovs are
         * gadgets too (gadgets.Grenades.*) and stay "" (a burning molotov given to the avatar is not wanted) */
        if (!cur && impl && *(int *)(impl + 0x74) == 2) cur = ((gcur_t)(g_base + 0x129090))(impl);
        if (cur != g_tx_wcur) {
            int gadget = impl && *(int *)(impl + 0x74) == 2 && cur;
            char code[96];
            void *wh = cur ? *(void **)((BYTE *)cur + 8) : NULL;
            g_tx_wcur = cur; g_tx_weap[0] = 0;
            if (wh && !IsBadReadPtr(wh, 8)) {
                snprintf(code, sizeof code, "__out = tostring(GetEntityName('%llu'))", *(unsigned long long *)wh);
                lua_eval(code, g_tx_weap, sizeof g_tx_weap);
                if (!strcmp(g_tx_weap, "nil")) g_tx_weap[0] = 0;
            }
            if (gadget && strncmp(g_tx_weap, "gadgets.Equipped.", 17)) { logf_("tx: gadget '%s' in hands, sent as none", g_tx_weap); g_tx_weap[0] = 0; }
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
static void npc_flags_pre(BYTE *mb);
static void *g_mf_vt[64], *g_mf_orig7c, *g_mf_orig80, *g_mf_obj;
static int g_mf_on = 1;
static void __attribute__((thiscall)) mf_call(void *orig, void *self, float dt)
{
    BYTE *mp = *(BYTE **)(g_base + 0x1645A74);
    BYTE old = 0;
    if (mp && g_mf_on) { old = mp[4]; mp[4] = 1; }
    npc_flags_pre((BYTE *)self);
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
        /* log the avatar's weapon object state fields. It used to get a private vtable copy here too (research: counting
         * its shot-method calls); that one shared buffer was put on the machete and then refilled for the pistol while
         * the machete object kept pointing at it; copy A crashed (FUN_10110470) on the next pistol shot, and without the
         * copy the same weapon swaps and shots ran without a crash */
        BYTE *y = *(BYTE **)((BYTE *)wc + 0x24);
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
    {
        /* a door (cinematic beautifier E16AD0) or a vehicle swaps the main beautifier; the new standard one needs the MP
         * flag at once, not at the next 500 ms check: until then the avatar slid out of the door without walking */
        static DWORD mf_t;
        if (now - mf_t >= 50) {
            void *hd = NULL;
            BYTE *ao = entity_obj(g_av_id, &hd), *bc;
            if (hd) (*(int *)((BYTE *)hd + 8))--;
            mf_t = now;
            if (ao && (bc = ((np_getcomp_t)(g_base + 0x4E2CC0))(ao, (void *)(g_base + 0xFDEAD4)))) mf_install(bc);
        }
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
                {
                    /* the point is where the peer's bullet stopped, i.e. on a surface; the replayed trace ended there and,
                     * with the position rounding, often just short of it (a shot at the ground at our feet left no dust
                     * on the other PC): carry the point 0.5 m on along muzzle -> point */
                    void *hd = NULL;
                    BYTE *ao = entity_obj(g_av_id, &hd);
                    if (hd) (*(int *)((BYTE *)hd + 8))--;
                    if (ao) {
                        float v[3], n;
                        for (k = 0; k < 3; k++) v[k] = g_rx_shot_p[k] - (*(float *)(ao + 0x60 + 4 * k) + d[k]);
                        n = sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
                        if (n > 0.05f && n < 500.0f) for (k = 0; k < 3; k++) g_rx_shot_p[k] += v[k] / n * 0.5f;
                    }
                }
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
    av_forget();
}

/* drop our avatar state without touching the world: after a load (our own game over or reloading a save) the world is
 * rebuilt and the avatar entity is gone, but its id stayed set, so no new avatar was spawned and the peer stayed
 * invisible here while it saw us */
static BYTE *g_st_obj[2];   /* defined with the stim hooks below */
static void av_forget(void)
{
    g_st_obj[0] = NULL;
    g_av_id = 0; g_av_body = g_av_mat = NULL; g_av_have = 0; av_compass(0);
    memset(g_av_wc, 0, sizeof g_av_wc);
    ply_del("avatar forgotten");
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
/* our player is within r metres (ground plane) of the avatar */
static int av_near_me(float r)
{
    void *h1 = NULL, *h2 = NULL;
    BYTE *a = entity_obj(g_av_id, &h1), *m = entity_obj(g_net_id, &h2);
    int touch = 0;
    if (a && m) {
        float dx = *(float *)(a + 0x60) - *(float *)(m + 0x60), dy = *(float *)(a + 0x64) - *(float *)(m + 0x64);
        touch = dx * dx + dy * dy < r * r;
    }
    if (h1) (*(int *)((BYTE *)h1 + 8))--;
    if (h2) (*(int *)((BYTE *)h2 + 8))--;
    return touch;
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
        if (s == 1 && dmg && g_av_id && (!src || src == g_net_id) && av_near_me(1.5f)) {
            /* damage with no other attacker while the avatar touches us: the avatar's pawn is driven by velocity toward
             * the peer's position and the physics resolved the overlap by throwing our player (the host died this way
             * snagging on the joiner's body several times); dropped. Own grenades this close to the avatar count too. */
            static unsigned n;
            if (++n <= 50) logf_("bump: dropped damage on us next to the avatar (type %d, amount %d, flags %x, src %llu)", *(int *)(ev + 0x48), *(int *)(ev + 0x58), *(unsigned *)(ev + 0x5C), src);
            return 0;
        }
        if (s == 1 && dmg) {
            static unsigned n;
            if (++n <= 100) logf_("damage on us: type %d, amount %d, flags %x, src %llu", *(int *)(ev + 0x48), *(int *)(ev + 0x58), *(unsigned *)(ev + 0x5C), src);
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
static struct { unsigned long long id; BYTE *mem, *obj; unsigned shots, fires; BYTE lastfire; void *wcur; int wmode; char wname[64]; unsigned wcat; DWORD wsent; unsigned lastact, animhash; DWORD animsent; } g_nh[NPC_MAX];
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
/* vt / hoff: object vtable RVA and the offset of its entity holder pointer (0 = CPawnAgent EC5078, +4) */
typedef struct { BYTE *p, *c; int busy; unsigned vt, hoff; } IncScan;
static int npc_scan_step(IncScan *s, size_t budget, void (*cb)(unsigned long long id, BYTE *obj, BYTE *agent, void *ctx), void *ctx)
{
    static BYTE chunk[0x10000];
    MEMORY_BASIC_INFORMATION mbi;
    unsigned vt = (unsigned)(g_base + (s->vt ? s->vt : 0xEC5078)), ho = s->hoff ? s->hoff : 4;
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
                    for (k = 0; k + ho + 4 <= n; k += 4) {
                        BYTE *holder, *obj;
                        if (*(unsigned *)(chunk + k) != vt) continue;
                        holder = *(BYTE **)(chunk + k + ho);
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
static struct { unsigned long long id; BYTE *mem, *obj; unsigned shots, fires; BYTE lastfire; void *wcur; int wmode; char wname[64]; unsigned wcat; DWORD wsent; unsigned lastact, animhash; DWORD animsent; } g_nb[NPC_MAX];  /* list being built */
static int g_nb_n;
static unsigned long long g_nx[64];  /* ids never synced (buddies) */
static int g_nx_n;
static struct { unsigned long long id; BYTE *agent; void *drv; } g_nagent[64];   /* host: AI agent of a synced NPC and its
                                                                                * state driver (agent vf+0x118; NRE1, NSG1) */
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
    {
        int k, free_k = -1;
        for (k = 0; k < 64; k++) { if (g_nagent[k].id == id) break; if (!g_nagent[k].id && free_k < 0) free_k = k; }
        if (k == 64) k = free_k >= 0 ? free_k : (int)(id % 64);
        g_nagent[k].id = id; g_nagent[k].agent = agent;
        /* vf+0x118 reads the pawn at agent+0x268: still 0 for an agent right after a load (Dunia+9600B6 crashed A);
         * the next pass fills it in */
        g_nagent[k].drv = IsBadReadPtr(agent + 0x268, 4) || !*(void **)(agent + 0x268) ? NULL :
            ((void *(__attribute__((thiscall)) *)(void *))(*(void ***)agent)[0x118 / 4])(agent);
    }
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
/* the animation graph's three layers (MoveLayer 0..2): what the AI and the GO states ask each layer to play ends up
 * as a move state id at +0x220 + layer * 4 of the same block (FUN_1051f500(id, layer, flag, blend) on the anim
 * component writes it through FUN_1027c4f0: id, flag byte +0x274, dirty byte +0x284; FUN_1051f4e0(layer) reads it).
 * mslog 1 logs every change for host NPCs and puppets. */
static int g_mslog;
static struct { unsigned long long id; int ms[3]; } g_msw[128];
static void ms_watch(const char *tag, unsigned long long id, const unsigned *v)
{
    const int *ms = (const int *)((const BYTE *)v - 0x10 + 0x220);
    int i, k, fr = -1;
    if (!g_mslog) return;
    for (i = 0; i < 128; i++) { if (g_msw[i].id == id) break; if (!g_msw[i].id && fr < 0) fr = i; }
    if (i == 128) { if (fr < 0) return; i = fr; g_msw[i].id = id; for (k = 0; k < 3; k++) g_msw[i].ms[k] = 0x7FFFFFFF; }
    for (k = 0; k < 3; k++)
        if (ms[k] != g_msw[i].ms[k]) {
            logf_("ms %s %llu layer %d: %x -> %x (flag %u, blend %.2f; v58 %d)", tag, id, k, g_msw[i].ms[k], ms[k],
                  ((const BYTE *)v - 0x10 + 0x274)[k], ((const float *)((const BYTE *)v - 0x10 + 0x22c))[k], (int)v[0x58]);
            g_msw[i].ms[k] = ms[k];
        }
}
/* ---- NPC move states (NMS1). Whatever the host's AI makes an NPC do (sit, drink, smoke, talk, gesture, react) ends
 * up as these three layer ids; the joiner's puppet (AI paused) asks for nothing and stands. The host sends each NPC's
 * three ids when one changes and every 2 s; the joiner asks its puppet's anim component for the same ones with the
 * game's own request FUN_1051f500. ---- */
#define NMS_MAGIC 0x31534D4Eu      /* "NMS1" */
typedef struct { unsigned magic; unsigned long long id; int ms[3]; } NpcMsPkt;
/* the first tries passed (layer, id): the id went in as a layer index and overwrote the block (+CF7D63, +286F82,
 * +28462D crashes); the AI calls it as (id, layer from FUN_1051f5f0(id), 0, 0.0). Checked on A/B 2026-11-04 with
 * npcanim 2 (owner: puppets calm like the host's and repeat their moves; smart terrain sitting still does not start) */
static int g_nmssync = 1;          /* nmssync 0|1 */
static int g_nmslayers = 3;        /* nmslayers 2|3: layers requested on puppets */
static unsigned g_nms_tx, g_nms_rx, g_nms_set;
static struct { unsigned long long id; int ms[3]; DWORD sent; } g_nms_h[128];    /* host: last sent */
static struct { unsigned long long id; int ms[3], done[3]; int ok, tries[3]; DWORD at[3]; } g_nms_j[128];   /* joiner: last from the host, last requested */
static void nms_host(unsigned long long id, const unsigned *v, DWORD now)
{
    const int *ms = (const int *)((const BYTE *)v - 0x10 + 0x220);
    int i, fr = -1;
    NpcMsPkt k;
    if (!g_nmssync) return;
    for (i = 0; i < 128; i++) { if (g_nms_h[i].id == id) break; if (!g_nms_h[i].id && fr < 0) fr = i; }
    if (i == 128) { if (fr < 0) return; i = fr; g_nms_h[i].id = id; g_nms_h[i].sent = 0; }
    if (!memcmp(g_nms_h[i].ms, ms, sizeof k.ms) && now - g_nms_h[i].sent < 2000) return;
    memcpy(g_nms_h[i].ms, ms, sizeof k.ms); g_nms_h[i].sent = now;
    k.magic = NMS_MAGIC; k.id = id; memcpy(k.ms, ms, sizeof k.ms);
    sendto(g_ns, (char *)&k, sizeof k, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    g_nms_tx++;
}
static void nms_rx(const NpcMsPkt *k)
{
    int i, fr = -1;
    if (g_npc_role != 2) return;
    g_nms_rx++;
    for (i = 0; i < 128; i++) { if (g_nms_j[i].id == k->id) break; if (!g_nms_j[i].id && fr < 0) fr = i; }
    if (i == 128) { if (fr < 0) return; i = fr; g_nms_j[i].id = k->id; }
    if (!g_nms_j[i].ok) { int l; for (l = 0; l < 3; l++) g_nms_j[i].done[l] = 0x7FFFFFFF; }
    memcpy(g_nms_j[i].ms, k->ms, sizeof k->ms); g_nms_j[i].ok = 1;
}
/* ---- NPC movement resources (NDP1). A move state plays only if the CMovementResource holding its clips is in the
 * pawn's CDynamicDeploadComponent container (dep_container): the host's AI adds the ones an action needs (smart
 * terrain: CSmartTerrain +0x158 lists them, FUN_1091bc00; the executor 9AB190 adds the STP's workspace), the paused
 * AI of a puppet never does, so a requested sit id (647-649) was dropped by the guard at 2848F0. The host sends each
 * NPC's CMovementResource ids on change and every 3 s; the joiner adds the missing ones with the game's own
 * FUN_10520a60(&id, container) (resource manager [11606294], type CMovementResource 10FDF168) and requests the
 * layers only once they are loaded. Ones it added and the host dropped are removed 10 s later. ---- */
#define NDP_MAGIC 0x3150444Eu      /* "NDP1" */
#define NDP_MAX 24
typedef struct { unsigned magic; unsigned long long id; unsigned n, ids[NDP_MAX]; int bb[5]; unsigned bbok; unsigned long long mount; } NpcDepPkt;
/* the move state ints on the pawn blackboard that the graph's smart terrain nodes play (CGOStateSmartTerrain,
 * blackboardMoveStateName): 647-649 on layer 0 are generic STP slots, the clip is the id in these. A puppet kept stale
 * ones: it sat with another clip (lifted above the box) and fell back to 4dd. */
static const unsigned g_bb_ms_keys[5] = { 0xBD3C16F5u /* smartterrain_moveStateID */, 0x7F6E3CC1u /* _start_ */,
                                          0x6B68DF22u /* _end_ */, 0xFCC03024u /* _abrutend_ */, 0xE755C0CDu };
/* the int value object of a blackboard entry (value vtable E39578, int at +4): map end node at bb+0x18, entries
 * {next, prev, key, holder}, holder+4 -> value */
static int *bb_int(BYTE *obj, unsigned key)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef BYTE *(__attribute__((thiscall)) *bb_t)(void *pawn);
    BYTE *pawn, *bb, *end, *n, *v;
    int c;
    if (!obj || !(pawn = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C))) || IsBadReadPtr(*(void **)pawn, 0x80)) return NULL;
    if (!(bb = ((bb_t)(*(void ***)pawn)[0x7C / 4])(pawn)) || IsBadReadPtr(bb, 0x20) || !(end = *(BYTE **)(bb + 0x18)) || IsBadReadPtr(end, 4)) return NULL;
    for (n = *(BYTE **)end, c = 0; n && n != end && c < 64; n = *(BYTE **)n, c++) {
        if (IsBadReadPtr(n, 0x10)) return NULL;
        if (*(unsigned *)(n + 8) != key) continue;
        if (IsBadReadPtr(*(BYTE **)(n + 0xC), 8) || !(v = *(BYTE **)(*(BYTE **)(n + 0xC) + 4)) || IsBadReadPtr(v, 8)) return NULL;
        return *(unsigned *)v == (unsigned)(g_base + 0xE39578) ? (int *)(v + 4) : NULL;
    }
    return NULL;
}
static unsigned g_ndp_tx, g_ndp_rx, g_ndp_add, g_ndp_del, g_ndp_bb;
static struct { unsigned long long id, mount; unsigned n, ids[NDP_MAX]; int bb[5]; DWORD sent; } g_ndp_h[128];
static struct { unsigned long long id, mount, mounted; unsigned n, ids[NDP_MAX], na, added[NDP_MAX], bbok; int bb[5], mtries; DWORD gone[NDP_MAX], since, mt; int ok; } g_ndp_j[128];
/* mounted guns: an NPC at a stationary gun is attached to it by FUN_100c76b0(CMountedWeapon comp (key FDE92C), pawn
 * comp) ("MountedWeapon - Attach": attaches the pawn entity to the gun, makes the gun its weapon, blackboard 9BB56DBB =
 * the gun's id); FUN_100c76c0 lets it go. The host's AI does it from a GO state (CE4580); a puppet only played the
 * gunner animation, ~0.5 m off the gun, and the gun did not turn. The host sends the gun's id (NDP1 mount) while its
 * NPC holds a weapons.MountedWeapons.* weapon; the joiner attaches its puppet the same way. */
#define MOUNT_BB_KEY 0x9BB56DBBu
static int ndp_mounted(unsigned long long id)
{
    int i;
    for (i = 0; i < 128; i++) if (g_ndp_j[i].id == id) return g_ndp_j[i].mounted != 0 || g_ndp_j[i].mount != ~0ULL;
    return 0;
}
static unsigned main_beaut_vt(BYTE *obj, BYTE **bcp)
{
    BYTE *bc = obj ? ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4)) : NULL;
    if (bcp) *bcp = bc;
    return bc && *(void **)(bc + 0x28) && !IsBadReadPtr(*(void **)(bc + 0x28), 4) ? **(unsigned **)(bc + 0x28) - (unsigned)g_base : 0;
}
/* while an NPC is at a gun, every 1.5 s on both copies: where it and the gun are, who the gun thinks uses it */
static void mount_diag(const char *tag, unsigned long long id, BYTE *obj, unsigned long long gun, DWORD now)
{
    static DWORD last[2];
    DWORD *l = &last[tag[0] == 'p'];
    void *hd = NULL, *mw;
    BYTE *go, *bc;
    unsigned vt;
    float *a, *b;
    if (now - *l < 1500) return;
    *l = now;
    go = entity_obj(gun, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!go) { logf_("mountd %s %llu: gun %llu not found", tag, id, gun); return; }
    mw = ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(go, (void *)(g_base + 0xFDE92C));
    vt = main_beaut_vt(obj, &bc);
    a = (float *)obj; b = (float *)go;
    logf_("mountd %s %llu: pawn (%.2f %.2f %.2f) dir (%.2f %.2f) | gun %llu (%.2f %.2f %.2f) dir (%.2f %.2f) | main vt %x base vt %x | gun user %llx", tag, id,
          a[0x60 / 4], a[0x64 / 4], a[0x68 / 4], a[0x30 / 4], a[0x34 / 4], gun, b[0x60 / 4], b[0x64 / 4], b[0x68 / 4], b[0x30 / 4], b[0x34 / 4], vt,
          bc && *(void **)(bc + 0x2C) && !IsBadReadPtr(*(void **)(bc + 0x2C), 4) ? **(unsigned **)(bc + 0x2C) - (unsigned)g_base : 0,
          mw && *(BYTE **)((BYTE *)mw + 0x10) ? *(unsigned long long *)(*(BYTE **)((BYTE *)mw + 0x10) + 0x38) : 0ULL);
}
static int g_mountprof = 1;   /* mountprof 0|1: the puppet at a gun gets the mountedweapon beautifier profile */
static void mf_install(BYTE *bc);
static void mount_call(unsigned long long gun, BYTE *obj, int on)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void (__attribute__((thiscall)) *use_t)(void *mw, void *pawn);
    void *hd = NULL, *mw, *pc;
    BYTE *go = entity_obj(gun, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!go || !(mw = ((gcomp_t)(g_base + 0x4E2CC0))(go, (void *)(g_base + 0xFDE92C))) || !(pc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)))) {
        logf_("mount: gun %llu or pawn not found", gun); return;
    }
    ((use_t)(g_base + (on ? 0xC76B0 : 0xC76C0)))(mw, pc);
    {
        /* the host's gunner is posed by the mountedweapon beautifier (profile CE7A971C); the puppet kept the
         * third-person one and stood ~0.5 m off the gun. Back to standard (10F7D787) when it lets go. */
        BYTE *bc;
        unsigned before = main_beaut_vt(obj, &bc), h = on ? 0xCE7A971Cu : 0x10F7D787u;
        int j;
        if (g_mountprof && bc) {
            ((void (__attribute__((thiscall)) *)(void *, unsigned *))(g_base + 0xE97C0))(bc, &h);
            mf_install(bc);
            for (j = 0; j < g_np_n; j++) if (g_np[j].obj == obj) g_np[j].mb = *(BYTE **)(bc + 0x28);
            if (!on && (!*(void **)(bc + 0x2C) || **(unsigned **)(bc + 0x2C) != (unsigned)(g_base + 0xE16E98))) np_slot(obj, 0x2C, 0x608487bc, 0xFFFFFFFFu, 0xFFFFFFFFu);
        }
        logf_("mount: puppet main beautifier vt %x -> %x, base vt %x (profile %08x%s)", before, main_beaut_vt(obj, NULL),
              bc && *(void **)(bc + 0x2C) ? **(unsigned **)(bc + 0x2C) - (unsigned)g_base : 0, h, g_mountprof ? "" : ", not set");
    }
}
static unsigned dep_movements(BYTE *obj, unsigned *ids)
{
    BYTE *k = dep_container(obj), **ch;
    unsigned i, n, m = 0;
    if (!k) return 0;
    n = *(unsigned *)(k + 0x2C); ch = *(BYTE ***)(k + 0x28);
    if (n > 64 || IsBadReadPtr(ch, n * 4)) return 0;
    for (i = 0; i < n && m < NDP_MAX; i++)
        if (ch[i] && !IsBadReadPtr(ch[i], 0x20) && !strcmp(res_type(ch[i]), "CMovementResource")) ids[m++] = *(unsigned *)(ch[i] + 0x1C);
    return m;
}
static void dep_host(unsigned long long id, BYTE *obj, int mounted, DWORD now)
{
    NpcDepPkt k;
    int i, fr = -1;
    memset(&k, 0, sizeof k);
    k.n = dep_movements(obj, k.ids);
    for (i = 0; i < 5; i++) { int *b = bb_int(obj, g_bb_ms_keys[i]); if (b) { k.bb[i] = *b; k.bbok |= 1u << i; } }
    k.mount = mounted ? pawn_bb_u64(id, MOUNT_BB_KEY) : ~0ULL;
    if (k.mount != ~0ULL) mount_diag("host", id, obj, k.mount, now);
    for (i = 0; i < 128; i++) { if (g_ndp_h[i].id == id) break; if (!g_ndp_h[i].id && fr < 0) fr = i; }
    if (i == 128) { if (fr < 0) return; i = fr; g_ndp_h[i].id = id; g_ndp_h[i].sent = 0; g_ndp_h[i].n = 0xFFFFFFFF; }
    if (g_ndp_h[i].n == k.n && !memcmp(g_ndp_h[i].ids, k.ids, k.n * 4) && !memcmp(g_ndp_h[i].bb, k.bb, sizeof k.bb) && g_ndp_h[i].mount == k.mount && now - g_ndp_h[i].sent < 3000) return;
    if (g_ndp_h[i].mount != k.mount && g_ndp_h[i].sent) logf_("ndp host %llu: mounted gun %llx -> %llx (main beautifier vt %x)", id, g_ndp_h[i].mount, k.mount, main_beaut_vt(obj, NULL));
    g_ndp_h[i].mount = k.mount;
    if (g_mslog && (g_ndp_h[i].n != k.n || memcmp(g_ndp_h[i].ids, k.ids, k.n * 4))) logf_("ndp host %llu: %u movements", id, k.n);
    g_ndp_h[i].n = k.n; memcpy(g_ndp_h[i].ids, k.ids, sizeof k.ids); memcpy(g_ndp_h[i].bb, k.bb, sizeof k.bb); g_ndp_h[i].sent = now;
    k.magic = NDP_MAGIC; k.id = id;
    sendto(g_ns, (char *)&k, sizeof k, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    g_ndp_tx++;
}
static void ndp_rx(const NpcDepPkt *k)
{
    int i, fr = -1;
    if (g_npc_role != 2 || k->n > NDP_MAX) return;
    g_ndp_rx++;
    for (i = 0; i < 128; i++) { if (g_ndp_j[i].id == k->id) break; if (!g_ndp_j[i].id && fr < 0) fr = i; }
    if (i == 128) { if (fr < 0) return; i = fr; memset(&g_ndp_j[i], 0, sizeof g_ndp_j[i]); g_ndp_j[i].id = k->id; }
    if (g_ndp_j[i].ok && (g_ndp_j[i].n != k->n || memcmp(g_ndp_j[i].ids, k->ids, k->n * 4))) g_ndp_j[i].since = 0;
    if (g_ndp_j[i].mount != k->mount) g_ndp_j[i].mtries = 0;
    g_ndp_j[i].n = k->n; memcpy(g_ndp_j[i].ids, k->ids, k->n * 4); memcpy(g_ndp_j[i].bb, k->bb, sizeof k->bb); g_ndp_j[i].bbok = k->bbok; g_ndp_j[i].mount = k->mount; g_ndp_j[i].ok = 1;
}
/* joiner, every pass for every puppet (not from the third-person beautifier's update: at a gun the main beautifier is
 * another class, dep_apply and the rest stop running there and the puppet never left the gun): the host NPC's gun,
 * attach (2 s apart, 3 tries per gun), let go when the host's lets go, then ask for the host's layers again */
static void mount_tick(unsigned long long id, unsigned long long lid, BYTE *obj, DWORD now)
{
    int i, l;
    for (i = 0; i < 128 && g_ndp_j[i].id != id; i++) ;
    if (i == 128 || !g_ndp_j[i].ok) return;
    if (g_ndp_j[i].mounted) mount_diag("puppet", id, obj, g_ndp_j[i].mounted, now);
    if (g_ndp_j[i].mounted && g_ndp_j[i].mounted != g_ndp_j[i].mount) {
        logf_("mount: puppet %llu leaves gun %llu", id, g_ndp_j[i].mounted);
        mount_call(g_ndp_j[i].mounted, obj, 0); g_ndp_j[i].mounted = 0;
        for (i = 0; i < 128; i++) if (g_nms_j[i].id == id) for (l = 0; l < 3; l++) g_nms_j[i].done[l] = 0x7FFFFFFF;
        return;
    }
    if (g_ndp_j[i].mount != ~0ULL && !g_ndp_j[i].mounted && g_ndp_j[i].mtries < 3 && now - g_ndp_j[i].mt > 2000) {
        g_ndp_j[i].mt = now; g_ndp_j[i].mtries++;
        mount_call(g_ndp_j[i].mount, obj, 1);
        logf_("mount: puppet %llu takes gun %llu (try %d): blackboard now %llx", id, g_ndp_j[i].mount, g_ndp_j[i].mtries, pawn_bb_u64(lid, MOUNT_BB_KEY));
        if (pawn_bb_u64(lid, MOUNT_BB_KEY) == g_ndp_j[i].mount) g_ndp_j[i].mounted = g_ndp_j[i].mount;
    }
}
/* joiner: make the puppet's container hold the host's movements; 1 = all of them loaded (or no list / given up) */
static int dep_apply(unsigned long long id, BYTE *obj, DWORD now)
{
    typedef BYTE *(__attribute__((thiscall)) *find_t)(void *c, unsigned *id);
    typedef void (__attribute__((thiscall)) *rem_t)(void *c, void *r);
    typedef char (__attribute__((thiscall)) *lf_t)(void *);
    BYTE *k = dep_container(obj), *r;
    unsigned j, a, in;
    int i, ready = 1;
    for (i = 0; i < 128 && g_ndp_j[i].id != id; i++) ;
    if (i == 128 || !g_ndp_j[i].ok || !k) return 1;
    for (j = 0; j < 5; j++) {
        int *b;
        if (!(g_ndp_j[i].bbok >> j & 1) || !(b = bb_int(obj, g_bb_ms_keys[j])) || *b == g_ndp_j[i].bb[j]) continue;
        if (++g_ndp_bb <= 300 || g_mslog) logf_("ndp: puppet %llu blackboard %08x: %x -> host's %x", id, g_bb_ms_keys[j], *b, g_ndp_j[i].bb[j]);
        *b = g_ndp_j[i].bb[j];
    }
    for (j = 0; j < g_ndp_j[i].n; j++) {
        unsigned rid = g_ndp_j[i].ids[j];
        if (!(r = ((find_t)(*(void ***)k)[0x48 / 4])(k, &rid))) {
            ((void (*)(unsigned *, void *))(g_base + 0x520A60))(&rid, k);
            if (!(r = ((find_t)(*(void ***)k)[0x48 / 4])(k, &rid))) { ready = 0; continue; }
            if (++g_ndp_add <= 200 || g_mslog) logf_("ndp: puppet %llu + movement %08x", id, rid);
            for (a = 0; a < g_ndp_j[i].na && g_ndp_j[i].added[a] != rid; a++) ;
            if (a == g_ndp_j[i].na && a < NDP_MAX) { g_ndp_j[i].added[a] = rid; g_ndp_j[i].gone[a] = 0; g_ndp_j[i].na++; }
        }
        if (!((lf_t)(*(void ***)r)[6])(r)) ready = 0;
    }
    /* the ones we added that the host no longer has: removed 10 s after it dropped them */
    for (a = 0; a < g_ndp_j[i].na; a++) {
        for (in = 0, j = 0; j < g_ndp_j[i].n; j++) if (g_ndp_j[i].ids[j] == g_ndp_j[i].added[a]) in = 1;
        if (in) { g_ndp_j[i].gone[a] = 0; continue; }
        if (!g_ndp_j[i].gone[a]) { g_ndp_j[i].gone[a] = now | 1; continue; }
        if (now - g_ndp_j[i].gone[a] < 10000) continue;
        if ((r = ((find_t)(*(void ***)k)[0x48 / 4])(k, &g_ndp_j[i].added[a]))) {
            BYTE **ch = *(BYTE ***)(k + 0x28);
            unsigned n = *(unsigned *)(k + 0x2C), c;
            for (c = 0; c < n && ch[c] != r; c++) ;
            if (c < n) { ((rem_t)(*(void ***)k)[0x64 / 4])(k, r); if (++g_ndp_del <= 200 || g_mslog) logf_("ndp: puppet %llu - movement %08x", id, g_ndp_j[i].added[a]); }
        }
        g_ndp_j[i].na--;
        g_ndp_j[i].added[a] = g_ndp_j[i].added[g_ndp_j[i].na]; g_ndp_j[i].gone[a] = g_ndp_j[i].gone[g_ndp_j[i].na]; a--;
    }
    if (ready) { g_ndp_j[i].since = 0; return 1; }
    if (!g_ndp_j[i].since) g_ndp_j[i].since = now | 1;
    return now - g_ndp_j[i].since > 5000;   /* still not loaded after 5 s: request anyway (the guard drops it) */
}
/* joiner, after the puppet's beautifier update: request the host's ids on layers that differ */
static void nms_apply(unsigned long long id, BYTE *obj, const unsigned *v)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    typedef void (__attribute__((thiscall)) *req_t)(void *ac, int ms, int layer, int flag, float blend);
    const int *cur = (const int *)((const BYTE *)v - 0x10 + 0x220);
    BYTE *ac;
    int i, l;
    if (!g_nmssync) return;
    { static LONG last; static DWORD t; DWORD now = GetTickCount();
      if (g_ms_skips != last && now - t > 5000) { logf_("ms guard: %ld requests skipped (no clip loaded)", g_ms_skips); last = g_ms_skips; t = now; } }
    for (i = 0; i < 128 && g_nms_j[i].id != id; i++) ;
    if (i == 128 || !g_nms_j[i].ok) return;
    if (!(ac = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDF190)))) return;
    if (!dep_apply(id, obj, GetTickCount())) return;
    /* layer 2 holds the props' gestures (beer, cigarette: 58x); before NDP1 a puppet asked for one crashed in the
     * layer update right after (Dunia+286F82), like the relayed layered STP before: nmslayers 2 leaves it out */
    for (l = 0; l < g_nmslayers; l++)
        /* once per host change: asked again every frame, a layer the puppet resets itself (layer 2 went back to -1
         * each frame) left its node pointer bad (Dunia+CF7D63, read of 2) */
        if (cur[l] != g_nms_j[i].ms[l] && (g_nms_j[i].done[l] != g_nms_j[i].ms[l] ||
            (g_nms_j[i].tries[l] < 3 && GetTickCount() - g_nms_j[i].at[l] > 1000))) {
            g_nms_j[i].tries[l] = g_nms_j[i].done[l] != g_nms_j[i].ms[l] ? 0 : g_nms_j[i].tries[l] + 1;
            g_nms_j[i].done[l] = g_nms_j[i].ms[l]; g_nms_j[i].at[l] = GetTickCount();
            if (++g_nms_set <= 300 || g_mslog) logf_("nms: puppet %llu layer %d: %x -> host's %x", id, l, cur[l], g_nms_j[i].ms[l]);
            ((req_t)(g_base + 0x51F500))(ac, g_nms_j[i].ms[l], l, 0, 0.0f);
        }
}
/* a layer whose move state has no animation loaded here (the host's AI streamed it in for the NPC, the puppet's did
 * not): FUN_10284770 asks both of its blend nodes for it (vf+0x80) and passed null on to FUN_10282d10 (Dunia+282D52,
 * read of 0). Patched at 102848F0: when the second one is null too, it leaves the way it does when vf+0x64 fails
 * (10284BC1), so the layer just does not play that request. */
static void ms_guard_install(void)
{
    static const BYTE orig[10] = { 0x8B, 0x82, 0x88, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0xEB, 0x07 };
    BYTE *at = g_base + 0x2848F0, *c;
    DWORD old;
    if (memcmp(at, orig, sizeof orig)) { logf_("ms guard: unexpected bytes at 2848F0"); return; }
    c = (BYTE *)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(c, orig, 8);                                           /* mov eax,[edx+88h]; call eax (st0 = float) */
    memcpy(c + 8, "\x83\xBC\x24\x94\x00\x00\x00\x00", 8);          /* cmp dword [esp+94h],0 */
    c[16] = 0x74; c[17] = 5;                                      /* je +5 */
    c[18] = 0xE9; *(DWORD *)(c + 19) = (DWORD)(g_base + 0x284901) - (DWORD)(c + 23);
    c[23] = 0xFF; c[24] = 0x05; *(DWORD *)(c + 25) = (DWORD)&g_ms_skips;   /* inc dword [g_ms_skips] */
    c[29] = 0xDD; c[30] = 0xD8;                                   /* fstp st(0) */
    c[31] = 0xE9; *(DWORD *)(c + 32) = (DWORD)(g_base + 0x284BC1) - (DWORD)(c + 36);
    VirtualProtect(at, 10, PAGE_EXECUTE_READWRITE, &old);
    at[0] = 0xE9; *(DWORD *)(at + 1) = (DWORD)c - (DWORD)(at + 5);
    memset(at + 5, 0x90, 5);
    VirtualProtect(at, 10, old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, 10);
    logf_("ms guard: missing layer animation no longer crashes (2848F0)");
}
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
    if (g_npc_role != 1 || g_ns == INVALID_SOCKET || !player_ready(g_net_id)) return;
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
    /* 5 states a second (was 10): with the animation and weapon messages the host sent ~75 datagrams a second, and the
     * Steam link broke after 15-20 s twice; NetPlayer smooths between states */
    if (now - last_send < 200) return;
    last_send = now;
    memset(&pk, 0, sizeof pk);
    for (i = 0; i < g_nh_n; i++) {
        typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
        void *hd = NULL, *pawn;
        BYTE *obj = entity_obj(g_nh[i].id, &hd), *m;
        NpcEnt *e = &pk.e[n];
        int k;
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!obj) { g_nh[i].obj = NULL; continue; }   /* gone from the world: never use the old pointer again */
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
        if (!enc_safe(g_npc_this, m, g_nh[i].id)) continue;
        e->id = g_nh[i].id;
        memcpy(e->pos, obj + 0x60, sizeof e->pos);
        for (k = 0; k < 3; k++) e->vel[k] = *(int *)(m + 0x78 + 0x14 * k);
        e->aim[0] = *(int *)(m + 0xB4); e->aim[1] = *(int *)(m + 0xC8); e->aim[2] = *(int *)(m + 0xDC); e->aim[3] = *(int *)(m + 0xF0);
        /* the encoder leaves the first (look) pair at 0/0 for AI pawns while the second pair holds the body yaw (a doorman
         * facing 1.67 rad stood at 0 on the joiner, the third-person beautifier turns the body to the look pair): the body
         * yaw goes into both; head turns come with the animation graph inputs */
        e->aim[1] = e->aim[3];
        /* aim[0] (always 0 on the puppet) carries the entity's real yaw in milliradians: the encoded yaw is where the
         * NPC looks, walking that is not where its body points (puppets walked up to 100 degrees off) */
        e->aim[0] = (int)(atan2f(*(float *)(obj + 0x34), *(float *)(obj + 0x30)) * 1000.0f);
        e->s104 = m[0x104]; e->s11c = m[0x11C]; e->s110 = m[0x110];
        { BYTE *pd = *(BYTE **)((BYTE *)pawn + 0x10); e->pad = pd ? pd[0x2D0 + 4] & 1 : 0; }
        if (e->s104 && !g_nh[i].lastfire) g_nh[i].fires++;
        g_nh[i].lastfire = e->s104;
        e->hp = npc_hp(obj, &e->hpmax);
        e->pulls = g_nh[i].shots;
        n++;
    }
    if (g_npcanim)
        for (i = 0; i < g_nh_n; i++) {
            NpcAnimPkt a;
            /* the entity is looked up again: a cached pointer of an NPC that had left the world crashed the host in
             * GetComponent (Dunia+0x4ddb8a, read of ffffffff) */
            void *hd2 = NULL;
            BYTE *o2 = entity_obj(g_nh[i].id, &hd2);
            unsigned *v;
            if (hd2) (*(int *)((BYTE *)hd2 + 8))--;
            v = o2 ? npc_animvars(o2) : NULL;
            if (!v || !safe_read(v, a.v, sizeof a.v)) continue;
            ms_watch("host", g_nh[i].id, v);
            nms_host(g_nh[i].id, v, now);
            if (g_nmssync) dep_host(g_nh[i].id, o2, !strncmp(g_nh[i].wname, "weapons.MountedWeapons.", 23), now);
            if (a.v[0x58] != g_nh[i].lastact) {
                logf_("npcact host %llu: action v58 %d -> %d (v42 %u v48 %u v11 %u v12 %u)", g_nh[i].id, (int)g_nh[i].lastact, (int)a.v[0x58], a.v[0x42],
                      a.v[0x48], a.v[0x11], a.v[0x12]);
                g_nh[i].lastact = a.v[0x58];
            }
            /* right away when the action state changes (v58 action, v42 running, v11/v12/v48 calm or alert), otherwise
             * every 2 s. "Only on change" was not enough: during an action the progress variables change every frame,
             * and these datagrams were ~43 of the host's ~67 a second through the relay */
            {
                unsigned key = (a.v[0x58] * 31u + a.v[0x42]) * 31u + ((a.v[0x11] * 31u + a.v[0x12]) * 31u + a.v[0x48]);
                if (key == g_nh[i].animhash && now - g_nh[i].animsent < (g_npcanim == 2 ? 200u : 2000u)) continue;
                g_nh[i].animhash = key; g_nh[i].animsent = now;
            }
            a.magic = NANM_MAGIC; a.id = g_nh[i].id;
            sendto(g_ns, (char *)&a, sizeof a, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
        }
    pk.magic = NPC_MAGIC; pk.seq = ++seq; pk.count = n;
    /* at most 12 NPCs per datagram (~800 bytes): 24 made ~1.5 KB, over one network packet; over the Steam relay both
     * sides then saw the other leave the lobby 16 s into the session */
    for (i = 0; i < n; i += 12) {
        NpcPkt part;
        int c = n - i < 12 ? n - i : 12;
        part.magic = NPC_MAGIC; part.seq = pk.seq; part.count = c;
        memcpy(part.e, pk.e + i, c * sizeof(NpcEnt));
        sendto(g_ns, (char *)&part, 12 + c * sizeof(NpcEnt), 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    }
}
static unsigned g_np_hostcount;
static DWORD g_np_first;
static void npc_rx(const NpcPkt *pk, int len)
{
    unsigned i;
    int j;
    if (g_npc_role != 2 || len < 12 || pk->count > NPC_MAX || len < (int)(12 + pk->count * sizeof(NpcEnt))) return;
    g_np_hostcount = pk->count;
    if (!g_np_first) g_np_first = GetTickCount() | 1;
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
/* facing: the host entity's yaw arrives in NpcEnt aim[0] (milliradians), but
 * nothing turns a puppet to it: NetPlayer does not rotate the body, clips do (root motion, turn on the spot), so
 * puppets stood 15-160 degrees off. While the host NPC stands, after the puppet's update its actual yaw (whatever the
 * clip made of it) is turned towards the host's, rate limited, with a dead zone. Overwriting the matrix with a yaw of
 * our own every frame fought the clips: puppets twitched (owner). Walking is left alone: a correction there is undone
 * by the next frame (a walking puppet holds a steady ~54 degrees off the host, in any direction; not understood) and
 * only makes the walk jerky. npcface 0 turns it off. */
static int g_npcface = 1;
static DWORD g_np_ft[NPC_MAX];
/* the host NPC stands: its synced velocity (memento +0x70 / +0x84) under 0.25 m/s */
static int npc_standing(int j)
{
    BYTE *m = g_np[j].mem;
    float vx, vy;
    if (!m || IsBadReadPtr(m + 0x70, 0x28)) return 0;
    vx = np_dq(m + 0x70, 15); vy = np_dq(m + 0x84, 15);
    return vx * vx + vy * vy < 0.25f * 0.25f;
}
/* heading of a puppet: FUN_100ab3d0 takes it from the velocity with bit 0 of the state flags (pawn data +0x140 / +0x2D0,
 * +4) clear, else from the aim point plus the weapon's offset (weapon +0xAC). NetPlayer's applier always sets the bit
 * (a remote player aims); AI NPCs walking do not have it (02, puppets 03), so puppets walked ~54 degrees off, sometimes
 * backwards. Before the beautifier update both flags get the host NPC's bit 0 (NpcEnt pad). Measured on A/B, forward
 * against velocity: 55 of 60 samples at -60 degrees, cleared 53 of 57 at 0. npcflag 0 turns it off. */
static int g_npcflag = 1;
static void npc_flags_pre(BYTE *mb)
{
    int j;
    if (g_npc_role != 2 || !g_npcflag) return;
    for (j = 0; j < g_np_n; j++) if (g_np[j].mb == mb) {
        BYTE *pc = *(BYTE **)(mb + 0x10);
        pc = pc ? *(BYTE **)(pc + 0x10) : NULL;        /* pawn comp +0x10 = pawn data */
        if (pc) {
            BYTE b = g_np[j].e.pad & 1;
            pc[0x140 + 4] = (BYTE)((pc[0x140 + 4] & ~1) | b);
            pc[0x2D0 + 4] = (BYTE)((pc[0x2D0 + 4] & ~1) | b);
        }
        return;
    }
}
/* wbp <n> (RE): hardware write breakpoint on row 0 of a walking puppet's matrix on all threads; the next n writes are
 * logged with the writer's address. Set from an exception on our thread, by suspending the others. */
static volatile LONG g_wbp_hits;
static LONG g_wbp_read, g_wbp_max;
static DWORD g_wbp_addr;
static struct { DWORD eip, tid, sp[32]; float v; } g_wbp_ring[64];
static LONG WINAPI wbp_veh(EXCEPTION_POINTERS *ep)
{
    CONTEXT *c = ep->ContextRecord;
    if (ep->ExceptionRecord->ExceptionCode == 0xE0C0DE01u) {
        c->Dr0 = g_wbp_addr; c->Dr7 = g_wbp_addr ? 0xD0001 : 0; c->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP && (c->Dr6 & 1)) {
        LONG i = InterlockedIncrement(&g_wbp_hits) - 1;
        c->Dr6 = 0;
        if (i < 64) {
            int k;
            g_wbp_ring[i].eip = c->Eip; g_wbp_ring[i].tid = GetCurrentThreadId(); g_wbp_ring[i].v = *(float *)g_wbp_addr;
            for (k = 0; k < 32; k++) g_wbp_ring[i].sp[k] = IsBadReadPtr((DWORD *)c->Esp + k, 4) ? 0 : ((DWORD *)c->Esp)[k];
        }
        if (i + 1 >= g_wbp_max) c->Dr7 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static void wbp_set(DWORD addr)
{
    static int veh;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
    int n = 0;
    if (!veh) { veh = 1; AddVectoredExceptionHandler(1, wbp_veh); }
    g_wbp_addr = addr;
    te.dwSize = sizeof te;
    if (snap != INVALID_HANDLE_VALUE) {
        if (Thread32First(snap, &te)) do {
            if (te.th32OwnerProcessID == pid && te.th32ThreadID != me) {
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (h) {
                    CONTEXT c;
                    SuspendThread(h);
                    memset(&c, 0, sizeof c); c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(h, &c)) { c.Dr0 = addr; c.Dr7 = addr ? 0xD0001 : 0; c.Dr6 = 0; if (SetThreadContext(h, &c)) n++; }
                    ResumeThread(h); CloseHandle(h);
                }
            }
        } while (Thread32Next(snap, &te));
        CloseHandle(snap);
    }
    RaiseException(0xE0C0DE01u, 0, 0, NULL);
    logf_("wbp: %s %08lx on %d other threads", addr ? "set on" : "cleared", (unsigned long)addr, n);
}
static void wbp_start(int n)
{
    int j;
    for (j = 0; j < g_np_n; j++) if (g_np[j].obj && g_np[j].mem && !npc_standing(j) && g_np[j].state) {
        g_wbp_hits = 0; g_wbp_read = 0; g_wbp_max = n > 64 ? 64 : n;
        logf_("wbp: puppet %llu", g_np[j].id);
        wbp_set((DWORD)(g_np[j].obj + 0x30));
        return;
    }
    logf_("wbp: no walking puppet now");
}
static void wbp_tick(void)
{
    LONG w = g_wbp_hits;
    if (w > 64) w = 64;
    for (; g_wbp_read < w; g_wbp_read++) {
        char s[300]; int k, o = 0;
        DWORD *q = g_wbp_ring[g_wbp_read].sp;
        for (k = 0; k < 32; k++) if (q[k] > (DWORD)g_base + 0x1000 && q[k] < (DWORD)g_base + 0xE00000) o += snprintf(s + o, sizeof s - o, " %lx", (unsigned long)(q[k] - (DWORD)g_base));
        s[o] = 0;
        logf_("wbp hit: T%lu eip %s%lx row0x %.3f, stack%s", (unsigned long)g_wbp_ring[g_wbp_read].tid, g_wbp_ring[g_wbp_read].eip > (DWORD)g_base && g_wbp_ring[g_wbp_read].eip < (DWORD)g_base + 0xE00000 ? "D+" : "abs ",
              (unsigned long)(g_wbp_ring[g_wbp_read].eip > (DWORD)g_base && g_wbp_ring[g_wbp_read].eip < (DWORD)g_base + 0xE00000 ? g_wbp_ring[g_wbp_read].eip - (DWORD)g_base : g_wbp_ring[g_wbp_read].eip), g_wbp_ring[g_wbp_read].v, s);
    }
    if (g_wbp_addr && g_wbp_hits >= g_wbp_max) wbp_set(0);
}
static void npc_face(int j, BYTE *obj)
{
    BYTE *m = g_np[j].mem;
    DWORD now = GetTickCount(), ms = now - g_np_ft[j];
    float err, step, a, dt, *r;
    g_np_ft[j] = now;
    if (g_npcface == 2 && m && !npc_standing(j)) {
        static DWORD tl;
        if (now - tl > 500) {
            float vd = atan2f(np_dq(m + 0x84, 15), np_dq(m + 0x70, 15)) * 57.3f, pd = atan2f(*(float *)(obj + 0x34), *(float *)(obj + 0x30)) * 57.3f + 90.0f, off = pd - vd;
            while (off > 180) off -= 360;
            while (off < -180) off += 360;
            tl = now;
            { BYTE *pc = ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
            pc = pc && !IsBadReadPtr(pc + 0x10, 4) ? *(BYTE **)(pc + 0x10) : NULL;
            logf_("facew %llu: forward vs velocity %.0f (host forward vs velocity %.0f) D %08x S %08x", g_np[j].id, off, remainderf(g_np[j].e.aim[0] * 0.0573f + 90.0f - vd, 360.0f),
                  pc ? *(unsigned *)(pc + 0x144) : 0, pc ? *(unsigned *)(pc + 0x2D4) : 0); }
        }
    }
    if (!g_npcface || !m || !npc_standing(j) || IsBadWritePtr(obj + 0x30, 0x30)) return;
    r = (float *)(obj + 0x30);
    a = atan2f(r[1], r[0]);
    err = g_np[j].e.aim[0] * 0.001f - a;
    while (err > 3.14159265f) err -= 6.2831853f;
    while (err < -3.14159265f) err += 6.2831853f;
    if (fabsf(err) < 0.05f) return;                      /* ~3 degrees */
    dt = (ms > 100 ? 100 : ms) * 0.001f;
    step = (fabsf(err) > 1.5f ? 6.0f : 3.0f) * dt;       /* rad/s: a late turn catches up, a small error eases out */
    if (fabsf(err) < step) step = fabsf(err);
    a += err < 0 ? -step : step;
    r[0] = cosf(a); r[1] = sinf(a); r[2] = 0;
    r[4] = -r[1]; r[5] = r[0]; r[6] = 0;
    r[8] = 0; r[9] = 0; r[10] = 1;
}
/* called after a remote-driven main beautifier's update (mf_call) */
static void npc_anim_apply(BYTE *mb)
{
    static unsigned char own[NANM_VARS], move[NANM_VARS];
    static const unsigned char movev[8] = { 0x00, 0x01, 0x02, 0x0b, 0x1d, 0x34, 0x38, 0x5f };
    static int init;
    unsigned *v;
    int j, k;
    if (g_npc_role != 2 || !g_npcanim) return;
    if (!init) { for (k = 0; k < (int)sizeof g_anim_own; k++) own[g_anim_own[k]] = 1; for (k = 0; k < 8; k++) move[movev[k]] = 1; init = 1; }
    for (j = 0; j < g_np_n; j++)
        if (g_np[j].mb == mb) {
            void *hd3 = NULL;
            BYTE *o3 = entity_obj(g_np[j].lid ? g_np[j].lid : g_np[j].id, &hd3);
            if (hd3) (*(int *)((BYTE *)hd3 + 8))--;
            if (o3 != g_np[j].obj) return;   /* the puppet left the world: its cached entity pointer is stale */
            if ((v = npc_animvars(o3))) { nms_apply(g_np[j].id, o3, v); ms_watch("puppet", g_np[j].id, v); }
            npc_face(j, o3);
            if (g_np_react[j] && (int)(g_np_react[j] - GetTickCount()) > 0) return;
            if (g_np[j].avok && (v = npc_animvars(o3))) {
                if (!g_np[j].lastact && !g_np[j].lid && (v[0x58] != g_np[j].av[0x58] || v[0x42] != g_np[j].av[0x42])) g_np[j].ownact = 1;
                if (g_np[j].av[0x58] != g_np[j].lastact) {
                    logf_("npcact puppet %llu: host action %d -> %d, puppet graph had %d (v42 %u -> %u)", g_np[j].id, (int)g_np[j].lastact,
                          (int)g_np[j].av[0x58], (int)v[0x58], v[0x42], g_np[j].av[0x42]);
                    g_np[j].lastact = g_np[j].av[0x58];
                }
                /* npcanim 2: also the 15 of those 23 that hold the pose (the MP beautifier keeps puppets combat-ready,
                 * owner: host NPCs calm, puppets weapon up); the 8 that change every frame with the movement stay the
                 * puppet's own (all 23 from the host: puppets walked on the spot) */
                for (k = 0; k < NANM_VARS; k++) if (!own[k] || (g_npcanim == 2 && !move[k])) v[k] = g_np[j].av[k];
                /* while the host NPC stands, its speed / turn inputs too: the puppet's own (v00 2.4 -> 0 while it caught
                 * up with the host position) made it step on the spot */
                if (g_npcface && npc_standing(j)) { v[0x00] = g_np[j].av[0x00]; v[0x01] = g_np[j].av[0x01]; v[0x02] = g_np[j].av[0x02]; }
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
    if (ndp_mounted(g_np[j].id)) return;   /* at the host's gun: the gun is its weapon (NDP1 mount) */
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
    if (id == g_net_id || id == g_av_id || g_nr_n >= 32) return;
    for (j = 0; j < g_np_n; j++) if (g_np[j].lid == id || g_np[j].id == id) return;
    for (j = 0; j < g_nkeep_n; j++) if (g_nkeep[j] == id) return;
    if (!(id >> 63)) {
        /* a save NPC within 60 m of us that the host has not reported 10 s into the session: dead or gone on the host
         * (the joiner loaded an older save) - unless the host's list was full */
        void *hd = NULL;
        BYTE *me;
        float dx, dy;
        if (!g_np_first || GetTickCount() - g_np_first < 10000 || g_np_hostcount >= NPC_MAX) return;
        me = entity_obj(g_net_id, &hd);
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!me) return;
        dx = *(float *)(obj + 0x60) - *(float *)(me + 0x60); dy = *(float *)(obj + 0x64) - *(float *)(me + 0x64);
        if (dx * dx + dy * dy > 60.0f * 60.0f) return;
    }
    g_nr[g_nr_n++] = id;
}
/* The joiner's reinforcement manager (singleton [11655274], ticked from the AI world at 95FBEF) kept creating squads:
 * it fills free places up to its limits (FUN_1092ac90: 20 infantry, 5 vehicles), so every RemoveEntity below made
 * room for the next squad. On A/B 606 NPCs in 5 min were spawned, shot at the player for up to 4 s and were removed,
 * which is what "NPCs vanish while shooting" was. The joiner's world must not decide this at all (the host's
 * reinforcements arrive as NREQ/NARC puppets through SpawnEntityFromArchetype, a separate path), so its tick returns at
 * once and the capacity check always says no (both are called only for AI spawning; the check's callers skip the
 * spawn and release their references normally). */
static void reinf_tick(void)
{
    static const BYTE t0[3] = { 0x55, 0x8B, 0xEC }, c0[5] = { 0x8B, 0x44, 0x24, 0x08, 0x85 };
    static const BYTE t1[3] = { 0xC2, 0x04, 0x00 }, c1[5] = { 0x33, 0xC0, 0xC2, 0x08, 0x00 };
    static int state;                /* 0 not applied, 1 applied, -1 unexpected bytes */
    BYTE *t = g_base + 0x92E0B0, *c = g_base + 0x92AC90;
    DWORD o1, o2;
    int want = g_reinfblock != 0;
    if (state < 0 || state == want) return;
    if (memcmp(t, want ? t0 : t1, 3) || memcmp(c, want ? c0 : c1, 5)) { state = -1; logf_("reinforcements: unexpected code at 92E0B0 / 92AC90, not patched"); return; }
    VirtualProtect(t, 3, PAGE_EXECUTE_READWRITE, &o1); VirtualProtect(c, 5, PAGE_EXECUTE_READWRITE, &o2);
    memcpy(t, want ? t1 : t0, 3); memcpy(c, want ? c1 : c0, 5);
    VirtualProtect(t, 3, o1, &o1); VirtualProtect(c, 5, o2, &o2);
    FlushInstructionCache(GetCurrentProcess(), t, 3); FlushInstructionCache(GetCurrentProcess(), c, 5);
    state = want;
    logf_("reinforcements: the joiner's own spawning is %s", want ? "off (the host decides)" : "on");
}
/* npcdiff 1: one line a second per live puppet: how far it is from the host's NPC, and which move state each has */
static void npc_diff(int j, BYTE *obj, DWORD now)
{
    static DWORD t[NPC_MAX];
    const NpcEnt *e = &g_np[j].e;
    const BYTE *m = g_np[j].mem;
    float dx, dy, dz, a, err, vx, vy;
    const int *ms = NULL;
    unsigned *v;
    int i;
    if (!g_npcdiff || e->hp <= 0 || now - t[j] < 1000) return;
    t[j] = now;
    dx = *(float *)(obj + 0x60) - e->pos[0]; dy = *(float *)(obj + 0x64) - e->pos[1]; dz = *(float *)(obj + 0x68) - e->pos[2];
    a = atan2f(*(float *)(obj + 0x34), *(float *)(obj + 0x30));
    err = e->aim[0] * 0.001f - a;
    while (err > 3.14159265f) err -= 6.2831853f;
    while (err < -3.14159265f) err += 6.2831853f;
    vx = np_dq((BYTE *)m + 0x70, 15); vy = np_dq((BYTE *)m + 0x84, 15);
    if ((v = npc_animvars(obj))) ms = (const int *)((const BYTE *)v - 0x10 + 0x220);
    for (i = 0; i < 128 && g_nms_j[i].id != g_np[j].id; i++) ;
    logf_("npcdiff %llu: off %.2f m (z %+.2f), yaw %+.0f, host speed %.1f, flag %d, layer0 here %x host %x, age %lu ms, hp %.0f",
          g_np[j].id, sqrtf(dx * dx + dy * dy), dz, err * 57.3f, sqrtf(vx * vx + vy * vy), e->pad & 1, ms ? ms[0] : -1,
          i < 128 ? g_nms_j[i].ms[0] : -1, (unsigned long)(now - g_np[j].last), e->hp);
}
static void npc_join_tick(DWORD now)
{
    wbp_tick();
    static DWORD last_find;
    static int need_agent;
    int j, k;
    if (g_npc_role != 2) return;
    reinf_tick();
    static IncScan js;
    /* an NPC we just spawned for the host runs its own AI until the scan has found its agent: don't wait 3 s for that */
    if (!js.busy && now - last_find > (need_agent ? 300u : 3000u)) { g_nr_n = 0; last_find = now; need_agent = 0; npc_scan_step(&js, 0, npc_join_local_cb, NULL); }
    if (js.busy && npc_scan_step(&js, 16u << 20, npc_join_local_cb, NULL)) {
        last_find = now;
        for (k = 0; k < g_nr_n; k++) {
            char code[120], name[96];
            snprintf(code, sizeof code, "__out = tostring(GetEntityName('%llu'))", g_nr[k]);
            lua_eval(code, name, sizeof name);
            if (!strncmp(name, "buddies.", 8) || !strncmp(name, "player.", 7)) { if (g_nkeep_n < 32) g_nkeep[g_nkeep_n++] = g_nr[k]; continue; }
            {
                void *hd = NULL;
                BYTE *o = entity_obj(g_nr[k], &hd);
                float p[3] = { 0, 0, 0 };
                char o2[16];
                if (hd) (*(int *)((BYTE *)hd + 8))--;
                if (o) memcpy(p, o + 0x60, sizeof p);
                snprintf(code, sizeof code, "RemoveEntity('%llu')", g_nr[k]);
                lua_eval(code, o2, sizeof o2);
                logf_("npcsync join: removed our own NPC %llu (%s) at (%.0f %.0f %.0f) - %s", g_nr[k], name, p[0], p[1], p[2], (g_nr[k] >> 63) ? "the host runs NPCs" : "not on the host (dead or gone there)");
            }
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
            /* only NPCs spawned during play (ids with the high bit): a save NPC can simply not be streamed in yet, and
             * spawning one made a second copy next to the original */
            if (g_np[j].state == 0 && (g_np[j].id >> 63) && !g_np[j].lid && !g_np[j].nospawn && e->hp > 0 && now - g_np[j].req > 3000 && g_ns != INVALID_SOCKET) {
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
            if (!g_np[j].agent) { need_agent = 1; continue; }
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
        npc_diff(j, obj, now);
        npc_weap_watch("puppet", g_np[j].id, obj, &g_np[j].wcur, &g_np[j].wmode, g_np[j].wname, &g_np[j].wcat);
        npc_weap_fix(j, obj, now);
        {
            BYTE *pwc = ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
            g_np_drv[j] = pwc ? ((void *(__attribute__((thiscall)) *)(void *))(*(void ***)pwc)[0x78 / 4])(pwc) : NULL;
        }
        if (g_nmssync) mount_tick(g_np[j].id, g_np[j].lid ? g_np[j].lid : g_np[j].id, obj, now);
        np_pos(m + 4, e->pos);
        for (k = 0; k < 3; k++) { *(int *)(m + 0x78 + 0x14 * k) = e->vel[k]; m[0x74 + 0x14 * k] = 1; }
        {
            /* height: NetPlayer corrects position errors only above 1.5 m and a puppet's controller keeps the packet's
             * z velocity (0 standing), so a puppet that got lifted (onto a crate) stayed in the air (+1.4 m measured).
             * The error goes into the z velocity. */
            float ez = e->pos[2] - *(float *)(obj + 0x68);
            unsigned bits = *(unsigned *)(m + 0x98 + 0x10);
            if (g_npcz && e->hp > 0 && fabsf(ez) > 0.15f && bits && bits < 31) {
                float vz = ez * 3.0f;
                if (vz > 3.0f) vz = 3.0f; if (vz < -3.0f) vz = -3.0f;
                *(int *)(m + 0xA0) = e->vel[2] + (int)(vz * ((1u << bits) - 1) / 15.0f);
                /* real floating only: above a standing host by 0.35 m, or 1 m off, for 0.5 s. A running NPC's height from
                 * 5 packets a second lags on slopes by that much all the time (96 snaps in 20 s: a twitch of its own) */
                if (!((ez < -0.35f && npc_standing(j)) || fabsf(ez) > 1.0f)) g_npcz_t[j] = 0;
                else if (!g_npcz_t[j]) g_npcz_t[j] = now | 1;
                if (g_npcz_t[j] && now - g_npcz_t[j] > 500) {
                    g_npcz_t[j] = 0;
                    /* the velocity does not always win: a standing puppet was seen rising at 0.1 m/s against it, up to
                     * NetPlayer's teleport at 5 m (owner: floating in the air). Same call as that teleport, sooner */
                    /* through the entity: g_np[j].mb goes stale when a dying NPC changes beautifier (crash on B, D+.. P+e14c) */
                    BYTE *pd2 = ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C));
                    pd2 = pd2 && !IsBadReadPtr(pd2 + 0x10, 4) ? *(BYTE **)(pd2 + 0x10) : NULL;
                    if (pd2 && IsBadReadPtr(pd2 + 0x2D0, 0xC0)) pd2 = NULL;
                    g_npcz_snaps++;
                    if (now - g_npcz_log > 2000) {
                        g_npcz_log = now;
                        logf_("npcz: puppet %llu %.2f m off the host's height (%.2f, host %.2f), snap %u; vz desired %.2f actual %.2f, sent %.2f", g_np[j].id, -ez, *(float *)(obj + 0x68), e->pos[2], g_npcz_snaps,
                              pd2 ? *(float *)(pd2 + 0x140 + 0xB8) : 0, pd2 ? *(float *)(pd2 + 0x2D0 + 0xB8) : 0, np_dq(m + 0x98, 15));
                    }
                    ((void (__attribute__((thiscall)) *)(void *, float, float, float))(g_base + 0x4E01B0))(obj, *(float *)(obj + 0x60), *(float *)(obj + 0x64), e->pos[2]);
                }
            }
        }
        { static const int aimf[4] = { 0xAC, 0xC0, 0xD4, 0xE8 }; for (k = 0; k < 4; k++) { *(int *)(m + aimf[k] + 8) = k ? e->aim[k] : 0; m[aimf[k] + 4] = 1; } }
        m[0x104] = e->s104; m[0x100] = 1; m[0x11C] = e->s11c; m[0x118] = 1; m[0x110] = e->s110; m[0x10C] = 1;
        if (e->hp >= 0) { *(float *)(m + 0x13C) = e->hp; m[0x134] = 1; }
    }
}

/* ---- the avatar as a second player (RE). The player manager [11645578] (vtable E6CC68): +4 array of players, +8
 * count, +0xC capacity (64). A player is 8 bytes {vtable E6CF9C, view}; the view (vtable E6CF7C, ctor 4FEC50) holds the
 * player's entity handle at +8 (FUN_105d9910) and its camera: +0x18 position, +0x30 near / +0x34 far, +0x38.. fov,
 * +0x58 forward, +0x64 up, +0x70 right, +0x7C pitch, +0x80 roll, +0x84 yaw. AI code asks the manager "the player of
 * this entity id" (FUN_104f3430, 0 if none) and "player #i" (FUN_104f3550; the NPC push handler 973C60 uses #0).
 * plyadd puts the avatar in the list as player #1: that broke the host's mouse look (input runs for every player), so
 * plyfind 1 instead only makes the id lookup answer the fake player. The game does not update the fake view:
 * ply_tick writes the avatar's camera from its memento aim every frame. ---- */
static BYTE *g_ply_p, *g_ply_v;
static int g_ply_on;                 /* the fake player is in the manager's list (plyadd) */
static unsigned long long g_ply_for;
static BYTE **ply_arr(void)
{
    BYTE *mgr = *(BYTE **)(g_base + 0x1645578);
    return mgr && !IsBadReadPtr(mgr, 0x10) && *(unsigned *)(mgr + 8) ? *(BYTE ***)(mgr + 4) : NULL;
}
/* build the fake player {vtable E6CF9C, view copied from ours with the avatar's handle at +8}; 0 without an avatar */
static int ply_prepare(void)
{
    BYTE **arr = ply_arr(), *ao, *v0;
    void *hd = NULL;
    if (g_ply_v && g_ply_for == g_av_id) return 1;
    ao = arr && g_av_id ? entity_obj(g_av_id, &hd) : NULL;
    if (!ao || !hd) return 0;
    v0 = *(BYTE **)(arr[0] + 4);
    if (!g_ply_v) { g_ply_v = (BYTE *)calloc(1, 0x400); g_ply_p = (BYTE *)calloc(1, 16); }
    memcpy(g_ply_v, v0, 0x200);
    *(void **)(g_ply_v + 8) = hd;            /* keeps the reference entity_obj took */
    *(void **)g_ply_p = *(void **)arr[0]; *(BYTE **)(g_ply_p + 4) = g_ply_v;
    g_ply_for = g_av_id;
    logf_("ply: fake player %p (view %p copied from %p) for avatar %llu, holder %p", g_ply_p, g_ply_v, v0, g_av_id, hd);
    return 1;
}
static void ply_add(void)
{
    BYTE *mgr = *(BYTE **)(g_base + 0x1645578), **arr = ply_arr();
    if (g_ply_on) { logf_("plyadd: already in"); return; }
    if (!arr || *(unsigned *)(mgr + 8) != 1) { logf_("plyadd: no player manager or not one player"); return; }
    if (!ply_prepare()) { logf_("plyadd: no avatar"); return; }
    arr[1] = g_ply_p; *(unsigned *)(mgr + 8) = 2; g_ply_on = 1;
    logf_("plyadd: avatar %llu is player #1", g_av_id);
}
static void ply_del(const char *why)
{
    BYTE *mgr = *(BYTE **)(g_base + 0x1645578), **arr = ply_arr();
    if (!g_ply_on) return;
    if (arr && *(unsigned *)(mgr + 8) == 2 && arr[1] == g_ply_p) { *(unsigned *)(mgr + 8) = 1; arr[1] = NULL; }
    g_ply_on = 0;
    logf_("plydel (%s): the avatar is no player any more", why);
}
static void ply_show(void)
{
    BYTE *mgr = *(BYTE **)(g_base + 0x1645578), **arr = ply_arr();
    unsigned i, cnt = arr ? *(unsigned *)(mgr + 8) : 0;
    logf_("plyshow: %u players, fake %p view %p", cnt, g_ply_p, g_ply_v);
    for (i = 0; i < cnt && i < 4; i++) { logf_("player #%u %p view %p", i, arr[i], *(BYTE **)(arr[i] + 4)); hexdump_(*(BYTE **)(arr[i] + 4), 0x90); }
    if (g_ply_v && !g_ply_on) hexdump_(g_ply_v, 0x90);
}
static void ply_tick(void)
{
    void *hd = NULL;
    BYTE *ao, *v;
    float pitch, yaw, sp, cp, sy, cy;
    if (!g_ply_on && !g_plyfind) return;
    if (!g_av_mem || !ply_prepare()) return;
    v = g_ply_v;
    ao = entity_obj(g_av_id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!ao) return;
    pitch = np_dq(g_av_mem + 0xAC, 360); yaw = np_dq(g_av_mem + 0xC0, 360);
    sp = sinf(pitch); cp = cosf(pitch); sy = sinf(yaw); cy = cosf(yaw);
    *(float *)(v + 0x18) = *(float *)(ao + 0x60); *(float *)(v + 0x1C) = *(float *)(ao + 0x64); *(float *)(v + 0x20) = *(float *)(ao + 0x68) + 1.65f;
    *(float *)(v + 0x58) = -sy * cp; *(float *)(v + 0x5C) = cy * cp; *(float *)(v + 0x60) = sp;
    *(float *)(v + 0x64) = sy * sp;  *(float *)(v + 0x68) = -cy * sp; *(float *)(v + 0x6C) = cp;
    *(float *)(v + 0x70) = cy;       *(float *)(v + 0x74) = sy;       *(float *)(v + 0x78) = 0;
    *(float *)(v + 0x7C) = pitch;    *(float *)(v + 0x80) = 0;        *(float *)(v + 0x84) = yaw;
}
/* who asks the player manager: callers of FUN_104f3430 / FUN_104f3550 are counted (plycallers prints and resets) */
static void *g_pfind_orig, *g_pidx_orig;
static struct { volatile LONG rva, n; } g_pcall[2][128];
static void ply_count(int k, unsigned rva)
{
    int i;
    for (i = 0; i < 128; i++) {
        if (g_pcall[k][i].rva == (LONG)rva) { InterlockedIncrement(&g_pcall[k][i].n); return; }
        if (!g_pcall[k][i].rva && InterlockedCompareExchange(&g_pcall[k][i].rva, (LONG)rva, 0) == 0) { InterlockedIncrement(&g_pcall[k][i].n); return; }
        if (g_pcall[k][i].rva == (LONG)rva) { InterlockedIncrement(&g_pcall[k][i].n); return; }
    }
}
static void *__attribute__((thiscall)) pfind_hook(void *mgr, unsigned lo, unsigned hi)
{
    void *r = ((void *(__attribute__((thiscall)) *)(void *, unsigned, unsigned))g_pfind_orig)(mgr, lo, hi);
    ply_count(0, (unsigned)__builtin_return_address(0) - (unsigned)g_base);
    if (!r && g_plyfind && g_ply_p && g_ply_for == g_av_id && g_av_id && lo == (unsigned)g_av_id && hi == (unsigned)(g_av_id >> 32)) r = g_ply_p;
    return r;
}
/* NPC AI asks for "player #0" in its behaviour conditions (FUN_10a07220, a switch over condition types) and in its
 * event handler (FUN_10973c60: the shove handler pushes player #0 and sends it player_pushed). While one of them runs
 * (the agent kept in a TLS slot), player #0 is whichever of us and the avatar is nearer to that agent. */
static DWORD g_ai_tls = TLS_OUT_OF_INDEXES;
static void *g_cond_orig, *g_aiev_orig;
static volatile LONG g_ai_swaps, g_ai_asks;
static void *volatile g_ai_vt;     /* agent vtable seen in 973C60: only agents with it get a position query */
static void *__attribute__((thiscall)) pidx_hook(void *mgr, void *out, unsigned i)
{
    BYTE *agent;
    ply_count(1, (unsigned)__builtin_return_address(0) - (unsigned)g_base);
    if (i == 0 && g_plyfind && g_ply_v && g_ply_for == g_av_id && g_ai_tls != TLS_OUT_OF_INDEXES &&
        (agent = (BYTE *)TlsGetValue(g_ai_tls)) && g_ai_vt && *(void **)agent == g_ai_vt && *(BYTE **)(g_ply_v + 8)) {
        BYTE **arr = *(BYTE ***)((BYTE *)mgr + 4), *h0, *o0, *ah = *(BYTE **)(g_ply_v + 8), *ao;
        float buf[16] __attribute__((aligned(16))), *ap;
        InterlockedIncrement(&g_ai_asks);
        h0 = arr && arr[0] ? *(BYTE **)(*(BYTE **)(arr[0] + 4) + 8) : NULL;
        o0 = h0 ? *(BYTE **)(h0 + 0xC) : NULL;
        ao = *(BYTE **)(ah + 0xC);
        ap = ((float *(__attribute__((thiscall)) *)(void *, void *))(*(void ***)agent)[0x78 / 4])(agent, buf);
        if (o0 && ao && ap) {
            float d0 = 0, d1 = 0;
            int k;
            for (k = 0; k < 3; k++) {
                d0 += (*(float *)(o0 + 0x60 + 4 * k) - ap[k]) * (*(float *)(o0 + 0x60 + 4 * k) - ap[k]);
                d1 += (*(float *)(ao + 0x60 + 4 * k) - ap[k]) * (*(float *)(ao + 0x60 + 4 * k) - ap[k]);
            }
            if (d1 < d0) {
                *(BYTE **)out = ah; (*(int *)(ah + 8))++;
                InterlockedIncrement(&g_ai_swaps);
                return out;
            }
        }
    }
    return ((void *(__attribute__((thiscall)) *)(void *, void *, unsigned))g_pidx_orig)(mgr, out, i);
}
static int __attribute__((thiscall)) cond_hook(BYTE *self, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, void *a8)
{
    void *prev = TlsGetValue(g_ai_tls);
    int r;
    {
        static int logged;
        if (!logged && *(BYTE **)(self + 4)) { logged = 1; logf_("ply: condition owner vtable D+%X", **(unsigned **)(self + 4) - (unsigned)g_base); }
    }
    TlsSetValue(g_ai_tls, *(void **)(self + 4));
    r = ((int (__attribute__((thiscall)) *)(void *, void *, void *, void *, void *, void *, void *, void *))g_cond_orig)(self, a2, a3, a4, a5, a6, a7, a8);
    TlsSetValue(g_ai_tls, prev);
    return r;
}
static void __attribute__((thiscall)) aiev_hook(BYTE *agent, void *ev)
{
    void *prev = TlsGetValue(g_ai_tls);
    if (!g_ai_vt) { g_ai_vt = *(void **)agent; logf_("ply: AI agent vtable D+%X", (unsigned)g_ai_vt - (unsigned)g_base); }
    TlsSetValue(g_ai_tls, agent);
    ((void (__attribute__((thiscall)) *)(void *, void *))g_aiev_orig)(agent, ev);
    TlsSetValue(g_ai_tls, prev);
}
static void ply_install(void)
{
    /* 4F3430: sub esp,8; push ebx; push ebp; mov ebp,ecx; mov eax,[ebp+8] (10 bytes)
     * 4F3550: mov eax,[ecx+8]; mov edx,[esp+8]; cmp edx,eax (9 bytes) */
    static const BYTE p1[10] = { 0x83, 0xEC, 0x08, 0x53, 0x55, 0x8B, 0xE9, 0x8B, 0x45, 0x08 };
    static const BYTE p2[9] = { 0x8B, 0x41, 0x08, 0x8B, 0x54, 0x24, 0x08, 0x3B, 0xD0 };
    if (g_pfind_orig) return;
    if (memcmp(g_base + 0x4F3430, p1, sizeof p1) || memcmp(g_base + 0x4F3550, p2, sizeof p2)) { logf_("ply: unexpected bytes, no player hooks"); g_pfind_orig = (void *)1; return; }
    g_pfind_orig = make_detour(g_base + 0x4F3430, 10, (void *)pfind_hook, 1);
    g_pidx_orig = make_detour(g_base + 0x4F3550, 9, (void *)pidx_hook, 1);
    logf_("ply: player lookup hooks on 4F3430 / 4F3550 installed");
    {
        /* A07220: sub esp,2Ch; mov eax,[esp+30h]; mov eax,[eax] (9 bytes); 973C60: sub esp,45Ch; push ebx/ebp/esi/edi (10) */
        static const BYTE c1[9] = { 0x83, 0xEC, 0x2C, 0x8B, 0x44, 0x24, 0x30, 0x8B, 0x00 };
        static const BYTE c2[10] = { 0x81, 0xEC, 0x5C, 0x04, 0x00, 0x00, 0x53, 0x55, 0x56, 0x57 };
        if (memcmp(g_base + 0xA07220, c1, sizeof c1) || memcmp(g_base + 0x973C60, c2, sizeof c2)) { logf_("ply: unexpected bytes, no AI context hooks"); return; }
        g_ai_tls = TlsAlloc();
        g_cond_orig = make_detour(g_base + 0xA07220, 9, (void *)cond_hook, 1);
        g_aiev_orig = make_detour(g_base + 0x973C60, 10, (void *)aiev_hook, 1);
        logf_("ply: AI context hooks on A07220 / 973C60 installed (tls %lu)", g_ai_tls);
    }
}
static void ply_callers(void)
{
    int k, i;
    for (k = 0; k < 2; k++) {
        char line[1200];
        size_t o = 0;
        line[0] = 0;
        for (i = 0; i < 128 && g_pcall[k][i].rva; i++) {
            if (g_pcall[k][i].n && o < 1100) o += snprintf(line + o, sizeof line - o, " %lX:%ld", (unsigned long)g_pcall[k][i].rva, (long)g_pcall[k][i].n);
            g_pcall[k][i].n = 0;
        }
        logf_("plycallers %s:%s", k ? "index" : "find", line);
    }
    logf_("plycallers: AI asked for player #0 %ld times, got the avatar %ld times", (long)g_ai_asks, (long)g_ai_swaps);
    g_ai_asks = g_ai_swaps = 0;
}

static void av_tick(DWORD now)
{
    av_init_ptr();
    if (g_peer_named && (g_peer_bye || (g_net_rx && now - g_net_lastrx > AV_SILENT_MS))) {
        notice_player(g_peer_nick, L"отключился");
        g_peer_named = 0;
    }
    /* the peer left (BYE1) or has been silent (crash, lost link): its avatar leaves the world too */
    if (g_av_id && (g_peer_bye || (g_net_rx && now - g_net_lastrx > AV_SILENT_MS))) {
        logf_("avatar: the peer %s - removing its avatar", g_peer_bye ? "left" : "is silent");
        av_remove();
    }
    if (g_peer_bye) {
        if ((int)(g_net_lastrx - g_bye_at) < 2000) return;   /* packets of a new session, not the last ones before the bye */
        g_peer_bye = 0;
    }
    if (g_net_rx == 0 || now - g_net_lastrx > 3000) return;
    if (!g_av_id) {
        char code[256], out[64];
        unsigned long long id;
        if (now - g_av_lastspawn < 3000) return;
        /* the joiner loads the host's save and stands where the host stood: an avatar spawned there overlapped a player,
         * and the game pushed that player out to a safe spot far away. The joiner spawns the avatar only after its own
         * placement next to the host; the host only once the peer is more than 1.5 m from its player. */
        if (g_npc_role == 2 && !g_join_tp) return;
        {
            void *hd = NULL;
            BYTE *me = entity_obj(g_net_id, &hd);
            float dx, dy;
            if (hd) (*(int *)((BYTE *)hd + 8))--;
            if (me) {
                dx = g_remote.pos[0] - *(float *)(me + 0x60); dy = g_remote.pos[1] - *(float *)(me + 0x64);
                if (dx * dx + dy * dy < 1.5f * 1.5f) return;
            }
        }
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
    {
        static DWORD gone;
        void *hd = NULL;
        BYTE *o = entity_obj(g_av_id, &hd);
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (o) gone = 0;
        else if (!gone) gone = now | 1;
        else if (now - gone > 1500 && now - g_av_lastspawn > 5000) {
            logf_("avatar %llu is gone from the world (a load?), a new one will be spawned", g_av_id);
            g_av_gone_at = now;
            gone = 0;
            av_forget();
            return;
        }
    }
    {
        /* the avatar walks (NetPlayer), it can't follow a teleport: the host spawned it where the joiner stood after
         * loading the save, the joiner was then moved next to the host (~150 m) and the avatar stayed at the old spot
         * (two-PC test 2026-11-02). More than 30 m from the peer for 2 s: spawn it again where the peer is. */
        static DWORD far_since;
        void *hd = NULL;
        BYTE *o = entity_obj(g_av_id, &hd);
        float dx = 0, dy = 0;
        if (o) { dx = g_remote.pos[0] + g_av_off[0] - *(float *)(o + 0x60); dy = g_remote.pos[1] + g_av_off[1] - *(float *)(o + 0x64); }
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!o || g_av_fake || dx * dx + dy * dy < 30.0f * 30.0f) far_since = 0;
        else if (!far_since) far_since = now | 1;
        else if (now - far_since > 2000 && now - g_av_lastspawn > 5000) {
            logf_("avatar %llu is %.0f m from the peer (a teleport?): spawning it again there", g_av_id, sqrtf(dx * dx + dy * dy));
            far_since = 0;
            av_remove();
            return;
        }
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
        ply_tick();
        /* the peer changed the weapon in its hands: give the avatar the same one (a failed try is retried after 2 s) */
        if (strcmp(g_rx_weap, g_av_weap) && now - g_av_weap_try > 2000) {
            g_av_weap_try = now;
            if (g_av_mapcomp) av_compass(0);   /* the map goes away: remove its GPS */
            /* empty hands, or a stationary gun (weapons.MountedWeapons.*, given as a hand weapon it hung at the avatar's
             * side): holster; using the mounted gun itself is not replicated yet */
            if (!g_rx_weap[0] || !strncmp(g_rx_weap, "weapons.MountedWeapons.", 23)) {
                void *hd = NULL;
                BYTE *ao = entity_obj(g_av_id, &hd);
                if (hd) (*(int *)((BYTE *)hd + 8))--;
                if (ao) pawn_holster(ao);
                logf_("avweapon: peer holds '%s' -> avatar holsters", g_rx_weap);
                strcpy(g_av_weap, g_rx_weap);
                g_av_weap_try = 0;
            }
            else if (av_select_cached(g_rx_weap)) { strcpy(g_av_weap, g_rx_weap); g_av_weap_try = 0; }
            else if (av_give_weapon(g_rx_weap)) {
                strcpy(g_av_weap, g_rx_weap); g_av_weap_try = 0;
                if (g_last_wid) av_cache_weapon(g_rx_weap, g_last_wid);
                if (!strcmp(g_rx_weap, "gadgets.Equipped.Map")) { g_av_mapcomp = g_last_gadget; av_compass(1); }
            }
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

/* the player is really in the world: entity and pawn exist at a real position (both exist at 0,0,0 while the load
 * screen is up) and have for 3 s. Encoding the own player earlier crashed in the ThirdParty encoder (Dunia+0x493bb0,
 * null +0x2C) - after netstart from coop_auto.txt 3 s in, and from start-coop.ps1 1 s after the player id answered. */
static int player_ready(unsigned long long me)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    static DWORD since;
    static unsigned long long who;
    void *hd = NULL;
    BYTE *obj;
    if (!me) return 0;
    if (me != who) { who = me; since = 0; }
    obj = entity_obj(me, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!obj || !((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE39C)) ||
        (*(float *)(obj + 0x60) == 0.0f && *(float *)(obj + 0x64) == 0.0f)) { since = 0; return 0; }
    if (!since) since = GetTickCount() | 1;
    return GetTickCount() - since >= 3000;   /* was 12 s; the encoder calls are guarded now (enc_safe) */
}
/* ---- reload together (RLD1) ----
 * A game over or a load on the host rolls its world back to a save, and the joiner stayed in the old one (NPCs no
 * longer matched). The host sends the save's file name, size and CRC-32 for 6 s after it read it; a joiner holding the
 * same file writes coop_reload.txt (the file name) next to the game and ends its process. start-coop.ps1 sees the file,
 * makes that save the newest and starts the game again, so it loads the host's save and connects as at the first
 * join. A joiner without the same file only logs it (sending the save over the link is not done yet). */
/* BYE1: our game is closing (quit, or ending for a reload): the peer removes our avatar at once. Without it (a crash,
 * a lost link) the avatar goes after AV_SILENT_MS without packets; packets coming back spawn it again. */
#define BYE_MAGIC 0x31455942u
/* NAM1 + UTF-8 Steam name: sent by the relay to its own game every 3 s while the peer is up. The first one of a session
 * shows "Игрок <name> подключается"; a bye or silence then shows "Игрок <name> отключился". */
#define NAM_MAGIC 0x314D414Eu
static void bye_send(void)
{
    unsigned m[4] = { BYE_MAGIC, 0, 0, 0 };
    int i;
    if (g_ns == INVALID_SOCKET) return;
    for (i = 0; i < 3; i++) sendto(g_ns, (char *)m, sizeof m, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    logf_("bye: told the peer we are leaving");
}
#define RLD_MAGIC 0x31444C52u
typedef struct { unsigned magic, seq, size, crc; char name[64]; } RldPkt;
static int file_crc(const wchar_t *path, unsigned *size, unsigned *crc)
{
    static unsigned tab[256];
    BYTE buf[65536];
    DWORD got;
    unsigned c = 0xFFFFFFFFu, n = 0, i, k;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    if (!tab[1]) for (i = 0; i < 256; i++) { unsigned r = i; for (k = 0; k < 8; k++) r = (r >> 1) ^ (0xEDB88320u & (0u - (r & 1))); tab[i] = r; }
    while (ReadFile(f, buf, sizeof buf, &got, NULL) && got) { for (i = 0; i < got; i++) c = tab[(c ^ buf[i]) & 0xFF] ^ (c >> 8); n += got; }
    CloseHandle(f);
    *size = n; *crc = ~c;
    return 1;
}
static void rld_host_tick(DWORD now)
{
    static LONG seen = -1;
    static DWORD since, last, read_at;
    static unsigned sent;
    static RldPkt pk;
    if (g_npc_role != 1 || g_ns == INVALID_SOCKET || g_net_rx == 0) return;
    if (seen < 0) { seen = g_sav_loads; return; }
    /* a save read alone can be the menu's save list; it counts as a load once the world was rebuilt as well (our
     * avatar vanished) within 60 s */
    if (g_sav_loads != seen && !read_at) read_at = now | 1;
    if (read_at && (int)(now - read_at) > 60000) { read_at = 0; seen = g_sav_loads; }   /* signed: read_at is now | 1 */
    if ((read_at && g_av_gone_at && (int)(g_av_gone_at - read_at) >= -1) || g_rld_force) {
        read_at = 0; g_rld_force = 0;
        const wchar_t *b = wcsrchr(g_sav_last, L'\\');
        seen = g_sav_loads; since = now | 1;
        memset(&pk, 0, sizeof pk);
        pk.magic = RLD_MAGIC; pk.seq = now | 1;   /* unique per load: the joiner ignores a number it has handled */
        WideCharToMultiByte(CP_ACP, 0, b ? b + 1 : g_sav_last, -1, pk.name, sizeof pk.name - 1, NULL, NULL);
        logf_("reload: we loaded %s - the joiner reloads it too", pk.name);
    }
    if (!since) return;
    if ((int)(now - since) > 6000) { since = 0; logf_("reload: %u message(s) sent (%s, %u bytes, crc %08x)", sent, pk.name, pk.size, pk.crc); sent = 0; return; }
    if ((int)(now - since) < 1000 || now - last < 500) return;   /* let the game finish reading the file */
    last = now;
    if (!pk.size && !file_crc(g_sav_last, &pk.size, &pk.crc)) { logf_("reload: cannot read %ls", g_sav_last); since = 0; return; }
    if (sendto(g_ns, (char *)&pk, sizeof pk, 0, (struct sockaddr *)&g_peer, sizeof g_peer) == sizeof pk) sent++;
    else logf_("reload: send failed (%d)", WSAGetLastError());
}
static void rld_rx(const RldPkt *pk)
{
    static unsigned done;
    wchar_t path[MAX_PATH], *b;
    unsigned size, crc;
    char flag[MAX_PATH];
    FILE *f;
    if (pk->seq != done) logf_("reload: message %u from the host: %.63s (role %d, our last save %ls)", pk->seq, pk->name, g_npc_role, g_sav_last);
    if (g_npc_role != 2 || pk->seq == done || !g_sav_last[0] || memchr(pk->name, 0, sizeof pk->name) == NULL ||
        strchr(pk->name, '\\') || strchr(pk->name, '/') || strstr(pk->name, "..")) return;
    done = pk->seq;
    wcscpy(path, g_sav_last);
    b = wcsrchr(path, L'\\');
    if (!b) return;
    MultiByteToWideChar(CP_ACP, 0, pk->name, -1, b + 1, MAX_PATH - (int)(b + 1 - path));
    if (!file_crc(path, &size, &crc) || size != pk->size || crc != pk->crc) {
        logf_("reload: the host loaded %s (%u bytes, crc %08x), ours is %s - not following", pk->name, pk->size, pk->crc,
              GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES ? "missing" : "different");
        return;
    }
    strcpy(flag, g_cmdpath);
    strcpy(strrchr(flag, '\\') + 1, "coop_reload.txt");
    if (!(f = fopen(flag, "w"))) { logf_("reload: cannot write %s", flag); return; }
    fprintf(f, "%s\n", pk->name);
    fclose(f);
    logf_("reload: the host loaded %s, ours matches (crc %08x): ending the game, start-coop restarts it with that save", pk->name, crc);
    g_quitting = 1;
    bye_send();
    TerminateProcess(GetCurrentProcess(), 0);
}
/* ---- the peer on our map ----
 * The map gadget's UseStrategy object (vtable RVA E99EC0, settings FUN_106f28f0) spawns the player arrow from
 * archPlayerMarker (+0x80, gadgets.ObjectiveIcons.PlayerPosition) as a child of the map model (+0x38) and keeps its
 * handle at +0x110. Every frame its method vf+0x10 (FUN_106f4d30 -> FUN_106f49d0 -> FUN_106ee040) turns the player's
 * world position into a point on the model with FUN_106ed0b0(this, region +0x114, &ref, &world, &out, &angle, &offmap) -
 * the map axes come from its corner bones (+0x120 / +0x12C, FUN_106ec6c0) - and sets the arrow's local position
 * (FUN_104e01b0(obj, x, y, z + fMarkerPlayerZ +0xD0)) and local angles (FUN_104e01c0(obj, 0, 0, player yaw)), each
 * after FUN_104dd4f0(obj). vf+0x10 is hooked in the class vtable; after it, a second arrow of the same archetype is
 * attached to the map model the way the game attaches markers (FUN_104e11b0(map obj, child handle, &corner bone +0xC0, 0, 0),
 * which drops one reference of the handle) and placed the same way at the avatar's point, turned by the heading
 * difference avatar - our player, and put in the map's render group (FUN_106eca20). Writing an entity's matrix
 * directly did not move what is drawn.
 * Visibility: FUN_104ddb20(obj, on); hidden 300 ms after the map stops updating. */
static void *g_map_orig;
static volatile DWORD g_map_seen;
static unsigned g_map_faults;
/* the arrows we add to the map. Colours by role: the host is always green, the joiner always yellow (coop.PeerPosition,
 * see g_mk_arch). Slot 0: the other player's arrow (yellow on the host, green on the joiner). Slot 1, joiner only: our
 * own arrow in yellow; the game's own (green) player arrow is hidden while it shows. */
typedef struct { unsigned long long id; BYTE *parent; int shown; const char *arch; } MapMk;
static MapMk g_mk[2];
#define MK_GREEN "gadgets.ObjectiveIcons.PlayerPosition"
static int g_mk_noyellow;          /* coop.PeerPosition could not be spawned (no arrow patch): all green */
typedef char (__attribute__((thiscall)) *w2m_t)(void *self, int region, float *ref, float *world, float *out, float *ang, char *off);
typedef void (__fastcall *eflush_t)(void *obj);
typedef void (__attribute__((thiscall)) *eset3_t)(void *obj, float x, float y, float z);
typedef void (__attribute__((thiscall)) *evis_t)(void *obj, unsigned on);
typedef void (__attribute__((thiscall)) *eattach_t)(void *parent, void *child_handle, void *bone, int a, int b);
static int __attribute__((noinline)) map_w2m(BYTE *self, float *world, float *out)
{
    DWORD seh;
    float ang = 0;
    char off = 0;
    int r;
    __asm__ volatile("movl %%fs:0, %0" : "=r"(seh));
    g_enc_seh = seh; g_enc_tid = GetCurrentThreadId();
    if (__builtin_setjmp(g_enc_jb)) {
        g_enc_guard = 0;
        if (++g_map_faults <= 10) logf_("map: fault in the world-to-map call (%u)", g_map_faults);
        return 0;
    }
    g_enc_guard = 1;
    r = ((w2m_t)(g_base + 0x6ED0B0))(self, *(int *)(self + 0x114), world, world, out, &ang, &off);
    g_enc_guard = 0;
    return r != 0;
}
static BYTE *hobj(BYTE *h) { return h && !IsBadReadPtr(h, 0x10) ? *(BYTE **)(h + 0xC) : NULL; }
static void ent_show(BYTE *o, int on)
{
    ((eflush_t)(g_base + 0x4DD4F0))(o);
    ((evis_t)(g_base + 0x4DDB20))(o, (unsigned)on);
}
static void mk_show(MapMk *m, BYTE *o, int on)
{
    if (!o || m->shown == on) return;
    ent_show(o, on);
    m->shown = on;
}
static void mk_hide(MapMk *m)
{
    void *hd = NULL;
    BYTE *o = m->id ? entity_obj(m->id, &hd) : NULL;
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    mk_show(m, o, 0);
}
/* one of our arrows onto the map model at local (x, y) with yaw a */
static void mk_place(BYTE *self, BYTE *mapobj, MapMk *m, void *h, BYTE *o, const float *l, float a)
{
    if (m->parent != mapobj) {
        (*(int *)((BYTE *)h + 8))++;                  /* the attach call releases one reference */
        ((eflush_t)(g_base + 0x4DD4F0))(mapobj);
        /* on the map's lower left corner bone (+0xC0, sMapCornerDownLeftBone), as FUN_106f07d0 attaches markers;
         * on the model root ("none") the arrow sat behind the paper */
        ((eattach_t)(g_base + 0x4E11B0))(mapobj, h, self + 0xC0, 0, 0);
        /* then, as FUN_106f07d0 does: show it and FUN_106eca20(this, handle) - puts its graphic component in the
         * map's render group (vf+0x98 / +0xA0 / +0xAC); without it the attached arrow was never drawn. Releases
         * one reference too. */
        ent_show(o, 1);
        (*(int *)((BYTE *)h + 8))++;
        ((void (__attribute__((thiscall)) *)(void *, void *))(g_base + 0x6ECA20))(self, h);
        m->parent = mapobj; m->shown = -1;
        logf_("map: arrow %s attached to the map model %p", m->arch, mapobj);
    }
    ((eflush_t)(g_base + 0x4DD4F0))(o);
    ((eset3_t)(g_base + 0x4E01B0))(o, l[0], l[1], l[2] + *(float *)(self + 0xD0));
    ((eflush_t)(g_base + 0x4DD4F0))(o);
    ((eset3_t)(g_base + 0x4E01C0))(o, 0, 0, a);
    mk_show(m, o, 1);
}
static void map_place(BYTE *self)
{
    static DWORD lastlog;
    void *hm = NULL, *ha = NULL, *h0 = NULL, *h1 = NULL;
    BYTE *pm, *mo, *mapobj, *me, *av, *o0, *o1;
    float w[3], l[3], lp[3], pa[3], *ang, a;
    g_map_seen = GetTickCount();
    pm = hobj(*(BYTE **)(self + 0x110));
    mo = *(BYTE **)(self + 0x38);
    mapobj = mo && !IsBadReadPtr(mo, 0xC) ? hobj(*(BYTE **)(mo + 8)) : NULL;
    me = entity_obj(g_net_id, &hm);
    av = g_av_id ? entity_obj(g_av_id, &ha) : NULL;
    o0 = g_mk[0].id ? entity_obj(g_mk[0].id, &h0) : NULL;
    o1 = g_mk[1].id ? entity_obj(g_mk[1].id, &h1) : NULL;
    if (pm && mapobj && me) {
        memcpy(lp, me + 0x60, sizeof lp);
        if (map_w2m(self, lp, lp)) {
            /* our player's yaw as the game reads it for its arrow (FUN_104df830: angles, z at +8) */
            ((eflush_t)(g_base + 0x4DD4F0))(me);
            ang = ((float *(__attribute__((thiscall)) *)(void *, float *))(g_base + 0x4DF830))(me, pa);
            if (o0 && h0 && av) {
                memcpy(w, av + 0x60, sizeof w);
                if (map_w2m(self, w, l)) {
                    /* heading difference avatar - our player (entity row 0 = facing): the avatar's is the one the peer
                     * sends; the avatar entity's own matrix is turned by NetPlayer every frame and made the arrow spin */
                    a = ang[2] + g_mk_yaw + g_mk_sign * (atan2f(g_remote.dir[1], g_remote.dir[0]) - atan2f(*(float *)(me + 0x34), *(float *)(me + 0x30)));
                    l[0] += g_mk_dbg[0]; l[1] += g_mk_dbg[1];
                    mk_place(self, mapobj, &g_mk[0], h0, o0, l, a);
                    if (GetTickCount() - lastlog > 10000) {
                        lastlog = GetTickCount();
                        logf_("map: other player at (%.4f %.4f), we at (%.4f %.4f), yaw %.2f / ours %.2f, mode %d", l[0], l[1], lp[0], lp[1], a, ang[2],
                              *(int *)(self + 0x138));
                    }
                }
            } else mk_show(&g_mk[0], o0, 0);
            if (o1 && h1) {
                /* the joiner's own arrow in yellow, where the game puts its green one, which is hidden */
                mk_place(self, mapobj, &g_mk[1], h1, o1, lp, ang[2]);
                ent_show(pm, 0);
            }
        }
    } else { mk_show(&g_mk[0], o0, 0); mk_show(&g_mk[1], o1, 0); }
    if (hm) (*(int *)((BYTE *)hm + 8))--;
    if (ha) (*(int *)((BYTE *)ha + 8))--;
    if (h0) (*(int *)((BYTE *)h0 + 8))--;
    if (h1) (*(int *)((BYTE *)h1 + 8))--;
}
static void __attribute__((thiscall)) map_hook(BYTE *self, void *dt)
{
    ((void (__attribute__((thiscall)) *)(void *, void *))g_map_orig)(self, dt);
    if (!g_quitting) map_place(self);
}
/* main thread: hook once, spawn our arrows while the map is in use, hide them when the map is put away */
static void map_tick(DWORD now)
{
    int k, joiner = g_npc_role == 2;
    const char *yellow = g_mk_noyellow ? MK_GREEN : "coop.PeerPosition";
    if (!g_map_orig && g_base) {
        void **slot = (void **)(g_base + 0xE99EC0 + 0x10);   /* vtable E99EC0, slot 4: FUN_106f4d30 */
        DWORD old;
        if (*slot == (void *)(g_base + 0x6F4D30) && VirtualProtect(slot, 4, PAGE_READWRITE, &old)) {
            g_map_orig = *slot; *slot = (void *)map_hook;
            VirtualProtect(slot, 4, old, &old);
            logf_("map: per-frame method of the map hooked");
        } else { g_map_orig = (void *)1; logf_("map: unexpected map vtable slot %p, not hooked", *slot); }
    }
    g_mk[0].arch = g_mk_arch[0] ? g_mk_arch : joiner ? MK_GREEN : yellow;
    g_mk[1].arch = joiner && !g_mk_noyellow ? yellow : NULL;
    for (k = 0; k < 2; k++) {
        MapMk *m = &g_mk[k];
        int want = k == 0 ? g_av_id != 0 : m->arch != NULL;
        if (m->id) {
            void *hd = NULL;
            BYTE *o = entity_obj(m->id, &hd);
            if (hd) (*(int *)((BYTE *)hd + 8))--;
            if (!o) { logf_("map: our arrow %llu is gone (a load?)", m->id); m->id = 0; m->parent = NULL; }
        }
        if (m->id && ((k == 0 && g_mk_respawn) || !want)) {
            char code[96], out[32];
            snprintf(code, sizeof code, "RemoveEntity('%llu') __out = 'removed'", m->id);
            lua_eval(code, out, sizeof out);
            m->id = 0; m->parent = NULL;
        }
        if (!m->id && want && g_map_seen && now - g_map_seen < 1000) {
            char out[64], code[200];
            /* spawned near the players (one spawned far below the world, z -10000, was never drawn) */
            snprintf(code, sizeof code, "__out = tostring(SpawnEntityFromArchetype('%s', %.2f, %.2f, %.2f, 0, 0, 0))",
                     m->arch, g_remote.pos[0], g_remote.pos[1], g_remote.pos[2] + 1.0f);
            lua_eval(code, out, sizeof out);
            m->id = strtoull(out, NULL, 10);
            if (m->id == 0xFFFFFFFFFFFFFFFFull) m->id = 0;
            if (!m->id && strcmp(m->arch, MK_GREEN)) {
                logf_("map: no archetype %s (%s): the arrow patch is missing, all arrows stay green", m->arch, out);
                g_mk_noyellow = 1;
                if (m->arch == g_mk_arch) g_mk_arch[0] = 0;
                return;
            }
            m->parent = NULL;
            logf_("map: arrow %s spawned for %s: %s", m->arch, k ? "us" : "the other player", out);
        }
        if (m->id && now - g_map_seen > 300) mk_hide(m);
    }
    g_mk_respawn = 0;
}
/* our player's health, logged when it changes (to tell real damage from hit reactions) */
static void hp_tick(DWORD now)
{
    static DWORD last;
    static float prev = -1;
    void *hd = NULL;
    BYTE *me;
    float hp, mx;
    if (now - last < 250) return;
    last = now;
    me = g_net_id ? entity_obj(g_net_id, &hd) : NULL;
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!me) return;
    hp = npc_hp(me, &mx);
    if (prev >= 0 && fabsf(hp - prev) >= 1.0f) logf_("health: %.0f -> %.0f of %.0f", prev, hp, mx);
    prev = hp;
}
/* ---- vehicle sync (VEH1) ----
 * World vehicles keep their save ids, so both sides know them by id. The driver owns a vehicle: each side sends the
 * vehicle its own player drives (and the seat its player sits in, driver or not); the host also sends the vehicles
 * moving near either player that the joiner does not drive (AI drivers, pushed or rolling cars). The receiver turns
 * those into puppets: the Havok body gets velocities that steer it onto the sender's pose (teleport when far off), so
 * wheels and collisions stay physical. Body = vehicle phys comp FDE25C +0x60 [0] +0x30 (rigid body wrapper, vtable
 * E67390): +0x20 get / +0x50 set linear vel, +0x28 / +0x54 angular, +0x48 set position, +0x4C set rotation (x y z w).
 * The other player's seat goes to the avatar: engine seat call D8050 + beautifier profile "vehicle" (its NetPlayer
 * already follows the seat position from the player packets). */
#define VEH_MAGIC 0x31484556u      /* "VEH1" */
#define VEH_MAX 12
#define VF_DRIVE 1                 /* the sender's player drives it: its pose is authoritative */
#define VF_SEAT 2                  /* the sender's player sits in seat `seat` */
#define VF_HOST 4                  /* host-run (no player in it): authoritative unless we drive it */
#define VF_TARGET 8                /* the sender's player is heading for it (pressed use, getting in) */
#define VF_EXIT 16                 /* the sender's player is getting out of it */
typedef struct { unsigned long long id; float pos[3], q[4], vel[3], avel[3]; unsigned char flags, seat, pad[2]; } VehEnt;
typedef struct { unsigned magic, seq, count; VehEnt e[VEH_MAX]; } VehPkt;
static int g_vehsync = 1;          /* vehsync 0|1 */
static unsigned g_veh_rx, g_veh_tx, g_veh_snaps, g_veh_unknown;
static struct { unsigned long long id; VehEnt e; DWORD t; int snapped; } g_vp[VEH_MAX];         /* puppets */
static struct { unsigned long long id; float pos[3]; DWORD moving, sent; } g_vh[32];             /* host's nearby list */
static int g_vh_n;
static unsigned long long g_vh_build[32];
static int g_vh_bn;
static unsigned long long g_peer_veh = ~0ULL, g_av_veh = ~0ULL;   /* the peer's player vehicle (packets) / where our avatar sits */
static int g_peer_seat = -1;
static DWORD g_peer_veh_t, g_peer_target_t;
static unsigned long long g_peer_target = ~0ULL;
static unsigned long long g_peer_drives[VEH_MAX];
static DWORD g_peer_drives_t[VEH_MAX];

static BYTE *veh_body(unsigned long long id)
{
    typedef void *(__attribute__((thiscall)) *gcomp_t)(void *ent, void *key);
    void *hd = NULL;
    BYTE *obj = entity_obj(id, &hd), *pc, *arr, *po, *w;
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!obj || !(pc = ((gcomp_t)(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDE25C))) || IsBadReadPtr(pc, 0x68)) return NULL;
    if (*(int *)(pc + 0x64) < 1 || !(arr = *(BYTE **)(pc + 0x60)) || IsBadReadPtr(arr, 4) || !(po = *(BYTE **)arr) || IsBadReadPtr(po, 0x34)) return NULL;
    w = *(BYTE **)(po + 0x30);
    return w && !IsBadReadPtr(w, 0x70) && *(unsigned *)w == (unsigned)(g_base + 0xE67390) && *(void **)(w + 0x68) ? w : NULL;
}
typedef void (__attribute__((thiscall)) *vbody_t)(void *w, float *v);
/* the body calls read and write the vector with MOVAPS: it must be 16-byte aligned (a stack array crashed B) */
static void vb(BYTE *w, int off, float *v)
{
    static float t[4] __attribute__((aligned(16)));   /* main thread only; gcc does not realign the stack */
    memcpy(t, v, sizeof t);
    ((vbody_t)(*(void ***)w)[off / 4])(w, t);
    memcpy(v, t, 3 * sizeof(float));
    if (off == 0x4C) v[3] = t[3];
}
/* rotation of an entity matrix (rows +0x30/+0x40/+0x50 = local x/y/z axes in world) as a quaternion x y z w */
static void veh_m2q(const BYTE *o, float *q)
{
    const float *X = (const float *)(o + 0x30), *Y = (const float *)(o + 0x40), *Z = (const float *)(o + 0x50);
    /* R columns = axes: R[r][c] = axis_c[r] */
    float m00 = X[0], m11 = Y[1], m22 = Z[2], t = m00 + m11 + m22, s;
    if (t > 0) { s = sqrtf(t + 1.0f) * 2; q[3] = 0.25f * s; q[0] = (Y[2] - Z[1]) / s; q[1] = (Z[0] - X[2]) / s; q[2] = (X[1] - Y[0]) / s; }
    else if (m00 > m11 && m00 > m22) { s = sqrtf(1.0f + m00 - m11 - m22) * 2; q[3] = (Y[2] - Z[1]) / s; q[0] = 0.25f * s; q[1] = (Y[0] + X[1]) / s; q[2] = (Z[0] + X[2]) / s; }
    else if (m11 > m22) { s = sqrtf(1.0f + m11 - m00 - m22) * 2; q[3] = (Z[0] - X[2]) / s; q[0] = (Y[0] + X[1]) / s; q[1] = 0.25f * s; q[2] = (Z[1] + Y[2]) / s; }
    else { s = sqrtf(1.0f + m22 - m00 - m11) * 2; q[3] = (X[1] - Y[0]) / s; q[0] = (Z[0] + X[2]) / s; q[1] = (Z[1] + Y[2]) / s; q[2] = 0.25f * s; }
}
/* rotation taking a to b as angle * axis (world), for steering by angular velocity */
static void veh_qerr(const float *a, const float *b, float *out)
{
    /* e = b * conj(a) */
    float ax = -a[0], ay = -a[1], az = -a[2], aw = a[3];
    float ex = b[3] * ax + b[0] * aw + b[1] * az - b[2] * ay;
    float ey = b[3] * ay - b[0] * az + b[1] * aw + b[2] * ax;
    float ez = b[3] * az + b[0] * ay - b[1] * ax + b[2] * aw;
    float ew = b[3] * aw - b[0] * ax - b[1] * ay - b[2] * az, sn, ang;
    if (ew < 0) { ex = -ex; ey = -ey; ez = -ez; ew = -ew; }
    sn = sqrtf(ex * ex + ey * ey + ez * ez);
    if (sn < 1e-5f) { out[0] = out[1] = out[2] = 0; return; }
    ang = 2.0f * atan2f(sn, ew);
    out[0] = ex / sn * ang; out[1] = ey / sn * ang; out[2] = ez / sn * ang;
}
/* fill an entry from our world; 0 when the vehicle or its body is not there */
static int veh_fill(unsigned long long id, VehEnt *e)
{
    void *hd = NULL;
    BYTE *obj = entity_obj(id, &hd), *w = veh_body(id);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if (!obj || !w) return 0;
    memset(e, 0, sizeof *e);
    e->id = id;
    memcpy(e->pos, obj + 0x60, sizeof e->pos);
    veh_m2q(obj, e->q);
    { float t[4] = { 0, 0, 0, 0 }; vb(w, 0x20, t); memcpy(e->vel, t, sizeof e->vel); vb(w, 0x28, t); memcpy(e->avel, t, sizeof e->avel); }
    return 1;
}
static int veh_peer_drives(unsigned long long id, DWORD now)
{
    int i;
    for (i = 0; i < VEH_MAX; i++) if (g_peer_drives[i] == id && now - g_peer_drives_t[i] < 1000) return 1;
    return 0;
}
static void veh_scan_cb(unsigned long long id, BYTE *obj, BYTE *comp, void *ctx)
{
    const float *mp = (const float *)ctx;
    float dx = *(float *)(obj + 0x60) - mp[0], dy = *(float *)(obj + 0x64) - mp[1], ex = *(float *)(obj + 0x60) - mp[2], ey = *(float *)(obj + 0x64) - mp[3];
    (void)comp;
    if (g_vh_bn < 32 && (dx * dx + dy * dy < 150.0f * 150.0f || ex * ex + ey * ey < 150.0f * 150.0f)) g_vh_build[g_vh_bn++] = id;
}
/* our player's vehicle and seat (~0 / -1 when on foot), and whether that seat is the driver's */
static unsigned long long veh_mine(int *seat, int *drive)
{
    unsigned long long v = pawn_bb_u64(g_net_id, 0xFD1BA782u);
    BYTE *im = v != ~0ULL ? veh_impl(v) : NULL;
    int s = im ? veh_seat_of(im, g_net_id) : -1;
    *seat = s; *drive = s >= 0 && *(int *)(*(BYTE **)(im + 0xC) + s * VEH_SEAT_STRIDE + 0x10) == 1;
    return im ? v : ~0ULL;
}
static void veh_send_tick(DWORD now)
{
    static DWORD last_send, last_scan;
    static unsigned seq;
    static IncScan vs;
    static float mp[4];
    VehPkt pk;
    unsigned long long mine;
    int i, n = 0, mydrive, myseat;
    if (!g_vehsync || g_ns == INVALID_SOCKET || !player_ready(g_net_id)) return;
    /* host: re-pick the vehicles within 150 m of us or the avatar, a pass every 10 s spread over frames */
    if (g_npc_role == 1) {
        if (!vs.busy && (!last_scan || now - last_scan > 10000)) {
            void *hd = NULL;
            BYTE *me = entity_obj(g_net_id, &hd), *av;
            if (hd) { (*(int *)((BYTE *)hd + 8))--; hd = NULL; }
            memset(mp, 0, sizeof mp);
            if (me) memcpy(mp, me + 0x60, 2 * sizeof(float));
            av = g_av_id ? entity_obj(g_av_id, &hd) : NULL;
            if (hd) (*(int *)((BYTE *)hd + 8))--;
            if (av) memcpy(mp + 2, av + 0x60, 2 * sizeof(float)); else { mp[2] = mp[0]; mp[3] = mp[1]; }
            g_vh_bn = 0; last_scan = now; vs.busy = 0; vs.vt = 0xE1A790; vs.hoff = 8;
            npc_scan_step(&vs, 0, veh_scan_cb, mp);
        }
        if (vs.busy && npc_scan_step(&vs, 16u << 20, veh_scan_cb, mp)) {
            int j, k, old = g_vh_n;
            for (j = 0; j < g_vh_bn; j++) {
                for (k = 0; k < g_vh_n && g_vh[k].id != g_vh_build[j]; k++) ;
                if (k == g_vh_n && g_vh_n < 32) { memset(&g_vh[g_vh_n], 0, sizeof g_vh[0]); g_vh[g_vh_n++].id = g_vh_build[j]; }
            }
            for (k = 0; k < g_vh_n; k++) {   /* drop the ones no longer near */
                for (j = 0; j < g_vh_bn && g_vh_build[j] != g_vh[k].id; j++) ;
                if (j == g_vh_bn) g_vh[k--] = g_vh[--g_vh_n];
            }
            if (g_vh_n != old) logf_("vehsync host: %d vehicles within 150 m of us or the avatar (pass %lu ms)", g_vh_n, GetTickCount() - last_scan);
        }
    }
    mine = veh_mine(&myseat, &mydrive);
    /* 20 Hz while we drive, 10 Hz otherwise */
    if (now - last_send < (mydrive ? 50u : 100u)) return;
    last_send = now;
    memset(&pk, 0, sizeof pk);
    if (mine != ~0ULL && veh_fill(mine, &pk.e[n])) {
        /* seat state 2 getting in, 4 seated, 1 then 3 getting out: say so at once, the avatar's get-out then runs
         * alongside ours (waiting until we were out left it ~1.8 s behind) */
        BYTE *im = veh_impl(mine);
        int ss = im && myseat >= 0 ? *(int *)(*(BYTE **)(im + 0xC) + myseat * VEH_SEAT_STRIDE + 0x30) : 4;
        pk.e[n].flags = (ss == 1 || ss == 3 ? VF_EXIT : VF_SEAT) | (mydrive ? VF_DRIVE : 0);
        pk.e[n].seat = (unsigned char)(myseat < 0 ? 0 : myseat);
        n++;
    }
    if (mine == ~0ULL) {
        /* heading for a vehicle (use pressed, walking up / getting in): the avatar starts getting in with us */
        unsigned long long tg = pawn_bb_u64(g_net_id, 0x1BAA9B71u);
        if (tg != ~0ULL && veh_fill(tg, &pk.e[n])) { pk.e[n].flags = VF_TARGET; n++; }
    }
    if (g_npc_role == 1)
        for (i = 0; i < g_vh_n && n < VEH_MAX; i++) {
            VehEnt *e = &pk.e[n];
            float sp, dx, dy, dz;
            if (g_vh[i].id == mine || veh_peer_drives(g_vh[i].id, now) || !veh_fill(g_vh[i].id, e)) continue;
            sp = e->vel[0] * e->vel[0] + e->vel[1] * e->vel[1] + e->vel[2] * e->vel[2] + e->avel[0] * e->avel[0] + e->avel[1] * e->avel[1] + e->avel[2] * e->avel[2];
            dx = e->pos[0] - g_vh[i].pos[0]; dy = e->pos[1] - g_vh[i].pos[1]; dz = e->pos[2] - g_vh[i].pos[2];
            if (sp > 0.04f || dx * dx + dy * dy + dz * dz > 0.01f) g_vh[i].moving = now;
            memcpy(g_vh[i].pos, e->pos, sizeof g_vh[i].pos);
            /* moving, or up to 2 s after it stopped so the resting pose arrives; still ones every 5 s */
            if (now - g_vh[i].moving > 2000 && now - g_vh[i].sent < 5000) continue;
            e->flags = VF_HOST; g_vh[i].sent = now; n++;
        }
    if (!n) return;
    pk.magic = VEH_MAGIC; pk.seq = ++seq; pk.count = n;
    sendto(g_ns, (char *)&pk, (int)(offsetof(VehPkt, e) + n * sizeof(VehEnt)), 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    g_veh_tx++;
}
static void veh_rx(const VehPkt *pk, int len)
{
    DWORD now = GetTickCount();
    unsigned i, n = pk->count;
    if (!g_vehsync || n > VEH_MAX || len != (int)(offsetof(VehPkt, e) + n * sizeof(VehEnt))) return;
    g_veh_rx++;
    for (i = 0; i < n; i++) {
        const VehEnt *e = &pk->e[i];
        int j, f = -1;
        if (e->flags & VF_SEAT) { g_peer_veh = e->id; g_peer_seat = e->seat; g_peer_veh_t = now; }
        if (e->flags & VF_TARGET) { g_peer_target = e->id; g_peer_target_t = now; }
        if ((e->flags & VF_EXIT) && g_peer_veh == e->id) g_peer_veh = ~0ULL;
        if (e->flags & VF_DRIVE) {
            for (j = 0; j < VEH_MAX && g_peer_drives[j] != e->id && now - g_peer_drives_t[j] < 1000; j++) ;
            if (j < VEH_MAX) { g_peer_drives[j] = e->id; g_peer_drives_t[j] = now; }
        }
        if (!(e->flags & (VF_DRIVE | VF_HOST))) continue;
        if (!veh_body(e->id)) {
            if (++g_veh_unknown <= 20) logf_("vehsync: vehicle %llx from the peer is not in our world (or has no body)", e->id);
            continue;
        }
        for (j = 0; j < VEH_MAX; j++) if (g_vp[j].id == e->id) { f = j; break; }
        if (f < 0) for (j = 0; j < VEH_MAX; j++) if (!g_vp[j].id || now - g_vp[j].t > 3000) { f = j; break; }
        if (f < 0) continue;
        if (g_vp[f].id != e->id) { memset(&g_vp[f], 0, sizeof g_vp[f]); g_vp[f].id = e->id; logf_("vehsync: puppet for vehicle %llx", e->id); }
        g_vp[f].e = *e; g_vp[f].t = now;
    }
}
/* steer the puppets every frame */
static void veh_puppet_tick(DWORD now)
{
    int i, myseat, mydrive;
    unsigned long long mine = veh_mine(&myseat, &mydrive);
    for (i = 0; i < VEH_MAX; i++) {
        const VehEnt *e = &g_vp[i].e;
        void *hd = NULL;
        BYTE *obj, *w;
        float dt, tp[3], err[3], d2, cq[4], re[3], v[4], av[4], ang2;
        int k;
        if (!g_vp[i].id || now - g_vp[i].t > 1500) continue;
        if (g_vp[i].id == mine && mydrive) continue;   /* we drive it ourselves: ours wins, the peer gets our state */
        obj = entity_obj(g_vp[i].id, &hd);
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!obj || !(w = veh_body(g_vp[i].id))) continue;
        dt = (now - g_vp[i].t) / 1000.0f;
        if (dt > 0.3f) dt = 0.3f;
        for (k = 0; k < 3; k++) { tp[k] = e->pos[k] + e->vel[k] * dt; err[k] = tp[k] - *(float *)(obj + 0x60 + 4 * k); }
        d2 = err[0] * err[0] + err[1] * err[1] + err[2] * err[2];
        veh_m2q(obj, cq);
        veh_qerr(cq, e->q, re);
        ang2 = re[0] * re[0] + re[1] * re[1] + re[2] * re[2];
        if (!g_vp[i].snapped || d2 > 16.0f || ang2 > 0.8f * 0.8f) {
            float p[4] = { tp[0], tp[1], tp[2], 0 }, q[4];
            memcpy(q, e->q, sizeof q);
            vb(w, 0x48, p); vb(w, 0x4C, q);
            g_vp[i].snapped = 1;
            if (++g_veh_snaps <= 40) logf_("vehsync: puppet %llx placed (off %.1f m, %.0f deg)", g_vp[i].id, sqrtf(d2), sqrtf(ang2) * 57.3f);
        }
        /* resting and in place: leave the body alone so it can sleep */
        if (d2 < 0.0025f && ang2 < 0.0004f && e->vel[0] * e->vel[0] + e->vel[1] * e->vel[1] + e->vel[2] * e->vel[2] < 0.0025f &&
            e->avel[0] * e->avel[0] + e->avel[1] * e->avel[1] + e->avel[2] * e->avel[2] < 0.0025f) continue;
        for (k = 0; k < 3; k++) { v[k] = e->vel[k] + 4.0f * err[k]; av[k] = e->avel[k] + 4.0f * re[k]; }
        v[3] = av[3] = 0;
        vb(w, 0x50, v); vb(w, 0x54, av);
    }
}
/* the other player's seat on our avatar */
/* leave by hand (fallback): the engine's get-out E5B40, then free the seat if it still holds the avatar and take the
 * seat out of the anim graph (v2A seat type, v53 seat index, as 151D50 set them); beautifier back to "standard" */
static void veh_avatar_force_out(BYTE *pw)
{
    BYTE *im = veh_impl(g_av_veh), *obj;
    void *hd = NULL, *bc;
    unsigned *v, prof = 0x10F7D787u;
    int s;
    if (im) {
        veh_seat_call(5, im, 0, pw);
        if ((s = veh_seat_of(im, g_av_id)) >= 0) {
            BYTE *st = *(BYTE **)(im + 0xC) + s * VEH_SEAT_STRIDE;
            *(unsigned long long *)(st + 0x28) = ~0ULL; *(int *)(st + 0x30) = 0; *(int *)(st + 0x24) = -1; st[0x21] = 0;
        }
    }
    obj = entity_obj(g_av_id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    if ((v = npc_animvars(obj))) { v[0x2A] = 0; v[0x53] = 0; }
    bc = obj ? ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4)) : NULL;
    if (bc) ((void (__attribute__((thiscall)) *)(void *, unsigned *))(g_base + 0xE97C0))(bc, &prof);
}
/* seat by hand (fallback, e.g. we joined while the peer already drove): the vehicle's get-in E5740 (nearest entry point
 * within impl +0x118), else D8050 into the peer's seat with seat state 4; beautifier profile for the seat type */
static void veh_avatar_force_in(BYTE *pw, BYTE *im)
{
    BYTE *obj;
    void *hd = NULL, *bc;
    unsigned prof;
    int type;
    if (g_peer_seat < 0 || g_peer_seat >= (int)*(unsigned *)(im + 0x10)) return;
    type = *(int *)(*(BYTE **)(im + 0xC) + g_peer_seat * VEH_SEAT_STRIDE + 0x10);
    veh_seat_call(4, im, 0, pw);
    if (veh_seat_of(im, g_av_id) < 0) {
        veh_seat_call(1, im, g_peer_seat, pw);
        if (veh_seat_of(im, g_av_id) == g_peer_seat) *(int *)(*(BYTE **)(im + 0xC) + g_peer_seat * VEH_SEAT_STRIDE + 0x30) = 4;
    }
    prof = type == 1 ? 0x1B80E486u : type == 2 ? 0xCE7A971Cu : 0xC83DA229u;   /* vehicle / mountedweapon / vehiclepassenger */
    obj = entity_obj(g_av_id, &hd);
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    bc = obj ? ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4)) : NULL;
    if (bc) ((void (__attribute__((thiscall)) *)(void *, unsigned *))(g_base + 0xE97C0))(bc, &prof);
}
/* the other player's vehicle on our avatar. The avatar's GO state machine (Main Avatar vehicle graph in worlds.fat)
 * does the whole thing with its animations once it gets the target vehicle (blackboard 0x1BAA9B71) and the signal
 * entervehicle_new (CRC32 B2B02045): holster, get-in (the vehicle's E5740), Pawn_Generic_Vehicle_GetIn, seat choice,
 * Driving / Passenger; out with the signal exitvehicle (F1ACDD97, Pawn_Generic_Vehicle_GetOut). It starts when the
 * peer's player heads for a vehicle (its own target, VF_TARGET) or sits in one; hand-made seating only as a fallback. */
static void veh_avatar_tick(DWORD now)
{
    static int st, tries;   /* st: 0 on foot, 1 entering (signal sent), 2 in, 3 seated by hand, 4 getting out */
    static DWORD t, lost;
    unsigned long long want = g_peer_veh != ~0ULL ? g_peer_veh : g_peer_target, cur;
    BYTE *pw, *im;
    if (!g_av_id) { g_av_veh = ~0ULL; st = 0; return; }
    if (!(pw = pawn_comp_of(g_av_id))) return;
    cur = pawn_bb_u64(g_av_id, 0xFD1BA782u);
    if (g_av_veh != ~0ULL && want != g_av_veh) {
        /* the peer got out (or into another vehicle): out first */
        if (st == 1 || st == 2) {
            pawn_state_event(pw, 0xF1ACDD97u);   /* exitvehicle */
            st = 4; t = now;
            logf_("vehsync: avatar gets out of vehicle %llx (signal)", g_av_veh);
        } else if (st == 3 || (st == 4 && now - t > 4000)) {
            if (st == 4) logf_("vehsync: avatar still in vehicle %llx after the exit signal: out by hand", g_av_veh);
            veh_avatar_force_out(pw);
            st = 0;
        }
        if (st == 4 && cur == ~0ULL) st = 0;
        if (st == 0) { logf_("vehsync: avatar is out of vehicle %llx", g_av_veh); g_av_veh = ~0ULL; }
        return;
    }
    if (want == ~0ULL) return;
    if (!(im = veh_impl(want))) {
        if (g_av_veh != want) { g_av_veh = want; st = 3; logf_("vehsync: the peer's vehicle %llx is not in our world", want); }
        return;
    }
    if (g_av_veh != want) {
        pawn_bb_set_u64(g_av_id, 0x1BAA9B71u, want);
        pawn_state_event(pw, 0xB2B02045u);   /* entervehicle_new */
        g_av_veh = want; st = 1; t = now; tries = 0;
        logf_("vehsync: avatar heads for vehicle %llx (peer %s)", want, g_peer_veh != ~0ULL ? "seated" : "approaching");
        return;
    }
    if (st == 1) {
        if (cur == want) { st = 2; lost = 0; logf_("vehsync: avatar sits in vehicle %llx (state machine), seat %d", want, veh_seat_of(im, g_av_id)); }
        else if (now - t > 3000) {
            if (g_peer_veh == want && ++tries > 2) { veh_avatar_force_in(pw, im); st = 3; logf_("vehsync: avatar seated by hand in %llx seat %d", want, veh_seat_of(im, g_av_id)); }
            else { pawn_bb_set_u64(g_av_id, 0x1BAA9B71u, want); pawn_state_event(pw, 0xB2B02045u); t = now; }
        }
    } else if (st == 2 && g_peer_veh == want) {
        /* the engine put it out while the peer still sits (seen on A/B: the avatar stood on the roof again, e.g. with
         * both players in one car): get in again after 1 s */
        if (cur == want) lost = 0;
        else if (!lost) { lost = now | 1; logf_("vehsync: avatar lost vehicle %llx (current %llx, seat %d)", want, cur, veh_seat_of(im, g_av_id)); }
        else if (now - lost > 1000) { pawn_bb_set_u64(g_av_id, 0x1BAA9B71u, want); pawn_state_event(pw, 0xB2B02045u); st = 1; t = now; tries = 0; lost = 0; }
    } else if (st == 4) {
        /* the peer got back in while our avatar was still getting out: finish getting out, then in again */
        if (cur == ~0ULL || now - t > 4000) {
            if (cur != ~0ULL) veh_avatar_force_out(pw);
            logf_("vehsync: avatar is out of vehicle %llx, the peer is back in", g_av_veh);
            g_av_veh = ~0ULL; st = 0;
        }
    }
}
static void veh_tick(DWORD now)
{
    static DWORD last_log;
    if (!g_vehsync) return;
    /* a seated player's side sends its seat at 10-20 Hz; a joiner on foot sends no VEH1 at all, so the timeout is
     * checked here: no seat entry for 0.6 s = its player got out */
    if (g_peer_veh != ~0ULL && now - g_peer_veh_t > 600) g_peer_veh = ~0ULL;
    if (g_peer_target != ~0ULL && now - g_peer_target_t > 600) g_peer_target = ~0ULL;
    veh_send_tick(now);
    veh_puppet_tick(now);
    veh_avatar_tick(now);
    if (now - last_log > 5000 && (g_veh_rx || g_veh_tx)) {
        int i, np = 0;
        last_log = now;
        for (i = 0; i < VEH_MAX; i++) if (g_vp[i].id && now - g_vp[i].t < 1500) np++;
        logf_("vehsync: tx %u rx %u, %d live puppets, peer in %llx seat %d, avatar in %llx", g_veh_tx, g_veh_rx, np, g_peer_veh, g_peer_seat, g_av_veh);
    }
}

/* ---- state machine signals (SIG1). FUN_1029da10(driver, hash) passes a signal (CRC32 of its name) to every GO state
 * machine of a pawn (driver = pawn comp vf+0x78). 255 call sites: interactions (doors, healing, pickups), vehicles,
 * weapons, reactions. The detour records the signals our own player's driver gets (any thread, lock-free ring); the
 * main thread sends them to the peer, whose probe passes them to the avatar's driver the same way. ---- */
#define SIG_MAGIC 0x31474953u      /* "SIG1" */
#define SIG_N 8
typedef struct { unsigned magic, seq, n, hash[SIG_N]; } SigPkt;   /* hash[i] has seq - n + 1 + i */
static void *g_sig_orig;
static void *volatile g_sig_mydrv, *volatile g_sig_avdrv;
static volatile LONG g_sig_w;
static LONG g_sig_r;
static struct { unsigned hash, caller; void *drv; } g_sig_ring[512];
static unsigned g_sig_seq, g_sig_hist[SIG_N], g_sig_rx_seq, g_sig_tx, g_sig_rx;
static DWORD g_sig_new_t, g_sig_sent_t;
/* NPC reaction signals (Social graph c4dfa7f1), logged for any pawn with siglog 1: start_aimedat, stop_aimedat,
 * shove_player, start_shoved, player_pushed, start_charged, kill_gesture */
static const unsigned g_sig_watch[] = { 0x6699A29Cu, 0x3183E869u, 0x050EEBF3u, 0x3E95BCC4u, 0x79C9FA4Au, 0x49F9890Eu, 0xCAEAB4BEu };
static int sig_watched(unsigned h)
{
    unsigned i;
    for (i = 0; i < sizeof g_sig_watch / sizeof g_sig_watch[0]; i++) if (g_sig_watch[i] == h) return 1;
    return 0;
}
/* host: is this the state driver of a synced NPC's agent (NSG1)? */
/* off by default: a relayed loop_smart_terrain_layer (2E50267D) crashed the joiner 47 ms later (Dunia+282D52 reads a
 * null argument): the puppet's paused AI has no smart terrain data for the state the signal starts */
static int g_nsgsync = 0;          /* nsgsync 0|1 */
static int nsg_npc_drv(void *drv)
{
    int i;
    if (g_npc_role != 1 || !g_nsgsync) return 0;
    for (i = 0; i < 64; i++) if (g_nagent[i].drv == drv && g_nagent[i].id) return 1;
    return 0;
}
static void __attribute__((thiscall)) sig_hook(void *drv, unsigned hash)
{
    if (drv && (drv == g_sig_mydrv || g_siglog >= 2 || (g_siglog && drv == g_sig_avdrv) ||
                ((g_siglog || (g_nresync && g_npc_role == 2)) && sig_watched(hash)) || nsg_npc_drv(drv))) {
        LONG i = InterlockedIncrement(&g_sig_w) - 1;
        g_sig_ring[i & 511].hash = hash; g_sig_ring[i & 511].drv = drv;
        g_sig_ring[i & 511].caller = (unsigned)__builtin_return_address(0) - (unsigned)g_base;
    }
    /* a puppet takes orders from the host only. Its paused AI still runs and signals its pawn (FUN_109ff990: end_stp,
     * holsterweapon, drawweapon, stop_aimedat...): near the joiner's player puppets twitched, a shove took the weapon
     * away for 1.5 s (owner, A/B). The signals of AI code (900000-A10000) are still seen above (NRE1 forwards them) but
     * do not reach the pawn. npcsigdrop 0 lets them through. */
    if (g_npc_role == 2 && g_npcsigdrop && drv) {
        unsigned c = (unsigned)__builtin_return_address(0) - (unsigned)g_base;
        if (c >= 0x900000 && c < 0xA10000) {
            int j;
            for (j = 0; j < NPC_MAX; j++) if (g_np_drv[j] == drv) { g_npcsigdropped++; return; }
        }
    }
    ((void (__attribute__((thiscall)) *)(void *, unsigned))g_sig_orig)(drv, hash);
}
static void sig_install(void)
{
    /* 29DA10: mov eax,[esp+4]; cmp eax,[10E2C55C] (10 bytes, both position independent), then push edi */
    static const BYTE pro[10] = { 0x8B, 0x44, 0x24, 0x04, 0x3B, 0x05, 0x5C, 0xC5, 0xE2, 0x10 };
    if (g_sig_orig) return;
    if (memcmp(g_base + 0x29DA10, pro, sizeof pro)) { logf_("sig: unexpected bytes at 29DA10, no signal hook"); return; }
    g_sig_orig = make_detour(g_base + 0x29DA10, 10, (void *)sig_hook, 1);
    logf_("sig: signal hook on 29DA10 installed");
}
static void *pawn_driver(unsigned long long id)
{
    BYTE *pw = id ? pawn_comp_of(id) : NULL;
    return pw ? ((void *(__attribute__((thiscall)) *)(void *))(*(void ***)pw)[0x78 / 4])(pw) : NULL;
}
static int sig_listed(const unsigned *l, int n, unsigned h)
{
    int i;
    for (i = 0; i < n; i++) if (l[i] == h) return 1;
    return 0;
}
static void sig_send(void)
{
    SigPkt k;
    k.magic = SIG_MAGIC; k.seq = g_sig_seq; k.n = g_sig_seq < SIG_N ? g_sig_seq : SIG_N;
    memcpy(k.hash, g_sig_hist + (SIG_N - k.n), k.n * 4);
    memset(k.hash + k.n, 0, (SIG_N - k.n) * 4);
    sendto(g_ns, (char *)&k, sizeof k, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    g_sig_tx++;
}
static void sig_rx(const SigPkt *k)
{
    unsigned i, s0;
    BYTE *pw;
    if (k->n > SIG_N || k->seq < k->n) return;
    if (k->seq < g_sig_rx_seq) g_sig_rx_seq = 0;          /* the peer's probe restarted */
    if (k->seq == g_sig_rx_seq) return;
    pw = g_av_id ? pawn_comp_of(g_av_id) : NULL;
    s0 = k->seq - k->n + 1;
    for (i = 0; i < k->n; i++) {
        if (s0 + i <= g_sig_rx_seq) continue;
        g_sig_rx++;
        if (g_siglog) logf_("sig: avatar <- %08x (seq %u)%s", k->hash[i], s0 + i, pw ? "" : ", no avatar");
        if (pw) pawn_state_event(pw, k->hash[i]);
    }
    g_sig_rx_seq = k->seq;
}
/* ---- NPC reactions (NRE1). The host's NPCs react only to the host's player: bump and aim detection never ran for
 * the avatar. The joiner's puppets still run that part of their AI against the joiner's own player (start_aimedat:
 * hands up, start_shoved / shove_player, the player gets player_pushed). So the joiner forwards those signals of a
 * puppet to the host, which passes them to the real NPC; its animation then comes back to the joiner with NANM. ---- */
#define NRE_MAGIC 0x3145524Eu      /* "NRE1" */
typedef struct { unsigned magic, seq; unsigned long long id; unsigned hash, pad; } NpcReactPkt;
static unsigned g_nre_seq, g_nre_rx_seq, g_nre_tx, g_nre_rx;
static int g_nresync = 1;
static struct { unsigned long long id; DWORD aimed; } g_nre_aim[16];
static int nre_forwarded(unsigned h)
{
    /* start_aimedat, stop_aimedat, shove_player, start_shoved, start_charged */
    return h == 0x6699A29Cu || h == 0x3183E869u || h == 0x050EEBF3u || h == 0x3E95BCC4u || h == 0x49F9890Eu;
}
static void nre_send(unsigned long long id, unsigned h)
{
    NpcReactPkt k = { NRE_MAGIC, ++g_nre_seq, id, h, 0 };
    int i;
    for (i = 0; i < 2; i++) sendto(g_ns, (char *)&k, sizeof k, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    g_nre_tx++;
}
/* ---- NPC behaviour signals (NSG1): every signal the host's AI gives a synced NPC's agent (smart terrain: sitting,
 * drinking, smoking - start_smart_terrain / loop_ / stop_ ...; gestures; talks) goes to the joiner, which gives it to
 * its puppet's agent the same way (FUN_109ff990). Reactions to players (NRE1 set) are left out: the joiner's own
 * puppet AI makes those for its player. ---- */
#define NSG_MAGIC 0x3147534Eu      /* "NSG1" */
typedef struct { unsigned magic, seq; unsigned long long id; unsigned hash, pad; } NpcSigPkt;
static unsigned g_nsg_seq, g_nsg_rx_seq, g_nsg_tx, g_nsg_rx;
static void nsg_host_signal(void *drv, unsigned h)
{
    int i;
    NpcSigPkt k;
    if (!nsg_npc_drv(drv) || nre_forwarded(h) || h == 0xCAEAB4BEu) return;
    for (i = 0; i < 64; i++) if (g_nagent[i].drv == drv && g_nagent[i].id) break;
    if (i == 64) return;
    k.magic = NSG_MAGIC; k.seq = ++g_nsg_seq; k.id = g_nagent[i].id; k.hash = h; k.pad = 0;
    sendto(g_ns, (char *)&k, sizeof k, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    sendto(g_ns, (char *)&k, sizeof k, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
    if (++g_nsg_tx <= 300 || g_siglog) logf_("nsg: NPC %llu got %08x from our AI -> joiner", k.id, h);
}
static void nsg_rx(const NpcSigPkt *k)
{
    int j;
    BYTE *ag = NULL;
    if (k->seq < g_nsg_rx_seq) g_nsg_rx_seq = 0;
    if (k->seq == g_nsg_rx_seq) return;
    g_nsg_rx_seq = k->seq;
    if (!g_nsgsync || g_npc_role != 2) return;
    g_nsg_rx++;
    for (j = 0; j < g_np_n; j++)
        if (g_np[j].id == k->id && g_np[j].agent && !IsBadReadPtr(g_np[j].agent, 8) && *(unsigned *)g_np[j].agent == (unsigned)(g_base + 0xEC5078)) {
            ag = g_np[j].agent; break;
        }
    if (ag) { unsigned h = k->hash; ((void (__attribute__((thiscall)) *)(void *, unsigned *))(g_base + 0x9FF990))(ag, &h); }
    if (g_nsg_rx <= 300 || g_siglog) logf_("nsg: host NPC %llu got %08x -> %s", k->id, k->hash, ag ? "our puppet's agent" : "no puppet agent here");
}
/* joiner: a puppet got a reaction signal from its own AI */
static void nre_puppet_signal(void *drv, unsigned h)
{
    int j, k, slot = -1;
    if (!g_nresync || g_npc_role != 2 || !nre_forwarded(h)) return;
    for (j = 0; j < g_np_n; j++) {
        BYTE *pc = g_np[j].id ? pawn_comp_of(g_np[j].lid ? g_np[j].lid : g_np[j].id) : NULL;
        if (pc && ((void *(__attribute__((thiscall)) *)(void *))(*(void ***)pc)[0x78 / 4])(pc) == drv) break;
    }
    if (j == g_np_n) return;
    /* stop_aimedat comes for every NPC all the time: only after a start_aimedat we sent */
    for (k = 0; k < 16; k++) if (g_nre_aim[k].id == g_np[j].id) break;
    if (h == 0x3183E869u && (k == 16 || !g_nre_aim[k].aimed)) return;
    if (h == 0x6699A29Cu || h == 0x3183E869u) {
        if (k == 16) for (k = 0; k < 16; k++) if (!g_nre_aim[k].aimed) { slot = k; break; }
        if (k == 16) k = slot;
        if (k >= 0 && k < 16) { g_nre_aim[k].id = g_np[j].id; g_nre_aim[k].aimed = h == 0x6699A29Cu ? GetTickCount() | 1 : 0; }
    }
    /* with npcsigdrop 0 the puppet plays its own reaction, which the host's anim vars would overwrite every frame: hold
     * them back meanwhile (hands up until stop_aimedat, at most 15 s; a shove 2.5 s) */
    if (j < 64 && !g_npcsigdrop) g_np_react[j] = h == 0x3183E869u ? 0 : (GetTickCount() + (h == 0x6699A29Cu ? 15000 : 2500)) | 1;
    logf_("nre: puppet %llu got %08x from its AI -> host", g_np[j].id, h);
    nre_send(g_np[j].id, h);
}
/* host: the joiner's player provoked our NPC */
static void nre_rx(const NpcReactPkt *k)
{
    BYTE *pc;
    if (k->seq < g_nre_rx_seq) g_nre_rx_seq = 0;
    if (k->seq == g_nre_rx_seq) return;
    g_nre_rx_seq = k->seq;
    if (!g_nresync || g_npc_role != 1 || !nre_forwarded(k->hash)) return;
    g_nre_rx++;
    /* the Social graph runs on the agent's state driver (agent vf+0x118, what its own AI signals go to through
     * FUN_109ff990), not on the pawn's (vf+0x78): sent to the pawn, nothing moved */
    {
        int i;
        BYTE *ag = NULL;
        for (i = 0; i < 64; i++)
            if (g_nagent[i].id == k->id && g_nagent[i].agent && !IsBadReadPtr(g_nagent[i].agent, 8) &&
                *(unsigned *)g_nagent[i].agent == (unsigned)(g_base + 0xEC5078) && !IsBadReadPtr(*(BYTE **)(g_nagent[i].agent + 4), 16) &&
                **(unsigned long long **)(g_nagent[i].agent + 4) == k->id) { ag = g_nagent[i].agent; break; }
        if (ag) { unsigned h = k->hash; ((void (__attribute__((thiscall)) *)(void *, unsigned *))(g_base + 0x9FF990))(ag, &h); }
        else if ((pc = pawn_comp_of(k->id))) pawn_state_event(pc, k->hash);
        else pc = NULL;
        logf_("nre: the joiner provoked NPC %llu: %08x %s", k->id, k->hash, ag ? "-> its agent" : pc ? "-> its pawn (no agent known)" : "(no such NPC here)");
    }
}

static void sig_tick(DWORD now)
{
    static DWORD drv_t;
    if (!g_sig_orig) sig_install();
    if (g_nmssync) { static int gi; if (!gi) { gi = 1; ms_guard_install(); } }
    if (now - drv_t > 500) {
        drv_t = now;
        g_sig_mydrv = player_ready(g_net_id) ? pawn_driver(g_net_id) : NULL;
        g_sig_avdrv = g_av_id ? pawn_driver(g_av_id) : NULL;
    }
    if (g_siglog && g_av_id) {
        /* which beautifiers drive the avatar (main +0x28, base +0x2C = NetPlayer): logged when they change */
        static unsigned last_m, last_b;
        void *hd = NULL, *bc;
        BYTE *obj = entity_obj(g_av_id, &hd);
        unsigned m = 0, b = 0;
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        bc = obj ? ((void *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0xFDEAD4)) : NULL;
        if (bc) {
            if (*(BYTE **)((BYTE *)bc + 0x28)) m = **(unsigned **)((BYTE *)bc + 0x28) - (unsigned)g_base;
            if (*(BYTE **)((BYTE *)bc + 0x2C)) b = **(unsigned **)((BYTE *)bc + 0x2C) - (unsigned)g_base;
        }
        if (m != last_m || b != last_b) { logf_("sig: avatar beautifiers main vt D+%X base vt D+%X", m, b); last_m = m; last_b = b; }
    }
    {
        static DWORD pl_t;
        if (g_plylog && now - pl_t >= 2000) { pl_t = now; ply_callers(); }
    }
    while (g_sig_r != g_sig_w) {
        unsigned h = g_sig_ring[g_sig_r & 511].hash, c = g_sig_ring[g_sig_r & 511].caller;
        void *d = g_sig_ring[g_sig_r & 511].drv;
        /* only listed signals: weapon ones (switch, select_*, drawweapon_now, shooting, reload) doubled what the weapon
         * sync already does and the avatar lost its weapon; door / heal graphs are first-person (arm-only animation,
         * cinematic beautifier, "Use Door" on the player's own target) and broke the avatar */
        int mine = d == g_sig_mydrv, tx;
        if (!mine && d != g_sig_avdrv) { nre_puppet_signal(d, h); nsg_host_signal(d, h); }
        tx = mine && (g_sigsync == 1 ? sig_listed(g_sig_allow, g_sig_nallow, h) :
                                                   g_sigsync == 2 && !sig_listed(g_sig_deny, g_sig_ndeny, h));
        g_sig_r++;
        if (g_siglog && (mine || d == g_sig_avdrv || g_siglog >= 3 || sig_watched(h)))
            logf_("sig: %s %08x from D+%X%s", mine ? "me" : d == g_sig_avdrv ? "avatar" : "npc", h, c, tx ? " -> peer" : "");
        else if (g_siglog >= 2 && !mine) {
            static unsigned nother;
            if (++nother <= 400) logf_("sig: other %p %08x from D+%X", d, h, c);
        }
        if (tx && (h == 0x33111508u || h == 0xC4A5E460u || h == 0x9F347422u)) door_target_send();
        if (tx) {
            memmove(g_sig_hist, g_sig_hist + 1, (SIG_N - 1) * 4);
            g_sig_hist[SIG_N - 1] = h; g_sig_seq++; g_sig_new_t = now;
            sig_send(); g_sig_sent_t = now;
        }
    }
    /* UDP can drop one: repeat the last packet twice, 100 ms apart */
    if (g_sig_seq && now - g_sig_new_t < 250 && now - g_sig_sent_t >= 100) { sig_send(); g_sig_sent_t = now; }
}

/* ---- doors (DOR1). The door graph's "Use Door" event (CGOStateEventFCXPawn req 6, Begin of Opening Door) runs
 * FUN_10727650(pawn comp) (stdcall): door id from the pawn's blackboard 0x3C06F343, its CDoor component (key
 * 11649A18), then FUN_106c4040(door comp, pawn handle): anim var 0x5B = door action (CDoor +0x4C), the door's
 * animation comp (FDF2F0) is bound to the pawn's animation (FUN_10524be0), weapon-safe zone in/out. So a door only
 * moves with its user's Pawn_Generic_Open_Door animation; calling it for an avatar that plays nothing did nothing.
 * Now: right before an open_door* signal goes out in SIG1 our player's door target goes out in DOR1, the peer puts it
 * in the avatar's blackboard, and the avatar's own door graph (from the signal) uses the door. ---- */
#define DOR_MAGIC 0x31524F44u      /* "DOR1" */
#define DOOR_BB_KEY 0x3C06F343u
typedef struct { unsigned magic, seq; unsigned long long door; int action, pad; } DoorPkt;   /* action = CDoor +0x4C */
#define DOOR_ACTION 0x4C            /* LastDoorAction (0 / 1 by the side the user stands on; descriptor 6C39A0) */
static int g_door_action;
static BYTE *door_comp(unsigned long long id)
{
    void *hd = NULL;
    BYTE *obj = id && id != ~0ULL ? entity_obj(id, &hd) : NULL, *dc;
    if (hd) (*(int *)((BYTE *)hd + 8))--;
    dc = obj ? ((BYTE *(__attribute__((thiscall)) *)(void *, void *))(g_base + 0x4E2CC0))(obj, (void *)(g_base + 0x1649A18)) : NULL;
    return dc && !IsBadWritePtr(dc, DOOR_ACTION + 4) ? dc : NULL;
}
static void *g_door_orig;
static BYTE *volatile g_door_av;      /* the avatar's pawn comp (set by door_tick) */
static volatile unsigned g_door_used; /* bumped by the detour when the avatar uses a door */
static unsigned g_door_seq, g_door_rx_seq;
static unsigned long long g_door_last;
static DWORD g_door_t, g_door_sent_t;
static int g_doorsync = 1;
static void __attribute__((stdcall)) door_hook(BYTE *pawn)
{
    ((void (__attribute__((stdcall)) *)(BYTE *))g_door_orig)(pawn);
    if (pawn && pawn == g_door_av) g_door_used++;
}
static void door_install(void)
{
    /* 727650: sub esp,8; test byte [1164CDEC],1 (10 bytes, position independent), then push ebx */
    static const BYTE pro[10] = { 0x83, 0xEC, 0x08, 0xF6, 0x05, 0xEC, 0xCD, 0x64, 0x11, 0x01 };
    if (g_door_orig) return;
    if (memcmp(g_base + 0x727650, pro, sizeof pro)) { logf_("door: unexpected bytes at 727650, no door hook"); g_door_orig = (void *)1; return; }
    g_door_orig = make_detour(g_base + 0x727650, 10, (void *)door_hook, 1);
    logf_("door: use-door hook on 727650 installed");
}
static void door_send(void)
{
    DoorPkt k = { DOR_MAGIC, g_door_seq, g_door_last, g_door_action, 0 };
    sendto(g_ns, (char *)&k, sizeof k, 0, (struct sockaddr *)&g_peer, sizeof g_peer);
}
/* called by sig_tick before it sends an open_door* signal */
static void door_target_send(void)
{
    if (!g_doorsync) return;
    BYTE *dc;
    /* the door code (6C43BE) sets our target (blackboard) and the door's action right after this signal */
    g_door_last = pawn_bb_u64(g_net_id, DOOR_BB_KEY);
    g_door_action = (dc = door_comp(g_door_last)) ? *(int *)(dc + DOOR_ACTION) : -1;
    g_door_seq++; g_door_t = g_door_sent_t = GetTickCount();
    logf_("door: our player opens door %llu, action %d -> peer", g_door_last, g_door_action);
    door_send();
}
static void door_rx(const DoorPkt *k)
{
    BYTE *dc;
    if (k->seq < g_door_rx_seq) g_door_rx_seq = 0;      /* the peer's probe restarted */
    if (k->seq == g_door_rx_seq) return;
    g_door_rx_seq = k->seq;
    if (!g_doorsync || !g_av_id) return;
    /* the door's action picks the side of the animation: left as it was here, the avatar jumped to the other side */
    if ((dc = door_comp(k->door)) && (k->action == 0 || k->action == 1)) *(int *)(dc + DOOR_ACTION) = k->action;
    logf_("door: the peer opens door %llu, action %d (door comp %p) -> avatar's target: %d", k->door, k->action, dc,
          pawn_bb_set_u64(g_av_id, DOOR_BB_KEY, k->door));
}
static void door_tick(DWORD now)
{
    static unsigned seen;
    if (!g_door_orig) door_install();
    g_door_av = g_av_id ? pawn_comp_of(g_av_id) : NULL;
    if (g_door_used != seen) { seen = g_door_used; logf_("door: the avatar used door %llu", pawn_bb_u64(g_av_id, DOOR_BB_KEY)); }
    /* repeat twice, 100 ms apart, like SIG1 (DOR1 goes out before the signal, so it arrives first) */
    if (g_doorsync && g_door_seq && now - g_door_t < 250 && now - g_door_sent_t >= 100) { door_send(); g_door_sent_t = now; }
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
    if (g_bodymat) {
        /* the cached body dies with the player (death, rescue, respawn) and its memory is freed: the 1 s status line read
         * its matrix and crashed the host. Drop it when it no longer looks like our body, or is away from our entity. */
        void *hd = NULL;
        BYTE *me = g_net_id ? entity_obj(g_net_id, &hd) : NULL;
        int bad = IsBadReadPtr(g_body, 4) || *(unsigned *)g_body != (unsigned)(g_base + RVA_BODY_VTABLE) || IsBadReadPtr(g_bodymat, 0x40);
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (!bad && me) {
            float dx = *(float *)(g_bodymat + 0x30) - *(float *)(me + 0x60), dy = *(float *)(g_bodymat + 0x34) - *(float *)(me + 0x64);
            if (dx * dx + dy * dy > 25.0f) bad = 1;
        }
        if (bad) { logf_("our cached body is gone (death, rescue or respawn): looking for it again"); g_body = NULL; g_bodymat = NULL; g_findtries = 0; }
    }
    if (!g_bodymat || IsBadReadPtr(g_body, 4) || *(unsigned *)g_body != (unsigned)(g_base + RVA_BODY_VTABLE)) {
        /* the body search scans all memory (a visible hitch): retry every 3 s at first, then back off to 60 s */
        if (now - g_net_lastfind > (g_findtries < 5 ? 3000u : 60000u)) {
            char c[64];
            g_net_lastfind = now; g_findtries++;
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
        if (r == (int)sizeof(NpcDepPkt) && rb.magic == NDP_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) ndp_rx((const NpcDepPkt *)&rb); continue; }
        if (r == (int)sizeof(NpcMsPkt) && rb.magic == NMS_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) nms_rx((const NpcMsPkt *)&rb); continue; }
        if (r == (int)sizeof(NpcAnimPkt) && rb.magic == NANM_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) npc_anim_rx((const NpcAnimPkt *)&rb); continue; }
        if (r == (int)sizeof(NpcHitPkt) && rb.magic == NSHT_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) npc_shot_apply((const NpcHitPkt *)&rb); continue; }
        if (r == (int)sizeof(NpcHitPkt) && rb.magic == NHIT_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) npc_hit_apply((const NpcHitPkt *)&rb); continue; }
        if (r > 4 && r < 68 && rb.magic == NAM_MAGIC) {
            /* only while the peer's game is really there: after it left, its relay keeps sending the name for ~20 s and
             * every one of them showed "подключается" / "отключился" again */
            if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr && !g_peer_bye && g_net_rx && GetTickCount() - g_net_lastrx < 2000) {
                char nm[64];
                memcpy(nm, (char *)&rb + 4, r - 4);
                nm[r - 4] = 0;
                if (!g_peer_named || strcmp(nm, g_peer_nick)) {
                    strcpy(g_peer_nick, nm);
                    if (!g_peer_named) notice_player(g_peer_nick, L"подключается");
                    g_peer_named = 1;
                    logf_("notice: the other player is %s", g_peer_nick);
                }
            }
            continue;
        }
        if (r == 16 && rb.magic == BYE_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) { if (!g_peer_bye) logf_("bye: the peer is leaving"); g_peer_bye = 1; g_bye_at = GetTickCount(); } continue; }
        if (r == (int)sizeof(RldPkt) && rb.magic == RLD_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) rld_rx((const RldPkt *)&rb); continue; }
        if (r == (int)sizeof(HitPkt) && rb.magic == HIT_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) hit_apply((const HitPkt *)&rb); continue; }
        if (r >= (int)offsetof(VehPkt, e) && rb.magic == VEH_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) veh_rx((const VehPkt *)&rb, r); continue; }
        if (r == (int)sizeof(NpcSigPkt) && rb.magic == NSG_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) nsg_rx((const NpcSigPkt *)&rb); continue; }
        if (r == (int)sizeof(NpcReactPkt) && rb.magic == NRE_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) nre_rx((const NpcReactPkt *)&rb); continue; }
        if (r == (int)sizeof(DoorPkt) && rb.magic == DOR_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) door_rx((const DoorPkt *)&rb); continue; }
        if (r == (int)sizeof(SigPkt) && rb.magic == SIG_MAGIC) { if (from.sin_addr.s_addr == g_peer.sin_addr.s_addr) sig_rx((const SigPkt *)&rb); continue; }
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
    if (g_npc_role == 2 && g_join_tp < 4 && g_net_rx > 10 && now - g_net_lastrx < 200 && g_remote.pos[0] != 0.0f && player_ready(g_net_id) &&
        g_bodymat && !IsBadWritePtr(g_bodymat, 0x40) && *(unsigned *)g_body == (unsigned)(g_base + RVA_BODY_VTABLE)) {
        /* the joiner loads the host's save, so it starts where the host stood when it saved; put it 2 m beside the host
         * now (the physics body's matrix as "tpb" does, and the entity position as "setpos"). Right after loading the
         * player was pushed out 80 m away: the host's avatar had been spawned on the same spot. The move comes 1 s after
         * the first contact (the avatar spawns right after it, see av_tick), is checked 4 s later, and another side of
         * the host is tried up to 4 times. */
        static DWORD first, moved;
        static float tx, ty;
        float d2 = (*(float *)(g_bodymat + 0x30) - tx) * (*(float *)(g_bodymat + 0x30) - tx) + (*(float *)(g_bodymat + 0x34) - ty) * (*(float *)(g_bodymat + 0x34) - ty);
        if (!first) first = now;
        if (moved && now - moved > 4000 && d2 < 9.0f) {
            logf_("join: our player stayed next to the host (try %d)", g_join_tp);
            g_join_tp = 4;
        } else if (!moved && now - first > 1000 && (d2 = (*(float *)(g_bodymat + 0x30) - g_remote.pos[0]) * (*(float *)(g_bodymat + 0x30) - g_remote.pos[0]) +
                   (*(float *)(g_bodymat + 0x34) - g_remote.pos[1]) * (*(float *)(g_bodymat + 0x34) - g_remote.pos[1])) >= 4.0f && d2 <= 100.0f) {
            logf_("join: our player is already %.1f m from the host, no move needed", sqrtf(d2));
            g_join_tp = 4;
        } else if (now - first > 1000 && (!moved || now - moved > 4000)) {
            static const float ox[4] = { 2.0f, -2.0f, 0.0f, 0.0f }, oy[4] = { 0.0f, 0.0f, 2.0f, -2.0f };
            float x = g_remote.pos[0] + ox[g_join_tp], y = g_remote.pos[1] + oy[g_join_tp], z = g_remote.pos[2] + 0.3f;
            void *hd = NULL;
            BYTE *me = entity_obj(g_net_id, &hd);
            if (hd) (*(int *)((BYTE *)hd + 8))--;
            logf_("join: moving our player from (%.1f %.1f %.1f) next to the host (%.1f %.1f %.1f), try %d", *(float *)(g_bodymat + 0x30),
                  *(float *)(g_bodymat + 0x34), *(float *)(g_bodymat + 0x38), x, y, z, g_join_tp + 1);
            *(float *)(g_bodymat + 0x30) = x; *(float *)(g_bodymat + 0x34) = y; *(float *)(g_bodymat + 0x38) = z;
            if (me) { *(float *)(me + 0x60) = x; *(float *)(me + 0x64) = y; *(float *)(me + 0x68) = z; }
            tx = x; ty = y; moved = now; g_join_tp++;
        }
    }
    {
        /* our player gone from the world for 2 s (back in the main menu, or loading): tell the peer we left, as on
         * quitting - leaving for the menu showed no "отключился" on the other PC. Back in the world, the packets
         * start a new session there ("подключается"). */
        static DWORD gone_since;
        static int left;
        void *hd = NULL;
        BYTE *me = g_net_id ? entity_obj(g_net_id, &hd) : NULL;
        if (hd) (*(int *)((BYTE *)hd + 8))--;
        if (me) {
            gone_since = 0;
            if (left) { left = 0; logf_("bye: our player is back in the world"); }
        } else if (!gone_since) gone_since = now | 1;
        else if (!left && now - gone_since > 2000) {
            left = 1;
            logf_("bye: our player has been out of the world for 2 s (menu or loading)");
            bye_send();
        }
        /* the joiner plays in the host's world: when the host leaves (BYE1) or goes silent, it goes back to the main
         * menu, once per host session. It waits 3 s first: the host's own load sends a bye too and its RLD1 then
         * restarts us with that save instead, and "Игрок <name> отключился" stays readable; packets of a new session
         * cancel it. */
        if (g_npc_role == 2 && g_net_rx) {
            static DWORD kick_at;
            static int kick_stage, kicked;
            int gone = (g_peer_bye && (int)(g_net_lastrx - g_bye_at) < 2000) || now - g_net_lastrx > AV_SILENT_MS;
            if (!gone) {
                if (kick_stage) logf_("menu: the host is back - staying");
                kick_stage = kicked = 0;
            } else if (me && !kicked && !g_quitting) {
                if (!kick_stage) { kick_stage = 1; kick_at = (now + 3000) | 1; logf_("menu: the host %s", g_peer_bye ? "left" : "is silent"); }
                else if (kick_stage == 1 && (int)(now - kick_at) >= 0) {
                    kick_stage = 2; kick_at = (now + 3000) | 1;
                    notice_w(L"Хост отключился: выход в главное меню");
                } else if (kick_stage == 2 && (int)(now - kick_at) >= 0) {
                    kick_stage = 0; kicked = 1;
                    quit_to_menu("the host left");
                }
            }
        }
    }
    av_tick(now);
    rld_host_tick(now);
    hp_tick(now);
    map_tick(now);
    notice_tick();
    world_tick(now);
    npc_host_tick(now);
    hit_tick(now);
    dumpd_tick(now);
    npc_join_tick(now);
    veh_tick(now);
    sig_tick(now);
    door_tick(now);
    /* send at 20 Hz */
    if ((g_bodymat || g_net_id) && now - g_net_lastsend >= 50 && player_ready(g_net_id)) {
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
static int player_ready(unsigned long long me);
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
    if (!player_ready(me)) return;
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
static BOOL WINAPI h_PeekMessageA(LPMSG m, HWND h, UINT a, UINT b, UINT c) { if (!g_quitting) { hold_tick(); net_tick(); watchd_tick(); fire_latch_tick(); pump_main(); } return o_PeekMessageA(m, h, a, b, c); }
static BOOL WINAPI h_PeekMessageW(LPMSG m, HWND h, UINT a, UINT b, UINT c) { if (!g_quitting) { hold_tick(); net_tick(); watchd_tick(); fire_latch_tick(); pump_main(); } return o_PeekMessageW(m, h, a, b, c); }

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

/* ---- "Cooperative" under Story Mode ----
 * Menus are code, not data (menus.fat holds only DLC map pictures, ui\*.mgb only layout). A list page builds its
 * rows as action objects passed to FUN_10cdbb80(page, UTF-16 label, char enabled, action) (thiscall, RET 0xC);
 * vf+0x40 FUN_10cdba50 clears the list (deletes each action through its vf 0 with 1); vf+0x10 is the page's update
 * (thiscall, float dt). The Story Mode page (vtable 0x10EBB120) gets its rows from FUN_108c9c50 (ECX = page: Continue
 * and Load Game when there are saves, New Story), called from its update once the save list is read.
 * We detour FUN_108c9c50: the page first shows "Singleplayer" (the game's own rows) and "Cooperative" (host or join,
 * then the same Continue / Load Game rows, with start-coop doing the Steam side). Labels are English: the English
 * menu font has no Cyrillic (Russian text showed as "?"). Our rows reuse the Quit action: 0x78 bytes from the game
 * allocator FUN_10228f30(size, 0) (cdecl), base ctor FUN_10188e20(page, 0) (thiscall), vtable 0x10EA23EC (8 slots);
 * its slot 5 (thiscall, one stack argument, called from the action's state machine FUN_101886f0) shows the Quit
 * box (FUN_10707760) and returns 1, our copy of the vtable has our function there and byte
 * +0x74 holds the row code. Sub-pages are the list cleared and built again from the update hook (never inside the
 * action, which the clear deletes). Once the page has not updated for a second (left), it starts at the top again.
 * Bridge to start-coop.ps1 -Role menu: we write bin\coop_menu.txt (host | join | pick <steamid> | cancel), it writes
 * bin\coop_menu_state.txt (UTF-8: line 1 the status, then "<steamid>\t<label>" per friend's game found, or "@play"
 * once a host is taken - Steam Join Game picks one without a row, so the friends page must follow the file). */
#define SM_VT    0xEBB120
#define SM_ROWS  0x8C9C50
#define MM_MAXH  4
enum { MM_TOP, MM_SP, MM_COOP, MM_FRIENDS, MM_PLAY };
static void *g_mm_rows, *g_mm_update;    /* trampoline to FUN_108c9c50, the page's own update */
static void *g_mm_vt[8];                 /* Quit action vtable with our slot 5 */
static int g_mm_sub;
static volatile LONG g_mm_click = -1;
static int g_mm_state;                   /* start-coop wrote a state file (it runs in menu mode) */
static wchar_t g_mm_status[96];
static int g_mm_nh;
static int g_mm_play;                    /* the state file says "@play": a host is taken (Steam Join Game too) */
static char g_mm_hid[MM_MAXH][24];
static wchar_t g_mm_hl[MM_MAXH][96];
static FILETIME g_mm_stamp;
static DWORD g_mm_poll, g_mm_seen;
static char g_mm_dir[MAX_PATH];          /* bin\ with the trailing backslash */

/* slot 5 is thiscall with one stack argument (the Quit one ends RET 4); returns "done" in AL */
static int __attribute__((thiscall)) mm_act(BYTE *self, void *arg)
{
    (void)arg;
    InterlockedExchange(&g_mm_click, self[0x74]);
    return 1;
}
static void mm_add(void *page, const wchar_t *label, int code, int enabled)
{
    BYTE *a = ((void *(__cdecl *)(unsigned, int))(g_base + 0x228F30))(0x78, 0);
    if (!a) return;
    ((void *(__attribute__((thiscall)) *)(void *, void *, int))(g_base + 0x188E20))(a, page, 0);
    *(void ***)a = g_mm_vt;
    a[0x74] = (BYTE)code;
    ((int (__attribute__((thiscall)) *)(void *, const wchar_t *, char, void *))(g_base + 0xCDBB80))(page, label, (char)enabled, a);
}
static void mm_request(const char *text)
{
    char p[MAX_PATH], t[MAX_PATH];
    FILE *f;
    snprintf(t, sizeof t, "%scoop_menu.tmp", g_mm_dir);
    snprintf(p, sizeof p, "%scoop_menu.txt", g_mm_dir);
    if (!(f = fopen(t, "wb"))) { logf_("menu: cannot write %s", t); return; }
    fprintf(f, "%s\r\n", text);
    fclose(f);
    MoveFileExA(t, p, MOVEFILE_REPLACE_EXISTING);
    logf_("menu: request '%s' for start-coop", text);
}
/* re-reads coop_menu_state.txt when it changed (or force); 1 = something changed */
static int mm_poll(int force)
{
    char p[MAX_PATH], buf[4096], *ln, *nx, *tab;
    WIN32_FILE_ATTRIBUTE_DATA fa;
    FILETIME st = {0, 0};
    int have, n = 0;
    FILE *f;
    DWORD now = GetTickCount();
    if (!force && now - g_mm_poll < 1000) return 0;
    g_mm_poll = now;
    snprintf(p, sizeof p, "%scoop_menu_state.txt", g_mm_dir);
    have = GetFileAttributesExA(p, GetFileExInfoStandard, &fa);
    if (have) st = fa.ftLastWriteTime;
    if (!force && have == g_mm_state && CompareFileTime(&st, &g_mm_stamp) == 0) return 0;
    g_mm_state = have; g_mm_stamp = st;
    g_mm_status[0] = 0; g_mm_nh = 0; g_mm_play = 0;
    if (!have || !(f = fopen(p, "rb"))) return 1;
    n = (int)fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n > 0 ? n : 0] = 0;
    ln = buf;
    if (!strncmp(ln, "\xEF\xBB\xBF", 3)) ln += 3;
    for (n = 0; ln && *ln; ln = nx, n++) {
        if ((nx = strchr(ln, '\n'))) *nx++ = 0;
        if (*ln && ln[strlen(ln) - 1] == '\r') ln[strlen(ln) - 1] = 0;
        if (n == 0) { MultiByteToWideChar(CP_UTF8, 0, ln, -1, g_mm_status, 96); g_mm_status[95] = 0; continue; }
        if (!strcmp(ln, "@play")) { g_mm_play = 1; continue; }
        if (!(tab = strchr(ln, '\t')) || tab == ln || g_mm_nh >= MM_MAXH) continue;
        *tab = 0;
        lstrcpynA(g_mm_hid[g_mm_nh], ln, 24);
        if (!MultiByteToWideChar(CP_UTF8, 0, tab + 1, -1, g_mm_hl[g_mm_nh], 96)) lstrcpyW(g_mm_hl[g_mm_nh], L"?");
        g_mm_hl[g_mm_nh][95] = 0;
        g_mm_nh++;
    }
    return 1;
}
static void __attribute__((thiscall)) mm_rows(void *page)
{
    int k;
    mm_poll(1);
    switch (g_mm_sub) {
    case MM_TOP:
        mm_add(page, L"Singleplayer", 7, 1);
        mm_add(page, L"Cooperative", 1, 1);
        break;
    case MM_SP:
        ((void (__attribute__((thiscall)) *)(void *))g_mm_rows)(page);
        mm_add(page, L"Back", 4, 1);
        break;
    case MM_COOP:
        if (!g_mm_state) mm_add(page, L"Needs start-coop -Role menu", 6, 0);
        mm_add(page, L"Host a game", 2, g_mm_state);
        mm_add(page, L"Join a friend's game", 3, g_mm_state);
        mm_add(page, L"Back", 4, 1);
        break;
    case MM_FRIENDS:
        for (k = 0; k < g_mm_nh; k++) mm_add(page, g_mm_hl[k], 10 + k, 1);
        mm_add(page, g_mm_status[0] ? g_mm_status : L"Looking for friends' games...", 6, 0);
        mm_add(page, L"Back", 4, 1);
        break;
    default:   /* MM_PLAY: the game's own rows to load the save, our status, a way out */
        ((void (__attribute__((thiscall)) *)(void *))g_mm_rows)(page);
        if (g_mm_status[0]) mm_add(page, g_mm_status, 6, 0);
        mm_add(page, L"Stop co-op", 5, 1);
    }
    if (g_mm_sub != MM_SP && g_mm_sub != MM_PLAY) *(int *)((BYTE *)page + 0x204) = -1;   /* the New Story row */
    /* the end of FUN_108c9c50: give the list the input focus (without it no row is highlighted, Enter does nothing) */
    ((void (__attribute__((thiscall)) *)(void *, int, void *))(g_base + 0xAA5180))(*(void **)((BYTE *)page + 0x14), 0, *(void **)((BYTE *)page + 8));
}
static void mm_rebuild(void *page)
{
    ((void (__attribute__((thiscall)) *)(void *))(g_base + 0xCDBA50))(page);
    mm_rows(page);
}
static void __attribute__((thiscall)) mm_update(void *page, void *dt)
{
    LONG c;
    char req[48];
    DWORD now = GetTickCount();
    if (now - g_mm_seen > 1000 && g_mm_sub != MM_TOP) { logf_("menu: Story Mode page entered again, top level"); g_mm_sub = MM_TOP; }
    g_mm_seen = now;
    ((void (__attribute__((thiscall)) *)(void *, void *))g_mm_update)(page, dt);
    if (g_quitting) return;
    /* the chosen row's action is still queued on the page (+0x54 list, +0x58 count) until its state machine is done:
     * clearing the list deletes it, so wait for an empty queue */
    if (*(int *)((BYTE *)page + 0x58)) return;
    c = InterlockedExchange(&g_mm_click, -1);
    if (c < 0) {
        if (mm_poll(0) && g_mm_sub >= MM_COOP) {
            /* Steam Join Game picks the host without a row: go to the load rows like a pick */
            if (g_mm_play && g_mm_sub == MM_FRIENDS) { logf_("menu: host taken by start-coop (Steam Join Game)"); g_mm_sub = MM_PLAY; }
            mm_rebuild(page);
        }
        return;
    }
    logf_("menu: row %ld chosen (page %d)", c, g_mm_sub);
    if (c == 7) g_mm_sub = MM_SP;
    else if (c == 1) g_mm_sub = MM_COOP;
    else if (c == 2) { mm_request("host"); g_mm_sub = MM_PLAY; }
    else if (c == 3) { mm_request("join"); g_mm_sub = MM_FRIENDS; }
    else if (c == 4) { if (g_mm_sub == MM_FRIENDS) mm_request("cancel"); g_mm_sub = g_mm_sub == MM_FRIENDS ? MM_COOP : MM_TOP; }
    else if (c == 5) { mm_request("cancel"); g_mm_sub = MM_COOP; }
    else if (c >= 10 && c < 10 + g_mm_nh) { snprintf(req, sizeof req, "pick %s", g_mm_hid[c - 10]); mm_request(req); g_mm_sub = MM_PLAY; }
    else return;
    mm_rebuild(page);
}
static void menu_install(void)
{
    void **vt = (void **)(g_base + SM_VT);
    BYTE *rows = g_base + SM_ROWS;
    DWORD old;
    char *s;
    GetModuleFileNameA(g_self, g_mm_dir, MAX_PATH);
    if ((s = strrchr(g_mm_dir, '\\'))) s[1] = 0;
    /* SUB ESP,0x9C at FUN_108c9c50 (6 bytes, moved to the trampoline) */
    if (vt[4] != (void *)(g_base + 0x8C9FA0) || memcmp(rows, "\x81\xEC\x9C\x00\x00\x00", 6) ||
        *(void **)(g_base + 0xEA23EC + 5 * 4) != (void *)(g_base + 0x7F8EE0)) {
        logf_("menu: unexpected Story Mode page / Quit action code, no co-op rows");
        return;
    }
    memcpy(g_mm_vt, g_base + 0xEA23EC, sizeof g_mm_vt);
    g_mm_vt[5] = (void *)mm_act;
    if (!VirtualProtect(vt + 4, 4, PAGE_READWRITE, &old)) { logf_("menu: vtable not writable (%lu)", GetLastError()); return; }
    g_mm_update = vt[4]; vt[4] = (void *)mm_update;
    VirtualProtect(vt + 4, 4, old, &old);
    g_mm_rows = make_detour(rows, 6, (void *)mm_rows, 1);
    logf_("menu: Singleplayer / Cooperative rows hooked into Story Mode (bridge files in %s)", g_mm_dir);
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
    menu_install();
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
