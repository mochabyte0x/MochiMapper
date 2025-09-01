#include "structs.h"
#include <shellapi.h> 
#include <string.h>

static LPWSTR  g_cmdlineW = NULL;
static LPSTR   g_cmdlineA = NULL;
static int     g_argc = 0;
static wchar_t** g_wargv = NULL;
static char** g_argv = NULL;

// simple heap helpers
static void* zalloc(size_t n) { return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n); }
static void  zfree(void* p) { if (p) HeapFree(GetProcessHeap(), 0, p); }

// convert wide to ansi 
static LPSTR w2a(const wchar_t* w) {
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, NULL, 0, NULL, NULL);
    if (n <= 0) return NULL;
    LPSTR a = (LPSTR)zalloc(n);
    WideCharToMultiByte(CP_ACP, 0, w, -1, a, n, NULL, NULL);
    return a;
}

static void FreeArgsState(void) {
    if (g_wargv) { LocalFree(g_wargv); g_wargv = NULL; } // CommandLineToArgvW uses LocalAlloc
    if (g_argv) {
        for (int i = 0; i < g_argc; i++) zfree(g_argv[i]);
        zfree(g_argv); g_argv = NULL;
    }
    zfree(g_cmdlineA); g_cmdlineA = NULL;
    zfree(g_cmdlineW); g_cmdlineW = NULL;
    g_argc = 0;
}

// Setting raw command line and argv from an image path + args tail.
// Example: SetMappedModuleArgsW(L"C:\\path\\app.exe", L"--foo \"bar baz\"");
BOOL SetMappedModuleArgsW(LPCWSTR imagePath, LPCWSTR argsTail)
{
    if (!imagePath) return FALSE;
    FreeArgsState();

    // Build raw wide cmdline:  "<imagePath>" + (" " + argsTail)
    size_t lenI = wcslen(imagePath);
    size_t lenA = argsTail ? wcslen(argsTail) : 0;
    size_t need = 3 + lenI + (lenA ? 1 + lenA : 0); // quotes + space
    g_cmdlineW = (LPWSTR)zalloc((need + 1) * sizeof(WCHAR));
    if (!g_cmdlineW) return FALSE;

    wcscpy(g_cmdlineW, L"\"");
    wcscat(g_cmdlineW, imagePath);
    wcscat(g_cmdlineW, L"\"");
    if (lenA) { wcscat(g_cmdlineW, L" "); wcscat(g_cmdlineW, argsTail); }

    // ANSI raw cmdline
    g_cmdlineA = w2a(g_cmdlineW);

    // Parse argv (wide) using system rules
    g_wargv = CommandLineToArgvW(g_cmdlineW, &g_argc);
    if (!g_wargv) { FreeArgsState(); return FALSE; }

    // Build ANSI argv mirroring wide argv
    g_argv = (char**)zalloc(sizeof(char*) * (g_argc + 1));
    if (!g_argv) { FreeArgsState(); return FALSE; }
    for (int i = 0; i < g_argc; i++) g_argv[i] = w2a(g_wargv[i]);
    g_argv[g_argc] = NULL;

    return TRUE;
}

LPWSTR GetCmdLineW_Spoof(void) { return g_cmdlineW; }
LPSTR GetCmdLineA_Spoof(void) { return g_cmdlineA; }
int* GetArgcPtr_Spoof(void) { return &g_argc; }
wchar_t*** GetWargvPtr_Spoof(void) { return &g_wargv; }
char*** GetArgvPtr_Spoof(void) { return &g_argv; }