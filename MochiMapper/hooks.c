#include "structs.h"
#include <string.h>


PFN_GetCommandLineA  g_real_GetCommandLineA = NULL;
PFN_GetCommandLineW  g_real_GetCommandLineW = NULL;
PFN___getmainargs    g_real___getmainargs = NULL;
PFN___wgetmainargs   g_real___wgetmainargs = NULL;
PFN___p___argv       g_real___p___argv = NULL;
PFN___p___wargv      g_real___p___wargv = NULL;
PFN___p___argc       g_real___p___argc = NULL;
PFN_ExitProcess      g_real_ExitProcess = NULL;
PFN_exitlike         g_real_exitlike = NULL;

extern LPWSTR     GetCmdLineW_Spoof(void);
extern LPSTR      GetCmdLineA_Spoof(void);
extern int* GetArgcPtr_Spoof(void);
extern wchar_t*** GetWargvPtr_Spoof(void);
extern char*** GetArgvPtr_Spoof(void);

// Hooks

LPSTR WINAPI hookGetCommandLineA(void) {
    LPSTR s = GetCmdLineA_Spoof();
    if (s) return s;
    return g_real_GetCommandLineA ? g_real_GetCommandLineA() : GetCommandLineA();
}

LPWSTR WINAPI hookGetCommandLineW(void) {
    LPWSTR s = GetCmdLineW_Spoof();
    if (s) return s;
    return g_real_GetCommandLineW ? g_real_GetCommandLineW() : GetCommandLineW();
}

int __cdecl hook__getmainargs(int* argc, char*** argv, char*** env, int wildcard, void* startinfo) {
    // Option 1: fully spoof
    if (argc) *argc = *GetArgcPtr_Spoof();
    if (argv) *argv = *GetArgvPtr_Spoof();
    // leave env as original: ask real CRT for env pointer if available
    if (env && g_real___getmainargs) {
        int tmp_argc = 0; char** tmp_argv = NULL; char** tmp_env = NULL;
        g_real___getmainargs(&tmp_argc, &tmp_argv, &tmp_env, wildcard, startinfo);
        *env = tmp_env;
        return 0;
    }
    return 0;
}

int __cdecl hook__wgetmainargs(int* argc, wchar_t*** wargv, wchar_t*** wenv, int wildcard, void* startinfo) {
    if (argc) *argc = *GetArgcPtr_Spoof();
    if (wargv) *wargv = *GetWargvPtr_Spoof();
    if (wenv && g_real___wgetmainargs) {
        int ta = 0; wchar_t** tv = NULL; wchar_t** te = NULL;
        g_real___wgetmainargs(&ta, &tv, &te, wildcard, startinfo);
        *wenv = te;
        return 0;
    }
    return 0;
}

char*** __cdecl hook__p___argv(void) {
    if (g_real___p___argv) return g_real___p___argv();
    return NULL;
}

wchar_t*** __cdecl hook__p___wargv(void) {
    if (g_real___p___wargv) return g_real___p___wargv();
    return NULL;
}

int* __cdecl hook__p___argc(void) {
    if (g_real___p___argc) return g_real___p___argc();
    static int zero = 0; return &zero;
}

VOID WINAPI hookExitProcess(UINT code) {
    if (g_real_ExitProcess) g_real_ExitProcess(code);
}

void __cdecl hookexit(int code) {
    if (g_real_exitlike) g_real_exitlike(code);
}


static int is_crt(const char* dll) {
    return dll &&
        (_stricmp(dll, "ucrtbase.dll") == 0 ||
            _stricmp(dll, "msvcrt.dll") == 0 ||
            _stricmp(dll, "vcruntime140.dll") == 0);
}

// Masquerading CMD arguments
FARPROC CmdlineHookCB(LPCSTR dll, LPCSTR func, FARPROC resolved, FARPROC* out)
{
    if (!dll || !func || !out) return NULL;

    // Win32 APIs from kernel32/kernelbase 
    if (_stricmp(func, "GetCommandLineA") == 0) { g_real_GetCommandLineA = (PFN_GetCommandLineA)resolved; *out = (FARPROC)hookGetCommandLineA; return *out; }
    if (_stricmp(func, "GetCommandLineW") == 0) { g_real_GetCommandLineW = (PFN_GetCommandLineW)resolved; *out = (FARPROC)hookGetCommandLineW; return *out; }
    if (_stricmp(func, "ExitProcess") == 0) { g_real_ExitProcess = (PFN_ExitProcess)resolved;     *out = (FARPROC)hookExitProcess;     return *out; }

    // CRT family
    if (is_crt(dll)) {
        if (_stricmp(func, "__getmainargs") == 0) { g_real___getmainargs = (PFN___getmainargs)resolved;   *out = (FARPROC)hook__getmainargs;  return *out; }
        if (_stricmp(func, "__wgetmainargs") == 0) { g_real___wgetmainargs = (PFN___wgetmainargs)resolved;  *out = (FARPROC)hook__wgetmainargs; return *out; }
        if (_stricmp(func, "__p___argv") == 0) { g_real___p___argv = (PFN___p___argv)resolved;      *out = (FARPROC)hook__p___argv;     return *out; }
        if (_stricmp(func, "__p___wargv") == 0) { g_real___p___wargv = (PFN___p___wargv)resolved;     *out = (FARPROC)hook__p___wargv;    return *out; }
        if (_stricmp(func, "__p___argc") == 0) { g_real___p___argc = (PFN___p___argc)resolved;      *out = (FARPROC)hook__p___argc;     return *out; }
        if (_stricmp(func, "exit") == 0 || _stricmp(func, "_Exit") == 0 ||
            _stricmp(func, "_exit") == 0 || _stricmp(func, "quick_exit") == 0) {
            g_real_exitlike = (PFN_exitlike)resolved; *out = (FARPROC)hookexit; return *out;
        }
    }

    return NULL;
}
