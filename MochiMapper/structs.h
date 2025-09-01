#pragma once
#include <windows.h>

// Helpers
#define PRINT_ERR(x) printf("[-] ERROR: %s: %d\n", (x), GetLastError())
#define PRINT_SUCC(x,...) printf("[+] SUCCESS: " x "\n", ##__VA_ARGS__)
#define PRINT_INF(x) printf("[i] %s\n", (x))

// Target Function if DLL
#define FUNCTION_NAME "" // YOUR EXPORTED FUNCTION NAME HERE (if needed)
#define PE_ARGS L"coffee exit" // YOUR CMD ARGS HERE

// API Hashing Part
#define HASHA(API)		(HashStringDjb2A((PCHAR) API))
#define INITIAL_HASH	#-INITIAL_HASH_VALUE-#  
#define INITIAL_SEED	#-INITIAL_SEED_VALUE-# 

// Structure to hold the PE headers
typedef struct _HEADERS {

	// Covering basic PE parsing needs
	PIMAGE_DOS_HEADER           pDOSHeader;
	PIMAGE_NT_HEADERS           pNTHeaders;
	PIMAGE_SECTION_HEADER       pSectionHeader;

	// Later, it is possible to check if the target PE is a DLL or EXE. This is important for execution
	BOOL isDll;
	// For convenience, we also hold somde data directory values
	IMAGE_DATA_DIRECTORY* pImportAddrTable;
	IMAGE_DATA_DIRECTORY* pBaseRelocTable;
	IMAGE_DATA_DIRECTORY* pExportDirectory;

	// Those are "optional". As explained earlier, this is to ensure the loader is more robust
	IMAGE_DATA_DIRECTORY* pTlsDirectory;
	IMAGE_DATA_DIRECTORY* pExceptionDirectory;

} HEADERS, * PHEADERS;

// typedefs
typedef FARPROC(*IatHookCallback)(LPCSTR dllName, LPCSTR funcName, FARPROC resolved,FARPROC* out);
FARPROC CmdlineHookCB(LPCSTR dll, LPCSTR func, FARPROC resolved, FARPROC* out);
typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef BOOL(WINAPI* MAIN)();

// CMD Hooking
typedef LPSTR(WINAPI* PFN_GetCommandLineA)(void);
typedef LPWSTR(WINAPI* PFN_GetCommandLineW)(void);
typedef int(__cdecl* PFN___getmainargs)(int*, char***, char***, int, void*);
typedef int(__cdecl* PFN___wgetmainargs)(int*, wchar_t***, wchar_t***, int, void*);
typedef char*** (__cdecl* PFN___p___argv)(void);
typedef wchar_t*** (__cdecl* PFN___p___wargv)(void);
typedef int* (__cdecl* PFN___p___argc)(void);
typedef VOID(WINAPI* PFN_ExitProcess)(UINT);
typedef void(__cdecl* PFN_exitlike)(int);

// GLobal
extern PFN_GetCommandLineA  g_real_GetCommandLineA;
extern PFN_GetCommandLineW  g_real_GetCommandLineW;
extern PFN___getmainargs    g_real___getmainargs;
extern PFN___wgetmainargs   g_real___wgetmainargs;
extern PFN___p___argv       g_real___p___argv;
extern PFN___p___wargv      g_real___p___wargv;
extern PFN___p___argc       g_real___p___argc;
extern PFN_ExitProcess      g_real_ExitProcess;
extern PFN_exitlike         g_real_exitlike;

// Hook implementation
LPSTR     WINAPI hookGetCommandLineA(void);
LPWSTR    WINAPI hookGetCommandLineW(void);
int       __cdecl hook__getmainargs(int*, char***, char***, int, void*);
int       __cdecl hook__wgetmainargs(int*, wchar_t***, wchar_t***, int, void*);
char*** __cdecl hook__p___argv(void);
wchar_t*** __cdecl hook__p___wargv(void);
int* __cdecl hook__p___argc(void);
VOID      WINAPI hookExitProcess(UINT);
void      __cdecl hookexit(int);

// Args Spoofing
BOOL SetMappedModuleArgsW(LPCWSTR imagePath, LPCWSTR argsTail);