# MochiMapper

A minimal **manual PE loader** that maps a PE from the `.rsrc` section into memory and emulates some parts of the Windows loader.

## Features

- Manual map from memory (payload embedded in `.rsrc` and optionally encrypted)
- Supports AES-128-CBC encrypted payloads 
- Robust relocation walker (bounds checked)
- Import repair that **reads INT/ILT** and **writes IAT**
- Optional **IAT-level interception** of command-line/CRT/exit APIs
- TLS callback runner
- x64 exception/unwind support by registering `.pdata`
- Export resolver with forwarder handling

## How-To

### Utility

"ObfusX" is also included as a utility tool to encrypt PEs/shellcode in various formats.

```
python3 obfusX.py -p <TARGET PE> -enc aes-128 -o encrypted_pe
```

Place the generated file in the .rsrc section of *MochiMapper*. Change the AES KEY/IV in the code aswell.

### CMD-Line Argument Support

### Exported Function Support (DLL)

### IAT hooks (optional)

Enable command-line hiding/spoofing without touching the PEB:

- GetCommandLineA/W → return synthetic strings
- __getmainargs/__wgetmainargs → supply argc/argv or just pass env from the real CRT
- __p___argv/__p___wargv/__p___argc → return stable pointers
- ExitProcess / exit family → observe or suppress termination
- GetModuleFileNameA/W(NULL, …) → return a fake name

Just pass CmdlineHookCB to the IAT repairer. *Hooks* store originals and swap IAT slots to your hook functions.

## Demo

## OPSEC

Static analysis will likely catch this in the current state. For better OPSEC, consider adding:

- API Hashing
- (indirect) Syscalls
- Better key/iv retrieval (maybe remotely ?)