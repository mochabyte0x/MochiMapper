# MochiMapper

A minimal **manual PE loader** that maps a PE from the `.rsrc` section into memory and emulates some parts of the Windows loader. I'm (probably) not gonna add more features to it. Too lazy for that, sry.

>[!CAUTION]
>This tool is designed for authorized operations only. I AM NOT RESPONSIBLE FOR YOUR ACTIONS. DON'T DO BAD STUFF.

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

>[!NOTE]
> If you compile *MochiMapper* and run it, the loader will launch *mimikatz.exe* which is put as a "demo" binary. Replace the content of the `.rsrc` section with something else.

### Utility

*ObfusX* is also included as a utility tool to encrypt PEs/shellcode in various formats.

```powershell
python3 obfusX.py -p <TARGET PE> -enc aes-128 -o encrypted_pe
```

Place the generated file in the `.rsrc` section of *MochiMapper*. Change the AES KEY/IV (located in the main function) in the code aswell.

### CMD-Line Argument Support

*MochiMapper* supports command line arguments. You can define them in the "structs.h" header. Leave blank if not needed.

<img width="657" height="92" alt="image" src="https://github.com/user-attachments/assets/4ce239b6-5a04-44d6-bfeb-566cfc9df928" />

### Exported Function Support (DLL)

If your target PE is a DLL AND the entrypoint is not DllMain but an exported function, you can specify this in the "structs.h" header. Leave blank if not needed.

<img width="657" height="92" alt="image" src="https://github.com/user-attachments/assets/af68478d-b97d-4e56-8b42-c9fa5d26fdad" />

### IAT hooks (optional)

Enable command-line hiding/spoofing without touching the PEB:

- GetCommandLineA/W → return synthetic strings
- __getmainargs/__wgetmainargs → supply argc/argv or just pass env from the real CRT
- __p___argv/__p___wargv/__p___argc → return stable pointers
- ExitProcess / exit family → observe or suppress termination
- GetModuleFileNameA/W(NULL, …) → return a fake name

Just pass `CmdlineHookCB` to the IAT repair function (already placed, but remove if you don't want to use this feature). *Hooks* store originals and swap IAT slots to your hook functions.

## Demo

<img width="1351" height="739" alt="image" src="https://github.com/user-attachments/assets/8255f54e-1c12-4854-8b75-a53c59668ccb" />

## OPSEC

Static analysis will likely catch this in the current state. For better OPSEC, consider adding:

- API Hashing
- (indirect) Syscalls
- Better KEY/IV retrieval (maybe remotely ?)
- Build it CRT Free for better entropy
- Convert this into a reflective DLL loader
