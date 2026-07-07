# GDID API Hook DLL (Mode 3)

An optional DLL that hooks `RegQueryValueExW` to intercept GDID reads at the Win32 API level.

## How It Works

Instead of modifying registry values (which could cause consistency issues or trigger detection), this DLL sits between `cdp.dll`/`wlidsvc.dll` and the Windows registry API. When any process reads the GDID registry keys, the hook returns a spoofed value instead.

The real registry value stays untouched — only the return value is modified at the API boundary.

## Compilation Requirements

- Visual Studio 2022 with Desktop development with C++ workload
- [MinHook](https://github.com/TsudaKageyu/minhook) library (included as submodule)

## Build

```powershell
git submodule update --init
msbuild gdid-hook.vcxproj /p:Configuration=Release /p:Platform=x64
```

## Install

```powershell
# Via AppInit_DLLs (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows)
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\path\to\gdid-hook.dll" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f

# Or via SetWindowsHookEx injection into CDPSvc
```

## Detection Risk

- `AppInit_DLLs` is well-known and flagged by many EDR/AV products
- Recommended approach: use a reflective DLL loader or manual injection
- Most users should stick with Mode 2 (registry rotation + firewall) instead